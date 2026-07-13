package socksstub

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/wgturnclient"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// VK TURN upstream — opt-in transport that wraps WireGuard inside DTLS
// inside VK call-relay traffic. This file is the gomobile-safe bridge
// between the Go runtime running in the main app (where SocksStub
// lives) and the Swift PacketTunnelProvider, which discovers the
// upstream's lifecycle through these exported strings/ints.
//
// Why the Go side owns the lifecycle: WireGuard config negotiation
// (GETCONF), the dispatcher, and the worker DTLS sessions are already
// implemented in the wgturnclient library — Swift cannot drive those
// loops because gomobile cannot expose Go goroutines back to it.
//
// Why we never return *Runner to Swift: gomobile constrains return
// types to string/int/int64/bool/[]byte. Errors travel back as
// strings: an empty string means success.

var (
	vkturnRunner           *wgturnclient.Runner
	vkturnCancel           context.CancelFunc
	vkturnWGConfig         atomic.Pointer[string]
	vkturnStats            atomic.Pointer[string]
	vkturnErr              atomic.Pointer[string]
	vkturnNet              atomic.Pointer[netstack.Net]
	vkturnRunning          atomic.Bool
	vkturnGeneration       atomic.Int64
	vkturnRestartNotBefore atomic.Int64
	vkturnRunDone          <-chan struct{}
	vkturnDraining         <-chan struct{}
	vkturnAttachStop       func()
	vkturnMu               sync.Mutex
)

const (
	vkturnConfigAttachTimeout   = 60 * time.Second
	vkturnShutdownWaitTimeout   = 15 * time.Second
	vkturnAllocationReleaseWait = 500 * time.Millisecond
	vkturnDefaultWorkers        = 24
	vkturnMinWorkers            = 12
	vkturnMaxWorkers            = 72
)

// StartVKTurnUpstream starts the VK TURN upstream. On success it returns "".
// On immediate setup error it returns the error message. GETCONF and
// userspace-WireGuard attach continue asynchronously so Network Extension
// startup is not blocked on TURN Allocate / DTLS handshakes. Calling it
// again while the runner is alive returns the "already running" sentinel so
// the Swift side does not spawn another attach poller for the same generation.
func StartVKTurnUpstream(credsJSON string, peerAddr string, wgPassword string, deviceID string, listenPort int, workers int) string {
	creds, err := parseVKTurnCredsJSON(credsJSON)
	if err != nil {
		return "credsJSON: " + err.Error()
	}
	workers = normalizeVKTurnWorkers(workers)
	return startVKTurnRunner(peerAddr, wgPassword, deviceID, listenPort, workers, 0, nil, nil, creds, len(credsJSON))
}

// StartVKTurnMultiRoomUpstream starts one full 20-worker pool per room.
func StartVKTurnMultiRoomUpstream(bundleJSON string, peerAddr string, wgPassword string, deviceID string, listenPort int, workersPerRoom int) string {
	hashes, credsByHash, err := parseVKTurnRoomCredsJSON(bundleJSON)
	if err != nil {
		return "roomCredsJSON: " + err.Error()
	}
	if workersPerRoom != 20 {
		return "workersPerRoom must be 20"
	}
	return startVKTurnRunner(peerAddr, wgPassword, deviceID, listenPort, len(hashes)*workersPerRoom, workersPerRoom, hashes, credsByHash, nil, len(bundleJSON))
}

func startVKTurnRunner(peerAddr, wgPassword, deviceID string, listenPort, workers, workersPerRoom int, hashes []string, credsByHash map[string]*wgturnclient.Credentials, singleCreds *wgturnclient.Credentials, jsonLen int) string {
	vkturnMu.Lock()
	if vkturnDraining != nil {
		vkturnMu.Unlock()
		rt.appendLog("warn: vkturn start blocked — previous runner still draining worker sessions")
		return "previous runner still draining"
	}
	if vkturnRunning.Load() {
		runningStats := TURNUpstreamStatsJSON()
		vkturnMu.Unlock()
		rt.appendLog(fmt.Sprintf("info: vkturn already running generation=%d stats=%s", vkturnGeneration.Load(), truncateLogField(runningStats, 180)))
		return "already running"
	}
	if notBefore := vkturnRestartNotBefore.Load(); notBefore > 0 {
		if wait := time.Until(time.Unix(0, notBefore)); wait > 0 {
			rt.appendLog(fmt.Sprintf("info: vkturn waiting %s for prior TURN allocation release", wait.Round(time.Millisecond)))
			time.Sleep(wait)
		}
		vkturnRestartNotBefore.Store(0)
	}

	resetVKTurnAtomicsLocked()
	attachOnce := &sync.Once{}
	firstCreds := singleCreds
	if firstCreds == nil && len(hashes) > 0 {
		firstCreds = credsByHash[hashes[0]]
	}
	useUDP := shouldUseUDP(firstCreds)
	rt.appendLog(fmt.Sprintf("info: vkturn start requested rooms=%d workers=%d workersPerRoom=%d useUDP=%t listenPort=%d peer=%s %s jsonLen=%d deviceIDLen=%d passwordLen=%d", maxInt(1, len(hashes)), workers, workersPerRoom, useUDP, listenPort, redactHostPortForLog(peerAddr), vkturnCredsSummary(firstCreds), jsonLen, len(deviceID), len(wgPassword)))
	configCh := make(chan string, 1)
	cfg := wgturnclient.Config{
		Listen: fmt.Sprintf("127.0.0.1:%d", listenPort), PeerAddr: peerAddr,
		Workers: workers, WorkersPerRoom: workersPerRoom, UseUDP: useUDP,
		VKHashes: hashes, DeviceID: deviceID, ConnPassword: wgPassword,
		PreloadedCreds: singleCreds, PreloadedCredsByHash: credsByHash,
		BondV2: workersPerRoom > 0 && len(hashes) >= 2,
		OnConfig: func(conf string) {
			select {
			case configCh <- conf:
			default:
			}
		},
		OnEvent: func(level, message string) { appendVKTurnEvent(level, message) },
	}
	runner, err := wgturnclient.New(cfg)
	if err != nil {
		vkturnMu.Unlock()
		return err.Error()
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	generation := vkturnGeneration.Add(1)
	vkturnRunner, vkturnCancel, vkturnRunDone = runner, cancel, runDone
	vkturnRunning.Store(true)
	storeVKTurnStats(0, true)
	vkturnMu.Unlock()

	go func() {
		err := runner.Start(ctx)
		// Signal that all worker groups, TURN allocations and dispatcher loops
		// have exited before attempting global-state cleanup. Stop can wait on
		// this while holding vkturnMu, preventing a replacement runner from
		// racing old allocation teardown.
		close(runDone)
		vkturnMu.Lock()
		defer vkturnMu.Unlock()
		if vkturnRunner != runner {
			return
		}
		if err != nil {
			errText := err.Error()
			vkturnErr.Store(&errText)
			rt.appendLog(fmt.Sprintf("error: vkturn runner exited err=%s", truncateLogField(errText, 180)))
		} else {
			rt.appendLog("info: vkturn runner exited cleanly")
		}
		stopVKTurnAttachLocked()
		vkturnRunning.Store(false)
		storeVKTurnStats(0, false)
		vkturnRestartNotBefore.Store(time.Now().Add(vkturnAllocationReleaseWait).UnixNano())
		vkturnRunner, vkturnCancel, vkturnRunDone = nil, nil, nil
	}()
	rt.appendLog(fmt.Sprintf("info: vkturn runner started generation=%d; waiting for GETCONF rooms=%d workers=%d", generation, maxInt(1, len(hashes)), workers))
	go finishVKTurnAttach(ctx, runner, cancel, runDone, configCh, attachOnce)
	return ""
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func normalizeVKTurnWorkers(n int) int {
	if n <= 0 {
		n = vkturnDefaultWorkers
	}
	if n < vkturnMinWorkers {
		n = vkturnMinWorkers
	}
	if n > vkturnMaxWorkers {
		n = vkturnMaxWorkers
	}
	// buildWorkerGroupPlans now supports a final partial group (for example
	// 12+8). Preserve the requested exact count instead of silently flooring
	// 20 to 12 in the legacy single-room fallback path.
	return n
}

// UpdateVKTurnCreds swaps fresh credentials into the running runner so
// the next worker-group rotation tick uses them for TURN Allocate.
// Returns "" on success, "not running" when no runner is alive, or a
// parser error message when credsJSON is malformed.
//
// Why this exists: Config.PreloadedCreds is consumed once when the
// runner starts. Credentials live ~3600 s, but workers rotate every
// `lifetime - 120` s. Without a live update path the second rotation
// (about 58 min into the session) tries to allocate against expired
// creds and gets 401, killing the upstream. The Swift heartbeat in
// TURNCredsRefresher (5-min cadence) re-fetches before expiry and
// calls this exported func to publish the fresh snapshot.
//
// Concurrency: the worker loop calls preloadedCreds.Load() under
// groupAuthMutex. We use atomic.Pointer.Store here too so the swap
// is race-free without holding the mutex.
func UpdateVKTurnCreds(credsJSON string) string {
	if !vkturnRunning.Load() {
		rt.appendLog("warn: vkturn update creds requested but runner not running")
		return "not running"
	}
	creds, err := parseVKTurnCredsJSON(credsJSON)
	if err != nil {
		rt.appendLog(fmt.Sprintf("error: vkturn update creds parse failed err=%s", truncateLogField(err.Error(), 160)))
		return "credsJSON: " + err.Error()
	}
	vkturnMu.Lock()
	runner := vkturnRunner
	vkturnMu.Unlock()
	if runner == nil {
		rt.appendLog("warn: vkturn update creds requested but runner nil")
		return "not running"
	}
	runner.UpdatePreloadedCreds(creds)
	rt.appendLog(fmt.Sprintf("info: vkturn update creds OK %s jsonLen=%d", vkturnCredsSummary(creds), len(credsJSON)))
	return ""
}

func UpdateVKTurnRoomCreds(bundleJSON string) string {
	if !vkturnRunning.Load() {
		return "not running"
	}
	hashes, credsByHash, err := parseVKTurnRoomCredsJSON(bundleJSON)
	if err != nil {
		return "roomCredsJSON: " + err.Error()
	}
	vkturnMu.Lock()
	runner := vkturnRunner
	vkturnMu.Unlock()
	if runner == nil {
		return "not running"
	}
	if err := runner.UpdatePreloadedCredsByHash(credsByHash); err != nil {
		return "roomCredsJSON: " + err.Error()
	}
	rt.appendLog(fmt.Sprintf("info: vkturn multi-room credentials updated rooms=%d jsonLen=%d", len(hashes), len(bundleJSON)))
	return ""
}

// StopVKTurnUpstream stops the in-flight runner and clears any stale
// userspace-WireGuard netstack. It is intentionally idempotent: a prior
// runner can leave vkturnRunning=false while vkturnNet is still non-nil,
// and dialUpstream gives that netstack priority over H2.
func StopVKTurnUpstream() {
	vkturnMu.Lock()
	defer vkturnMu.Unlock()

	runner := vkturnRunner
	done := vkturnRunDone
	if done == nil {
		done = vkturnDraining
	}
	if vkturnCancel != nil {
		vkturnCancel()
	}
	if runner != nil {
		runner.Shutdown()
	}

	// Do not allow a replacement runner to consume the same room quota until
	// every old session has returned and its TURN allocation has been closed.
	// runner.Start closes done before taking vkturnMu for final bookkeeping,
	// so waiting here cannot deadlock with the owner cleanup goroutine.
	if done != nil {
		select {
		case <-done:
			vkturnDraining = nil
			// pion sends Lifetime=0 without waiting for a TURN response. Give
			// the relay a short grace window to apply deallocation before a
			// replacement consumes the same per-room quota.
			time.Sleep(vkturnAllocationReleaseWait)
			vkturnRestartNotBefore.Store(0)
			rt.appendLog("info: vkturn shutdown drained all worker sessions and waited for allocation release")
		case <-time.After(vkturnShutdownWaitTimeout):
			vkturnDraining = done
			finishVKTurnDrainAsync(done)
			rt.appendLog(fmt.Sprintf("warn: vkturn shutdown drain timed out after %s; replacement starts are blocked until drain completes", vkturnShutdownWaitTimeout))
		}
	} else {
		vkturnDraining = nil
	}

	vkturnRunner = nil
	vkturnCancel = nil
	vkturnRunDone = nil
	vkturnGeneration.Add(1) // invalidate detached Swift diagnostics immediately
	stopVKTurnAttachLocked()
	resetVKTurnAtomicsLocked()
}

// StopVKTurnUpstreamAsync performs the cancellation/reset half of stop
// synchronously, but drains TURN workers and deallocations in the background.
// Network Extension stopTunnel must return promptly to the iOS watchdog; any
// replacement start remains gated by vkturnDraining until cleanup completes.
func StopVKTurnUpstreamAsync() {
	vkturnMu.Lock()
	runner := vkturnRunner
	done := vkturnRunDone
	alreadyDraining := done == nil && vkturnDraining != nil
	if done == nil {
		done = vkturnDraining
	}
	if vkturnCancel != nil {
		vkturnCancel()
	}
	if runner != nil {
		runner.Shutdown()
	}
	if done != nil {
		vkturnDraining = done
	}
	vkturnRunner = nil
	vkturnCancel = nil
	vkturnRunDone = nil
	vkturnGeneration.Add(1)
	stopVKTurnAttachLocked()
	resetVKTurnAtomicsLocked()
	vkturnMu.Unlock()

	if done == nil || alreadyDraining {
		return
	}
	finishVKTurnDrainAsync(done)
}

func finishVKTurnDrainAsync(drain <-chan struct{}) {
	go func() {
		<-drain
		time.Sleep(vkturnAllocationReleaseWait)
		vkturnMu.Lock()
		if vkturnDraining == drain {
			vkturnDraining = nil
			vkturnRestartNotBefore.Store(0)
		}
		vkturnMu.Unlock()
		rt.appendLog("info: vkturn async shutdown drained worker sessions and released allocations")
	}()
}

// TURNUpstreamDraining reports that a cancelled runner still owns worker
// sessions/allocations. Swift uses it to schedule one serialized attach retry.
func TURNUpstreamDraining() bool {
	vkturnMu.Lock()
	defer vkturnMu.Unlock()
	return vkturnDraining != nil
}

// TURNUpstreamWGConfig returns the latest WireGuard config text delivered
// by the server (the [Interface]/[Peer] block), or "" if not yet received.
func TURNUpstreamWGConfig() string {
	if !vkturnRunning.Load() {
		return ""
	}
	if p := vkturnWGConfig.Load(); p != nil {
		return *p
	}
	return ""
}

// TURNUpstreamStatsJSON returns the latest stats snapshot as a single-line
// JSON string. After startup failures it keeps the last error visible even
// if the runner has already stopped.
func TURNUpstreamStatsJSON() string {
	running := vkturnRunning.Load()
	if running {
		storeVKTurnStats(0, true)
	}
	if p := vkturnStats.Load(); p != nil {
		return *p
	}
	return ""
}

// TURNUpstreamRunning reports whether the VK TURN runner goroutine is alive.
func TURNUpstreamRunning() bool {
	return vkturnRunning.Load()
}

// TURNUpstreamGeneration identifies the current runner lifecycle. Swift
// diagnostics capture it before polling and stop when a newer start/stop
// invalidates their generation, preventing overlapping 60-second pollers.
func TURNUpstreamGeneration() int64 {
	return vkturnGeneration.Load()
}

// VKTurnNetstack returns the userspace WireGuard netstack the upstream
// is currently bound to, or nil if there is none. Callers route every
// TCP/UDP dial through this stack — its underlying packets traverse
// 127.0.0.1:<wgturn relay port> → DTLS+TURN → VK relay → server.
//
// Not gomobile-exported (returns a struct pointer), only the Go callers
// in this same module use it.
func VKTurnNetstack() *netstack.Net {
	return vkturnNet.Load()
}

// stopVKTurnAttachLocked tears down the userspace WG + netstack the
// previous Start built. MUST be called with vkturnMu held.
func stopVKTurnAttachLocked() {
	if vkturnAttachStop != nil {
		vkturnAttachStop()
		vkturnAttachStop = nil
	}
	vkturnNet.Store(nil)
}

// turnServerWire is the v2 wire shape for a single TURN server
// entry. Swift writes this through TURNCredsStore.vkCredsAsJSON; the
// older `turn_servers` []string is still emitted alongside for
// backward compatibility with any extension build still on the v1
// schema.
type turnServerWire struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"`
	Transport string `json:"transport"`
}

func parseVKTurnCredsJSON(credsJSON string) (*wgturnclient.Credentials, error) {
	var wire struct {
		Username      string           `json:"username"`
		Password      string           `json:"password"`
		TurnServers   []string         `json:"turn_servers"`
		TurnServersV2 []turnServerWire `json:"turn_servers_v2"`
		LifetimeSec   int              `json:"lifetime_sec"`
	}
	if err := json.Unmarshal([]byte(credsJSON), &wire); err != nil {
		return nil, err
	}
	if wire.Username == "" || wire.Password == "" {
		return nil, fmt.Errorf("empty username/password")
	}

	// Prefer v2 shape (carries scheme + transport per URL). Fall back
	// to v1 turn_servers []string when v2 is absent — keeps the new
	// Go-side runner compatible with extensions still writing the old
	// JSON during a rolling deploy.
	var turnURLs []string
	var turnServers []wgturnclient.TurnServer
	if len(wire.TurnServersV2) > 0 {
		for _, s := range wire.TurnServersV2 {
			if s.Host == "" || s.Port == 0 {
				continue
			}
			scheme := strings.ToLower(strings.TrimSpace(s.Scheme))
			if scheme == "" {
				scheme = "turn"
			}
			transport := strings.ToLower(strings.TrimSpace(s.Transport))
			if transport == "" {
				if scheme == "turns" {
					transport = "tcp"
				} else {
					transport = "udp"
				}
			}
			if transport != "udp" && transport != "tcp" {
				transport = "udp"
			}
			if scheme == "turns" {
				// This client implements TURNS as TLS over TCP. VK may omit
				// transport or send mixed-case/legacy values; never let a
				// turns: URL fall into the UDP dial path.
				transport = "tcp"
			}
			turnServers = append(turnServers, wgturnclient.TurnServer{
				Host:      s.Host,
				Port:      s.Port,
				Scheme:    scheme,
				Transport: transport,
			})
			turnURLs = append(turnURLs, fmt.Sprintf("%s:%d", s.Host, s.Port))
		}
	}
	if len(turnURLs) == 0 {
		// v1 fallback path.
		turnURLs = wire.TurnServers
	}
	if len(turnURLs) == 0 {
		return nil, fmt.Errorf("empty turn_servers")
	}

	lifetime := wire.LifetimeSec
	if lifetime <= 0 {
		lifetime = 3600
	}
	return &wgturnclient.Credentials{
		User:        wire.Username,
		Pass:        wire.Password,
		TurnURLs:    turnURLs,
		TurnServers: turnServers,
		Lifetime:    lifetime,
	}, nil
}

func parseVKTurnRoomCredsJSON(bundleJSON string) ([]string, map[string]*wgturnclient.Credentials, error) {
	var bundle struct {
		Rooms []struct {
			Hash        string          `json:"hash"`
			Credentials json.RawMessage `json:"credentials"`
		} `json:"rooms"`
	}
	if err := json.Unmarshal([]byte(bundleJSON), &bundle); err != nil {
		return nil, nil, err
	}
	if len(bundle.Rooms) < 1 || len(bundle.Rooms) > 4 {
		return nil, nil, fmt.Errorf("room count must be 1-4")
	}
	hashes := make([]string, 0, len(bundle.Rooms))
	credsByHash := make(map[string]*wgturnclient.Credentials, len(bundle.Rooms))
	for _, room := range bundle.Rooms {
		hash := strings.TrimSpace(room.Hash)
		if hash == "" {
			return nil, nil, fmt.Errorf("empty room hash")
		}
		if _, duplicate := credsByHash[hash]; duplicate {
			return nil, nil, fmt.Errorf("duplicate room hash")
		}
		creds, err := parseVKTurnCredsJSON(string(room.Credentials))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid room credentials: %w", err)
		}
		var freshness struct {
			AcquiredAtUnix int64 `json:"acquired_at_unix"`
		}
		if err := json.Unmarshal(room.Credentials, &freshness); err != nil || freshness.AcquiredAtUnix <= 0 {
			return nil, nil, fmt.Errorf("room credentials missing acquisition time")
		}
		age := time.Now().Unix() - freshness.AcquiredAtUnix
		if age < 0 {
			age = 0
		}
		safeLifetime := creds.Lifetime - 120
		if safeLifetime < 1 || age >= int64(safeLifetime) {
			return nil, nil, fmt.Errorf("room credentials are stale")
		}
		// Preserve actual remaining TTL. Treating a late-loaded snapshot as a
		// brand-new lifetime would rotate after the server-side credential had
		// already expired.
		creds.Lifetime -= int(age)
		hashes = append(hashes, hash)
		credsByHash[hash] = creds
	}
	return hashes, credsByHash, nil
}

// shouldUseUDP picks the wire transport for the runner. Preference
// order: UDP > TCP. When the v2 shape is present we look for any
// server advertising UDP; if there is one, we run UDP and let the
// session loop pick that server first (sessions iterate
// sessionID%len(TurnURLs), so VK's UDP relay sits at the same index
// in both lists). When v2 is absent we keep the historical
// hard-coded UDP behaviour.
func shouldUseUDP(creds *wgturnclient.Credentials) bool {
	if creds == nil || len(creds.TurnServers) == 0 {
		return true
	}
	for _, s := range creds.TurnServers {
		if strings.ToLower(strings.TrimSpace(s.Scheme)) == "turns" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(s.Transport)) == "udp" {
			return true
		}
	}
	return false
}

func vkturnCredsSummary(creds *wgturnclient.Credentials) string {
	if creds == nil {
		return "creds=none"
	}
	udp, tcp, turns := 0, 0, 0
	for _, s := range creds.TurnServers {
		scheme := strings.ToLower(strings.TrimSpace(s.Scheme))
		transport := strings.ToLower(strings.TrimSpace(s.Transport))
		if scheme == "turns" {
			turns++
		} else if transport == "tcp" {
			tcp++
		} else {
			udp++
		}
	}
	return fmt.Sprintf("creds v1=%d v2=%d transports=udp:%d,tcp:%d,turns:%d lifetime=%ds userLen=%d passLen=%d", len(creds.TurnURLs), len(creds.TurnServers), udp, tcp, turns, creds.Lifetime, len(creds.User), len(creds.Pass))
}

func appendVKTurnEvent(level, message string) {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case "warn", "error", "crit", "info":
	default:
		level = "info"
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	rt.appendLog(fmt.Sprintf("%s: vkturn: %s", level, truncateLogField(message, 220)))
}

func truncateLogField(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if max > 0 && len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func redactHostPortForLog(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "parse-error"
	}
	if host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("hostLen:%d:%s", len(host), port)
}

func resetVKTurnAtomicsLocked() {
	vkturnWGConfig.Store(nil)
	vkturnStats.Store(nil)
	vkturnErr.Store(nil)
	vkturnRunning.Store(false)
}

func isCurrentVKTurnRunner(runner *wgturnclient.Runner) bool {
	vkturnMu.Lock()
	defer vkturnMu.Unlock()
	return runner != nil && vkturnRunner == runner && vkturnRunning.Load()
}

func finishVKTurnAttach(ctx context.Context, runner *wgturnclient.Runner, cancel context.CancelFunc, runDone <-chan struct{}, configCh <-chan string, attachOnce *sync.Once) {
	timer := time.NewTimer(vkturnConfigAttachTimeout)
	defer timer.Stop()

	select {
	case conf := <-configCh:
		attachVKTurnConfig(runner, cancel, conf, attachOnce)
	case <-runDone:
		if ctx.Err() == nil && vkturnErr.Load() == nil && storeVKTurnErrorIfCurrent(runner, "not running before GETCONF") {
			rt.appendLog("warn: vkturn runner stopped before GETCONF")
		}
	case <-ctx.Done():
		rt.appendLog("info: vkturn attach wait cancelled")
	case <-timer.C:
		errText := fmt.Sprintf("GETCONF timeout after %s", vkturnConfigAttachTimeout)
		if !storeVKTurnErrorIfCurrent(runner, errText) {
			rt.appendLog("info: vkturn GETCONF timeout ignored for stale runner")
			return
		}
		rt.appendLog("error: vkturn " + errText)
		cancel()
		runner.Shutdown()
	}
}

func attachVKTurnConfig(runner *wgturnclient.Runner, cancel context.CancelFunc, conf string, attachOnce *sync.Once) {
	if conf == "" {
		return
	}
	if !isCurrentVKTurnRunner(runner) {
		rt.appendLog("info: vkturn GETCONF ignored for stale runner")
		return
	}
	rt.appendLog("info: vkturn GETCONF received; attaching userspace WireGuard")

	var res *wgturnclient.AttachResult
	var attachErr error
	attachOnce.Do(func() {
		res, attachErr = runner.AttachWireGuardUserspace(conf)
	})
	if attachErr != nil {
		errText := "wg attach: " + attachErr.Error()
		if storeVKTurnErrorIfCurrent(runner, errText) {
			rt.appendLog("error: vkturn " + errText)
			cancel()
			runner.Shutdown()
		} else {
			rt.appendLog("info: vkturn wg attach error ignored for stale runner")
		}
		return
	}
	if res == nil {
		rt.appendLog("warn: vkturn wg attach returned nil result")
		return
	}

	vkturnMu.Lock()
	defer vkturnMu.Unlock()
	if vkturnRunner != runner || !vkturnRunning.Load() {
		res.Stop()
		rt.appendLog("warn: vkturn wg attach skipped stale runner")
		return
	}
	vkturnNet.Store(res.Net)
	vkturnWGConfig.Store(&conf)
	vkturnAttachStop = res.Stop
	storeVKTurnStats(0, true)
	rt.appendLog("info: vkturn userspace WireGuard attached; netstack ready")
}

func storeVKTurnErrorIfCurrent(runner *wgturnclient.Runner, errText string) bool {
	vkturnMu.Lock()
	defer vkturnMu.Unlock()
	if runner == nil || vkturnRunner != runner || !vkturnRunning.Load() {
		return false
	}
	vkturnErr.Store(&errText)
	storeVKTurnStats(0, true)
	return true
}

func storeVKTurnStats(active int, running bool) {
	var errText string
	if p := vkturnErr.Load(); p != nil {
		errText = *p
	}
	payload := struct {
		Active  int    `json:"active"`
		Running bool   `json:"running"`
		Error   string `json:"error,omitempty"`
	}{Active: active, Running: running, Error: errText}
	b, err := json.Marshal(payload)
	if err != nil {
		snapshot := fmt.Sprintf(`{"active":%d,"running":%t}`, active, running)
		vkturnStats.Store(&snapshot)
		return
	}
	snapshot := string(b)
	vkturnStats.Store(&snapshot)
}
