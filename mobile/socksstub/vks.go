// vks.go — VKS room-transport upstream for the socksstub listener.
//
// When StartVKSUpstream is called, the VKS ladder client runs inside the
// main-app process and serves a local SOCKS5 listener; every TCP flow
// accepted by socksstub is chained through that listener (SOCKS5 CONNECT)
// and rides the WebRTC room tunnel to the tamizdat server. The olc client
// is stream-only: UDP follows the carrier mode like TCP does, and neither
// has an H2 or direct fallback outside Main mode.
//
// Public gomobile API:
//
//	StartVKSUpstream(specs, shortIDHex, wakeDNS, wakeZone string, listenPort int) string
//	StartVKSNativeUpstream(specs, shortIDHex, wakeDNS, wakeZone string, listenPort int) string
//	StopVKSUpstream() string
//	StopVKSNativeUpstream() string
//	VKSUpstreamRunning() bool
//	VKSNativeRunning() bool
//	VKSUpstreamStatsJSON() string
//	VKSLoginRequired() string
//	UploadVKSCredentials(provider, cookieHeader string) string
package socksstub

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	samizdat "github.com/funnybones69/tamizdat"
	"github.com/funnybones69/tamizdat/vks"
)

// vksCredsUploadTimeout bounds one upload: the server validates by creating
// a real room (telemost) or calling GetLoginData (mts) before replying.
const vksCredsUploadTimeout = 45 * time.Second

// VKSLoginRequired returns the comma-separated providers the server reported
// as needing a fresh login in its last beacon answer ("" = none).
func VKSLoginRequired() string {
	return strings.Join(vks.LoginRequiredProviders(), ",")
}

// UploadVKSCredentials sends a provider Cookie header to the server through
// whichever carrier is currently up (H2 in Main mode, the room tunnel in
// Whitelist mode). The server validates before storing. Returns "" on
// success, otherwise the error text.
func UploadVKSCredentials(provider, cookieHeader string) string {
	ctx, cancel := context.WithTimeout(context.Background(), vksCredsUploadTimeout)
	defer cancel()
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialUpstream(ctx, addr)
	}
	if err := vks.UploadProviderCredentials(ctx, dial, provider, cookieHeader); err != nil {
		rt.appendLog(fmt.Sprintf("warn: vks creds upload %s: %v", provider, err))
		return err.Error()
	}
	rt.appendLog(fmt.Sprintf("vks creds upload %s: accepted", provider))
	return ""
}

type vksState struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	addr    string
	specs   string
	lastErr string
	started time.Time
}

var vksUp vksState

// routeStdLogsToSink wires the Go standard logger into the App Group log
// file (rt.appendLog). The olc client and the ladder log exclusively via
// the std `log` package, which otherwise goes to stderr - invisible on
// device. Idempotent: SetOutput simply replaces the writer.
func routeStdLogsToSink() {
	log.SetOutput(io.MultiWriter(os.Stderr, logSinkWriter{}))
}

// logSinkWriter adapts std log writes to the socksstub log sink.
type logSinkWriter struct{}

func (logSinkWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			rt.appendLog(line)
		}
	}
	return len(p), nil
}

// StartVKSUpstream starts the legacy olcRTC VKS ladder and its local
// SOCKS5 listener. specs is a comma-separated provider:room ladder
// (telemost:…, jazz:…,mts:…). shortIDHex is the tamizdat master_shortid
// and the only credential: the olcRTC wire key is derived from it, so no
// separate shared secret is configured. listenPort is the loopback SOCKS5
// port. wakeDNS (e.g. "77.88.8.8:53") and wakeZone (e.g.
// "wake.example.com"), when both non-empty, make the client emit the
// on-demand wake beacon (a DNS query keyed by the shortid) before each
// connect, so an on-demand server joins the room just in time. Returns a
// JSON status line. Non-blocking: the ladder runs in background.
func StartVKSUpstream(specs, shortIDHex, wakeDNS, wakeZone string, listenPort int) string {
	// Bridge ladder diagnostics (std log) into the App Group log file so
	// they are visible on device.
	routeStdLogsToSink()

	vksUp.mu.Lock()
	defer vksUp.mu.Unlock()
	if vksUp.running {
		if specs != vksUp.specs {
			rt.appendLog("warn: VKS upstream already running with different specs - keeping the current ladder until stop")
		}
		return vksStatusJSON("already-running", vksUp.addr, "")
	}
	if specs == "" || shortIDHex == "" {
		return vksStatusJSON("error", "", "specs and shortIDHex are required")
	}
	if listenPort < 1024 || listenPort > 65535 {
		return vksStatusJSON("error", "", "listenPort must be 1024..65535")
	}
	if listenPort == 18443 {
		return vksStatusJSON("error", "", "listenPort collides with the in-process socksstub listener (18443)")
	}
	cfgs, err := vks.ParseSpecs(specs)
	if err != nil {
		return vksStatusJSON("error", "", err.Error())
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))
	wireKey := vks.DeriveWireKey(shortIDHex)
	ladder := make([]vks.ClientConfig, len(cfgs))
	for i := range cfgs {
		cfgs[i].KeyHex = wireKey
		ladder[i] = vks.ClientConfig{
			Config:        cfgs[i],
			ShortIDHex:    shortIDHex,
			ListenAddr:    addr,
			WakeDNSServer: wakeDNS,
			WakeZone:      wakeZone,
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	vksUp.cancel = cancel
	vksUp.running = true
	vksUp.addr = addr
	vksUp.specs = specs
	vksUp.lastErr = ""
	vksUp.started = time.Now()
	rt.appendLog("info: VKS upstream starting → " + addr)
	go func() {
		err := vks.RunLadder(ctx, ladder, 2*time.Second, 0)
		vksUp.mu.Lock()
		vksUp.running = false
		if err != nil && ctx.Err() == nil {
			vksUp.lastErr = err.Error()
		}
		vksUp.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			rt.appendLog("error: VKS upstream exited: " + err.Error())
		} else {
			rt.appendLog("info: VKS upstream stopped")
		}
	}()
	return vksStatusJSON("starting", addr, "")
}

// StopVKSUpstream tears down the ladder and its listener.
func StopVKSUpstream() string {
	vksUp.mu.Lock()
	defer vksUp.mu.Unlock()
	if !vksUp.running {
		return vksStatusJSON("stopped", "", "")
	}
	if vksUp.cancel != nil {
		vksUp.cancel()
		vksUp.cancel = nil
	}
	vksUp.running = false
	return vksStatusJSON("stopping", "", "")
}

// VKSUpstreamRunning reports whether the ladder is active.
func VKSUpstreamRunning() bool {
	vksUp.mu.Lock()
	defer vksUp.mu.Unlock()
	return vksUp.running
}

// VKSNativeRunning reports whether the native room-transport client is
// installed (armed). Surfaced through the extension status RPC so the
// main app can render the whitelist carrier state.
func VKSNativeRunning() bool {
	rt.mu.Lock()
	c := rt.vksNativeClient
	rt.mu.Unlock()
	return c != nil
}

// VKSUpstreamStatsJSON reports the runner state for the UI.
func VKSUpstreamStatsJSON() string {
	vksUp.mu.Lock()
	defer vksUp.mu.Unlock()
	m := map[string]any{
		"running": vksUp.running,
		"addr":    vksUp.addr,
		"specs":   vksUp.specs,
	}
	if !vksUp.started.IsZero() {
		m["uptimeSec"] = int(time.Since(vksUp.started).Seconds())
	}
	if vksUp.lastErr != "" {
		m["lastError"] = vksUp.lastErr
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// vksUpstreamAddr returns the loopback SOCKS5 address while the ladder is
// active, else "".
func vksUpstreamAddr() string {
	vksUp.mu.Lock()
	defer vksUp.mu.Unlock()
	if !vksUp.running {
		return ""
	}
	return vksUp.addr
}

func vksStatusJSON(status, addr, errMsg string) string {
	m := map[string]any{"status": status}
	if addr != "" {
		m["addr"] = addr
	}
	if errMsg != "" {
		m["error"] = errMsg
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// StartVKSNativeUpstream runs the NATIVE VKS tunnel: a samizdat Client whose
// session (utls + masq + shortid session-ID auth — the SAME stack as h2) runs
// over the VKS room datachannel instead of TCP. Single key (shortid), no
// olcRTC epoch/keyHex/smux. dialUpstream forwards via the Client's
// DialContext when this is set. The server config (pubkey, SNI) comes from
// the active proxy profile's blob; the room config from the VKS settings.
func StartVKSNativeUpstream(specs, shortIDHex, wakeDNS, wakeZone string, listenPort int) string {
	rt.mu.Lock()
	blob := rt.samizdatBlob
	rt.mu.Unlock()
	if blob == "" {
		return vksStatusJSON("error", "", "no active proxy profile (server config) for the native VKS path")
	}
	cfg, err := parseSamizdatURL(blob)
	if err != nil {
		return vksStatusJSON("error", "", err.Error())
	}
	pubKey, err := hex.DecodeString(cfg.PubkeyHex)
	if err != nil || len(pubKey) != 32 {
		return vksStatusJSON("error", "", "pubkey: 64 hex required")
	}
	cfgs, err := vks.ParseSpecs(specs)
	if err != nil || len(cfgs) == 0 {
		return vksStatusJSON("error", "", "need a room spec")
	}
	// Native ladder: every spec is a candidate, tried in order. A primary that
	// refuses fast must not hold the dial (see vks.NativeDialLadder); the outer
	// olc ladder stays as the fallback for a primary that is merely slow.
	nativeLadder := make([]vks.ClientConfig, 0, len(cfgs))
	for i := range cfgs {
		nativeLadder = append(nativeLadder, vks.ClientConfig{
			Config:        cfgs[i],
			ShortIDHex:    shortIDHex,
			WakeDNSServer: wakeDNS,
			WakeZone:      wakeZone,
		})
	}
	sidBytes, err := hex.DecodeString(shortIDHex)
	if err != nil || len(sidBytes) != 8 {
		return vksStatusJSON("error", "", "shortid: 16 hex required")
	}
	var shortID [8]byte
	copy(shortID[:], sidBytes)
	client, err := samizdat.NewClient(samizdat.ClientConfig{
		ServerAddr:    "vks-dc:443", // placeholder — the Dialer ignores it
		ServerName:    cfg.SNI,
		PublicKey:     pubKey,
		ShortID:       shortID,
		MinTransports: 1,
		MaxTransports: 1, // single session over the shared broadcast lane
		// applyDefaults() otherwise raises MinTransports to 2 for the
		// security defaults, which drags MaxTransports to 2 with it: the room
		// then carries two TLS+H2 sessions instead of one, and the pool
		// reports "MaxTransports cap: cap=2" the moment both are busy. Every
		// UDP flow (DNS, QUIC, APNs) is classified realtime and needed the
		// second slot, so it failed outright — 176 times in a few minutes of
		// a live log, while TCP kept working.
		//
		// The room is already the disguise, so the H2-side security defaults
		// are redundant here; keep the two fragmentation flags to preserve
		// the existing on-the-wire shape and own the pool sizing explicitly.
		DisableDefaultSecurity: true,
		TCPFragmentation:       true,
		RecordFragmentation:    true,
		CoverTrafficEnabled:    false,
		// The native client's Dialer is the ROOM, not the H2 endpoint: an
		// RTT probe inside it dials 1.1.1.1:80 through the room once a
		// second, which on Telemost means one CONNECT + one RTP sample per
		// second of pure noise on the same track the tunnel rides. It also
		// inflated the carrier's own byte counters. The room path already
		// reports its own health; keep the client quiet.
		DisableRTTProbe: true,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return vks.NativeDialLadder(ctx, nativeLadder)
		},
	})
	if err != nil {
		return vksStatusJSON("error", "", err.Error())
	}
	rt.mu.Lock()
	old := rt.vksNativeClient
	oldShortID := rt.vksNativeShortID
	oldSpecs := rt.vksNativeSpecs
	rt.vksNativeClient = client
	rt.vksNativeShortID = shortIDHex
	rt.vksNativeSpecs = specs
	// A fresh client invalidates the previous failure latch: keeping it would
	// make dialWhitelistVKS refuse the new carrier for up to vksNativeFailLatch.
	rt.vksNativeFailUntil.Store(0)
	// Probe misses during the native room/beacon warm-up are not verdicts.
	rt.vksCarrierReadyAtNanos.Store(time.Now().UnixNano())
	rt.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	// Sessions from a previous arming with a different identity or spec are
	// unreachable for the new client (dcKey is provider|room|shortid), so they
	// would linger as ghost participants. Release them. Re-arming with the
	// SAME shortid and spec keeps the warm session, so a redundant re-arm does
	// not force a fresh room join.
	if oldShortID != "" && (oldShortID != shortIDHex || oldSpecs != specs) {
		vks.ShutdownNativeSessions()
	}
	rt.appendLog(fmt.Sprintf("info: [vks-native] upstream up shortid=%s provider=%s (beacon must carry a VALID user shortid)", shortIDHex, cfgs[0].Provider))
	return vksStatusJSON("started", "", "")
}

// StopVKSNativeUpstream tears down the native VKS tunnel.
func StopVKSNativeUpstream() string {
	rt.mu.Lock()
	old := rt.vksNativeClient
	rt.vksNativeClient = nil
	rt.vksNativeFailUntil.Store(0)
	rt.vksCarrierReadyAtNanos.Store(0)
	rt.mu.Unlock()
	if old != nil {
		_ = old.Close()
		// Flows that were riding this carrier are parked in a copy with no
		// deadline; without this they outlive it and pile up across
		// reconnects until iOS kills the extension for memory.
		closeAllFlows("carrier stopped")
	}
	// The room sessions live inside the vks package, not on the samizdat client:
	// closing the client alone leaves the SFU websocket, the PeerConnections and
	// the room ping goroutine alive (and a ghost participant in the room).
	// ShutdownNativeSessions releases them, so teardown must call it explicitly.
	vks.ShutdownNativeSessions()
	return vksStatusJSON("stopped", "", "")
}

// dialViaSocks5 opens a SOCKS5 CONNECT through proxyAddr to dest. Used to
// chain socksstub flows through the local VKS listener.
func dialViaSocks5(ctx context.Context, proxyAddr, dest string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	// 5s cap: a flapping or dead ladder must not eat the flow's dial
	// budget - the flow fails instead of silently falling back to H2.
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// Greeting: VER=5, NMETHODS=1, NOAUTH.
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return nil, err
	}
	if sel[0] != 0x05 || sel[1] != 0x00 {
		return nil, fmt.Errorf("vks chain: proxy auth rejected (% x)", sel)
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, fmt.Errorf("vks chain: bad dest %q: %w", dest, err)
	}
	req := []byte{0x05, 0x01, 0x00} // CONNECT
	if ip := net.ParseIP(host); ip == nil {
		if len(host) > 255 {
			return nil, fmt.Errorf("vks chain: host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	} else if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else {
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("vks chain: bad port %q", portStr)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("vks chain: connect failed (rep=%d)", hdr[1])
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		skip = int(l[0])
	default:
		return nil, fmt.Errorf("vks chain: bad atyp %d", hdr[3])
	}
	if skip > 0 {
		if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
			return nil, err
		}
	}
	_ = c.SetDeadline(time.Time{})
	ok = true
	return c, nil
}
