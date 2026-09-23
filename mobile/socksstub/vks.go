// vks.go — VKS room-transport upstream for the socksstub listener.
//
// When StartVKSUpstream is called, the VKS ladder client runs inside the
// main-app process and serves a local SOCKS5 listener; every TCP flow
// accepted by socksstub is chained through that listener (SOCKS5 CONNECT)
// and rides the WebRTC room tunnel to the tamizdat server. The olc client
// is stream-only, so UDP flows keep the existing precedence
// (VK TURN netstack → samizdat → direct).
//
// Public gomobile API (mirrors the vkturn surface):
//
//	StartVKSUpstream(specs, keyHex, shortIDHex string, listenPort int) string
//	StopVKSUpstream() string
//	VKSUpstreamRunning() bool
//	VKSUpstreamStatsJSON() string
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

	"github.com/funnybones69/tamizdat/vks"
	samizdat "github.com/funnybones69/tamizdat"
)

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

// StartVKSUpstream starts the VKS ladder and its local SOCKS5 listener.
// specs is a comma-separated provider:room ladder (telemost:…,wbstream:…,
// jazz:…,mts:…). keyHex is the shared olcRTC wire key; shortIDHex is the
// tamizdat master_shortid. listenPort is the loopback SOCKS5 port.
// wakeDNS (e.g. "77.88.8.8:53") and wakeZone (e.g. "wake.example.com"),
// when both non-empty, make the client emit the on-demand wake beacon
// (a DNS query for <roomKey>.<nonce>.<zone>) before each connect, so an
// on-demand server joins the room just in time. Returns a JSON status
// line. Non-blocking: the ladder runs in background.
func StartVKSUpstream(specs, keyHex, shortIDHex, wakeDNS, wakeZone string, listenPort int) string {
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
	if specs == "" || keyHex == "" || shortIDHex == "" {
		return vksStatusJSON("error", "", "specs, keyHex and shortIDHex are required")
	}
	if listenPort < 1024 || listenPort > 65535 {
		return vksStatusJSON("error", "", "listenPort must be 1024..65535")
	}
	if listenPort == 18443 || listenPort == 9000 {
		return vksStatusJSON("error", "", "listenPort collides with an in-process listener (18443 socksstub / 9000 VK TURN relay)")
	}
	cfgs, err := vks.ParseSpecs(specs)
	if err != nil {
		return vksStatusJSON("error", "", err.Error())
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))
	ladder := make([]vks.ClientConfig, len(cfgs))
	for i := range cfgs {
		cfgs[i].KeyHex = keyHex
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
func StartVKSNativeUpstream(specs, keyHex, shortIDHex, wakeDNS, wakeZone string, listenPort int) string {
	blob := rt.samizdatBlob
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
	vksCfg := vks.ClientConfig{Config: cfgs[0], ShortIDHex: shortIDHex, WakeDNSServer: wakeDNS, WakeZone: wakeZone}
	vksCfg.KeyHex = keyHex
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
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return vks.NativeDial(ctx, vksCfg)
		},
	})
	if err != nil {
		return vksStatusJSON("error", "", err.Error())
	}
	rt.mu.Lock()
	old := rt.vksNativeClient
	rt.vksNativeClient = client
	rt.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	rt.appendLog(fmt.Sprintf("info: [vks-native] upstream up shortid=%s provider=%s (beacon must carry a VALID user shortid)", shortIDHex, cfgs[0].Provider))
	return vksStatusJSON("started", "", "")
}

// StopVKSNativeUpstream tears down the native VKS tunnel.
func StopVKSNativeUpstream() string {
	rt.mu.Lock()
	old := rt.vksNativeClient
	rt.vksNativeClient = nil
	rt.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
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
	// budget - dialUpstream falls back to samizdat after this.
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