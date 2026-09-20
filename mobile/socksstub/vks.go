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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/vks"
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

// StartVKSUpstream starts the VKS ladder and its local SOCKS5 listener.
// specs is a comma-separated provider:room ladder (telemost:…,wbstream:…,
// jazz:…,mts:…). keyHex is the shared olcRTC wire key; shortIDHex is the
// tamizdat master_shortid. listenPort is the loopback SOCKS5 port.
// Returns a JSON status line. Non-blocking: the ladder runs in background.
func StartVKSUpstream(specs, keyHex, shortIDHex string, listenPort int) string {
	vksUp.mu.Lock()
	defer vksUp.mu.Unlock()
	if vksUp.running {
		return vksStatusJSON("already-running", vksUp.addr, "")
	}
	if specs == "" || keyHex == "" || shortIDHex == "" {
		return vksStatusJSON("error", "", "specs, keyHex and shortIDHex are required")
	}
	cfgs, err := vks.ParseSpecs(specs)
	if err != nil {
		return vksStatusJSON("error", "", err.Error())
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort))
	ladder := make([]vks.ClientConfig, len(cfgs))
	for i := range cfgs {
		cfgs[i].KeyHex = keyHex
		ladder[i] = vks.ClientConfig{Config: cfgs[i], ShortIDHex: shortIDHex, ListenAddr: addr}
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
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
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