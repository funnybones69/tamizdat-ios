// Package mobile exposes the VKS room tunnel as a gomobile-bound runtime for
// the samizdat-ios Network Extension. Mirrors the socksstub pattern: scalar
// args, Start/Stop/Status, callback on state change.
package mobile

import (
	"context"
	"sync"

	"github.com/funnybones69/tamizdat/vks"
)

// Runtime is one gomobile-bound VKS tunnel instance.
type Runtime struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	socks   string
	lastErr string
}

// NewRuntime creates an idle VKS tunnel runtime.
func NewRuntime() *Runtime { return &Runtime{} }

// Start launches the ladder. specs is a comma-separated provider:room list
// (telemost:…,wbstream:…,jazz:…). keyHex is the shared olcRTC wire key.
// shortIDHex is the tamizdat master_shortid. listenAddr is the local SOCKS5
// bind (e.g. "127.0.0.1:11080"). Blocks are async; state via State().
func (r *Runtime) Start(specs, keyHex, shortIDHex, listenAddr string) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()

	cfgs, err := vks.ParseSpecs(specs)
	if err != nil {
		return err
	}
	ladder := make([]vks.ClientConfig, len(cfgs))
	for i := range cfgs {
		cfgs[i].KeyHex = keyHex
		ladder[i] = vks.ClientConfig{Config: cfgs[i], ShortIDHex: shortIDHex, ListenAddr: listenAddr}
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancel = cancel
	r.running = true
	r.socks = listenAddr
	r.lastErr = ""
	r.mu.Unlock()

	go func() {
		err := vks.RunLadder(ctx, ladder, 2*1000_000_000, 0) // 2s
		r.mu.Lock()
		r.running = false
		if err != nil && ctx.Err() == nil {
			r.lastErr = err.Error()
		}
		r.mu.Unlock()
	}()
	return nil
}

// Stop tears down the tunnel.
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.running = false
}

// State reports "running"/"stopped" and the SOCKS address or last error.
func (r *Runtime) State() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return "running " + r.socks
	}
	if r.lastErr != "" {
		return "error " + r.lastErr
	}
	return "stopped"
}

// IsRunning reports whether the tunnel is up.
func (r *Runtime) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}
