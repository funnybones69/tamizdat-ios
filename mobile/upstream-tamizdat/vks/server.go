package vks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/vks/olc/core/app/session"
	"github.com/funnybones69/tamizdat/vks/olc/core/control"
	olcserver "github.com/funnybones69/tamizdat/vks/olc/core/server"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
)

// ServerHooks is the seam between the VKS room server and the Tamizdat core.
type ServerHooks struct {
	// Authenticate validates a tamizdat master_shortid (hex) presented in the
	// olcRTC handshake claims. Returns userID, userName, tamizdat sessionID, ok.
	Authenticate func(shortIDHex string) (userID, userName, sessionID string, ok bool)
	// EndSession closes the tamizdat session opened by Authenticate.
	EndSession func(userID, sessionID string)
	// Dial routes an accepted CONNECT through the tamizdat outbound registry.
	Dial func(ctx context.Context, addr string, userID string) (net.Conn, error)
	// AddTraffic records per-user traffic (up, down bytes).
	AddTraffic func(userID, sessionID string, up, down int64)
}

// Server runs one VKS room in server mode on the Tamizdat core.
type Server struct {
	cfg   Config
	hooks ServerHooks

	mu       sync.Mutex
	rooms    map[string]string // olc sessionID -> userID
	roomSess map[string]string // olc sessionID -> tamizdat sessionID
}

// RunServer joins the room and serves until ctx is cancelled. Blocking.
// When cfg.IdleTimeout > 0 the server leaves the room (RunServer returns)
// once the room has had zero authenticated peers for that whole span —
// this is the on-demand building block: a room lives only while a client
// uses it, plus one join-grace window for the client that asked for it.
func RunServer(ctx context.Context, cfg Config, hooks ServerHooks) error {
	session.RegisterDefaults()
	s := &Server{cfg: cfg, hooks: hooks, rooms: map[string]string{}, roomSess: map[string]string{}}

	if cfg.IdleTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go s.watchIdle(ctx, cancel, cfg.IdleTimeout)
	}

	authHook := func(deviceID string, claims map[string]any) (string, error) {
		raw, _ := claims["shortid"].(string)
		if raw == "" {
			return "", fmt.Errorf("vks: missing shortid claim")
		}
		userID, _, tSessID, ok := hooks.Authenticate(raw)
		if !ok {
			return "", fmt.Errorf("vks: shortid rejected")
		}
		olcSID := fmt.Sprintf("vks-%s-%d", tSessID, time.Now().UnixNano())
		s.mu.Lock()
		s.rooms[olcSID] = userID
		s.roomSess[olcSID] = tSessID
		s.mu.Unlock()
		return olcSID, nil
	}

	dialHook := func(ctx context.Context, addr string, olcSID string) (net.Conn, error) {
		s.mu.Lock()
		userID := s.rooms[olcSID]
		s.mu.Unlock()
		if userID == "" {
			return nil, fmt.Errorf("vks: unknown session %s", olcSID)
		}
		return hooks.Dial(ctx, addr, userID)
	}

	onTraffic := func(olcSID, addr string, bytesIn, bytesOut uint64) {
		if hooks.AddTraffic == nil {
			return
		}
		s.mu.Lock()
		userID := s.rooms[olcSID]
		tSessID := s.roomSess[olcSID]
		s.mu.Unlock()
		if userID != "" {
			hooks.AddTraffic(userID, tSessID, int64(bytesIn), int64(bytesOut))
		}
	}

	onClose := func(olcSID, reason string) {
		s.mu.Lock()
		userID := s.rooms[olcSID]
		tSessID := s.roomSess[olcSID]
		delete(s.rooms, olcSID)
		delete(s.roomSess, olcSID)
		s.mu.Unlock()
		if hooks.EndSession != nil && userID != "" {
			hooks.EndSession(userID, tSessID)
		}
	}

	return olcserver.Run(ctx, olcserver.Config{
		Transport:        cfg.transportName(),
		Provider:         cfg.Provider,
		RoomURL:          cfg.RoomURL,
		ChannelID:        cfg.ChannelID,
		KeyHex:           cfg.KeyHex,
		DNSServer:        cfg.DNSServer,
		ProviderToken:    cfg.ProviderToken,
		TransportOptions: cfg.transportOptions(),
		Liveness:         control.Config{Interval: 10 * time.Second, Timeout: 15 * time.Second, Failures: 4},
		AuthHook:         authHook,
		DialHook:         dialHook,
		OnTraffic:        onTraffic,
		OnSessionClose:   onClose,
	})
}

// PeerCount reports live room peers (diagnostics for the panel later).
func (s *Server) PeerCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rooms)
}

// watchIdle cancels the room once it has sat empty (no authenticated peers)
// for the whole idle timeout. The server joins a room only because a client
// asked for it; when no client shows up within the timeout (join grace) or
// the last client leaves and the room stays empty, the room is released so
// the server does not sit in it 24/7.
func (s *Server) watchIdle(ctx context.Context, cancel context.CancelFunc, idle time.Duration) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	emptySince := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.PeerCount() == 0 {
				if time.Since(emptySince) >= idle {
					cancel()
					return
				}
			} else {
				emptySince = time.Now()
			}
		}
	}
}

var _ = transport.Features{}
var _ = strings.TrimSpace
