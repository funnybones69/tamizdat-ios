package vks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// WatchServer runs VKS rooms on demand instead of sitting in them 24/7.
//
// The server holds a static set of room configs (the rendezvous rooms) but
// does NOT join any of them at startup. It waits for an authenticated wake
// signal (see beacon_dns.go); only then does it join the named room as a
// fresh anonymous guest and serve it. Each room is released automatically
// once it has no authenticated peers for IdleTimeout — so the server is in
// a room exactly while a client is, plus one join-grace window.
//
// This keeps the data plane free of long-lived tokens: every join is a fresh
// anonymous guest registration, so nothing on the server can expire.
type WatchServer struct {
	hooks   ServerHooks
	idle    time.Duration
	keyHex  string
	creator RoomCreator

	mu     sync.Mutex
	rooms  map[string]Config            // roomKey -> room it may serve
	active map[string]context.CancelFunc // roomKey -> cancel of the live join
}

// NewWatchServer builds an on-demand server over the given room configs.
func NewWatchServer(rooms []Config, hooks ServerHooks, idle time.Duration) *WatchServer {
	if idle <= 0 {
		idle = 120 * time.Second
	}
	w := &WatchServer{
		hooks:  hooks,
		idle:   idle,
		rooms:  map[string]Config{},
		active: map[string]context.CancelFunc{},
	}
	for _, cfg := range rooms {
		cfg.IdleTimeout = idle
		if w.keyHex == "" {
			w.keyHex = cfg.KeyHex
		}
		w.rooms[w.roomKey(cfg)] = cfg
	}
	return w
}

// SetCreator installs the dynamic room factory (beacon-assignment flow).
// Without it the server can only serve statically armed rooms.
func (w *WatchServer) SetCreator(creator RoomCreator) {
	w.mu.Lock()
	w.creator = creator
	w.mu.Unlock()
}

// matchProviderKey maps a beacon selector to a provider name when the
// selector equals that provider's ProviderWakeKey (HMAC of the shared key).
func (w *WatchServer) matchProviderKey(selector string) string {
	w.mu.Lock()
	keyHex := w.keyHex
	w.mu.Unlock()
	if keyHex == "" {
		return ""
	}
	for _, p := range []string{"telemost", "wbstream", "jazz", "mts"} {
		if ProviderWakeKey(keyHex, p) == selector {
			return p
		}
	}
	return ""
}
// roomKey derives the stable, DNS-safe selector for a room from the shared
// wire key. A client proves it knows the key by beaconing this value; a
// random DNS querier cannot guess a valid roomKey, so noise and strangers
// cannot wake the server.
func (w *WatchServer) roomKey(cfg Config) string {
	return RoomWakeKey(cfg.KeyHex, cfg.Provider, cfg.RoomURL)
}

// RoomWakeKey computes the beacon token that wakes the given room. Shared by
// the server (to match) and the client (to emit).
func RoomWakeKey(keyHex, provider, roomURL string) string {
	key, _ := hex.DecodeString(strings.TrimSpace(keyHex))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("vks-wake\x00" + provider + "\x00" + roomURL))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}

// ProviderWakeKey computes the beacon token that asks the server to CREATE
// (or assign) a room on the given provider. The beacon carries this value;
// the server matches it against its enabled providers and responds with the
// room spec in the DNS TXT answer.
func ProviderWakeKey(keyHex, provider string) string {
	key, _ := hex.DecodeString(strings.TrimSpace(keyHex))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("vks-provider\x00" + provider))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}

// Serve registers a DYNAMICALLY created room (from the beacon-assignment
// flow) and immediately wakes it — the room was just created by a
// RoomFactory on behalf of a client, so the client is about to connect.
// Distinct from Wake: the config was not known at startup.
func (w *WatchServer) Serve(cfg Config) string {
	cfg.IdleTimeout = w.idle
	roomKey := w.roomKey(cfg)
	w.mu.Lock()
	if _, exists := w.rooms[roomKey]; !exists {
		w.rooms[roomKey] = cfg
	}
	w.mu.Unlock()
	w.Wake(roomKey)
	return roomKey
}

// Wake joins the named room if it is configured and not already live. Safe
// for concurrent calls; a duplicate wake for a live room is a no-op (the
// existing join's idle timer keeps running).
func (w *WatchServer) Wake(roomKey string) {
	roomKey = strings.ToLower(strings.TrimSpace(roomKey))
	w.mu.Lock()
	cfg, known := w.rooms[roomKey]
	_, live := w.active[roomKey]
	if !known || live {
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.active[roomKey] = cancel
	w.mu.Unlock()

	log.Printf("vks watch: waking room %s (%s) on demand", cfg.RoomURL, cfg.Provider)
	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.active, roomKey)
			w.mu.Unlock()
			cancel()
			log.Printf("vks watch: room %s released (idle)", cfg.RoomURL)
			if cfg.CleanupHook != nil {
				cfg.CleanupHook() // MTS lifecycle: delete the meeting
			}
		}()
		if err := RunServer(ctx, cfg, w.hooks); err != nil {
			log.Printf("vks watch: room %s error: %v", cfg.RoomURL, err)
		}
	}()
}

// AssignRoom is the beacon-assignment entry point: given a provider name it
// returns a room the client should join. It first tries the dynamic RoomCreator
// (WB/Jazz create a FRESH room — full bandwidth per client); when the creator
// cannot handle the provider (telemost/mts need account cookies) it falls
// back to an IDLE room from the statically armed pool of that provider; if
// every armed room of the provider is busy it wakes the least harmful one
// (shared bandwidth — still a working tunnel). The returned config has the
// room already armed and waking.
func (w *WatchServer) AssignRoom(ctx context.Context, provider string) (Config, error) {
	w.mu.Lock()
	creator := w.creator
	keyHex := w.keyHex
	w.mu.Unlock()

	if keyHex == "" {
		return Config{}, fmt.Errorf("vks watch: no key configured")
	}
	if creator != nil {
		cfg, err := creator(ctx, provider)
		if err == nil {
			cfg.IdleTimeout = w.idle
			w.Serve(cfg)
			return cfg, nil
		}
		if !errors.Is(err, ErrNoDynamicRoom) {
			return Config{}, err
		}
	}
	// Fall back: pick a room of this provider from the armed pool.
	w.mu.Lock()
	defer w.mu.Unlock()
	var idleK, busyK string
	var idleCfg Config
	for k, cfg := range w.rooms {
		if cfg.Provider != provider {
			continue
		}
		if _, live := w.active[k]; !live {
			if idleK == "" {
				idleK, idleCfg = k, cfg
			}
		} else if busyK == "" {
			busyK = k
		}
	}
	if idleK != "" {
		go w.Wake(idleK)
		return idleCfg, nil
	}
	if busyK != "" {
		// All armed rooms of this provider are busy — wake one (shared).
		go w.Wake(busyK)
		return w.rooms[busyK], nil
	}
	return Config{}, fmt.Errorf("vks watch: provider %q has no armed rooms and no creator", provider)
}

// ActiveRooms reports the number of rooms currently joined (diagnostics).
func (w *WatchServer) ActiveRooms() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.active)
}
