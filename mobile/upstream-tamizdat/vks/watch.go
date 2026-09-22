package vks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	hooks ServerHooks
	idle  time.Duration

	mu     sync.Mutex
	rooms  map[string]Config          // roomKey -> room it may serve
	active map[string]context.CancelFunc // roomKey -> cancel of the live join
}

// NewWatchServer builds an on-demand server over the given room configs.
// Each room's key is derived from the shared wire key, so a wake signal both
// authenticates the caller (it must know the key) and selects the room.
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
		w.rooms[w.roomKey(cfg)] = cfg
	}
	return w
}

// roomKey derives the stable, DNS-safe selector for a room from the shared
// wire key. A client proves it knows the key by beaconed this value; a
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
		}()
		if err := RunServer(ctx, cfg, w.hooks); err != nil {
			log.Printf("vks watch: room %s error: %v", cfg.RoomURL, err)
		}
	}()
}

// ActiveRooms reports the number of rooms currently joined (diagnostics).
func (w *WatchServer) ActiveRooms() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.active)
}
