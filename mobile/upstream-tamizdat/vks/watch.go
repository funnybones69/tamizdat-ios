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
	creator RoomCreator
	// telemostPool, when set, feeds AssignRoom's telemost branch with
	// previously created (persistent, reusable) rooms and records newly
	// created ones for reuse across restarts.
	telemostPool *TelemostPool
	// maxRooms caps the number of simultaneously joined rooms (0 =
	// unlimited). At the cap AssignRoom shares a busy telemost room or
	// fails over — it never joins a new room.
	maxRooms int
	// creds is the mutable provider credential store (telemost/mts
	// cookies); the beacon handler reads its login-required set for the
	// TXT flags.
	creds *CredStore
	// nativeServe, when set, serves a woken room via the NATIVE transport
	// (TLS+masq over the datachannel, shortid-only — no olcRTC) instead of
	// the olcRTC RunServer. Wired by the cmd when the native serve is
	// enabled.
	nativeServe func(ctx context.Context, cfg Config) error
	// validateShortID, when set, gates the provider beacon: the beacon carries
	// the client's shortid and the room is only created/assigned when the
	// shortid is a valid user (closes the unauthenticated-amplification gap).
	validateShortID func(shortIDHex string) bool

	mu      sync.Mutex
	rooms   map[string]Config             // roomKey -> room it may serve
	active  map[string]context.CancelFunc // roomKey -> cancel of the live join
	dynamic map[string]bool               // roomKey -> came from the creator, not the armed pool
}

// NewWatchServer builds an on-demand server over the given room configs.
func NewWatchServer(rooms []Config, hooks ServerHooks, idle time.Duration) *WatchServer {
	if idle <= 0 {
		idle = 120 * time.Second
	}
	w := &WatchServer{
		hooks:   hooks,
		idle:    idle,
		rooms:   map[string]Config{},
		active:  map[string]context.CancelFunc{},
		dynamic: map[string]bool{},
	}
	for _, cfg := range rooms {
		cfg.IdleTimeout = idle
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

// SetNativeServe makes the watch server serve woken rooms via the NATIVE
// transport (TLS+masq over the datachannel, shortid-only — no olcRTC).
func (w *WatchServer) SetNativeServe(fn func(ctx context.Context, cfg Config) error) {
	w.mu.Lock()
	w.nativeServe = fn
	w.mu.Unlock()
}

// SetShortIDValidator gates the provider beacon on a valid user shortid —
// a beacon that does not prove a valid user gets no room (closes the
// unauthenticated-amplification gap where anyone with the wire key could
// make the server create rooms).
func (w *WatchServer) SetShortIDValidator(fn func(shortIDHex string) bool) {
	w.mu.Lock()
	w.validateShortID = fn
	w.mu.Unlock()
}

// SetTelemostPool installs the reusable telemost room pool: idle pool
// rooms are assigned before creating a new one, and created rooms land
// there for reuse across restarts.
func (w *WatchServer) SetTelemostPool(pool *TelemostPool) {
	w.mu.Lock()
	w.telemostPool = pool
	w.mu.Unlock()
}

// SetMaxRooms caps the number of simultaneously joined rooms (0 =
// unlimited). At the cap AssignRoom shares a busy telemost room or
// returns an error (client failover) — it never joins a new room.
func (w *WatchServer) SetMaxRooms(n int) {
	w.mu.Lock()
	w.maxRooms = n
	w.mu.Unlock()
}

// SetCredStore installs the mutable credential store whose
// login-required set is advertised in the beacon TXT flags.
func (w *WatchServer) SetCredStore(creds *CredStore) {
	w.mu.Lock()
	w.creds = creds
	w.mu.Unlock()
}

// providerNames is the set of providers a beacon may select. Kept in sync
// with ParseSpec's accepted prefixes.
var providerNames = []string{"telemost", "wbstream", "jazz", "mts"}

// matchProviderKey maps a beacon selector to a provider name when the
// selector equals that provider's ProviderWakeKey for the beaconing user.
// The shortid is the only credential: the selector proves the caller knows
// the shortid it already carries in the query name, so the server needs no
// shared secret and no user enumeration.
func matchProviderKey(selector, shortIDHex string) string {
	if selector == "" || shortIDHex == "" {
		return ""
	}
	for _, p := range providerNames {
		if ProviderWakeKey(shortIDHex, p) == selector {
			return p
		}
	}
	return ""
}

// roomKey is the server's INTERNAL map key for a room. It is deliberately
// not a credential: the wake selector a client sends is derived per user
// (RoomWakeKey) and matched against the armed rooms by the beacon handler.
func (w *WatchServer) roomKey(cfg Config) string {
	return cfg.Provider + "\x00" + cfg.RoomURL
}

// matchRoomKey maps a per-user wake selector to the internal key of an
// armed room. The server iterates its (small) armed set because the
// selector is now derived from the beaconing user's shortid, so it is not
// known at startup.
func (w *WatchServer) matchRoomKey(selector, shortIDHex string) (string, bool) {
	if selector == "" || shortIDHex == "" {
		return "", false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, cfg := range w.rooms {
		if RoomWakeKey(shortIDHex, cfg.Provider, cfg.RoomURL) == selector {
			return k, true
		}
	}
	return "", false
}

// shortIDKey turns the user's shortid (16 hex chars) into HMAC key
// material. A malformed value is used verbatim so the derivation is still
// deterministic; the server's validator rejects it before any room is
// assigned.
func shortIDKey(shortIDHex string) []byte {
	sid := strings.ToLower(strings.TrimSpace(shortIDHex))
	if b, err := hex.DecodeString(sid); err == nil && len(b) > 0 {
		return b
	}
	return []byte(sid)
}

// DeriveWireKey returns the legacy olcRTC wire key derived from a user
// shortid. The native transport does not use it; it lets the legacy
// olcRTC ladder run without a separately configured shared secret. A
// deployment serving that ladder must set -vks-key to this value for the
// single user it serves (the olcRTC handshake has one key for the room).
func DeriveWireKey(shortIDHex string) string {
	mac := hmac.New(sha256.New, shortIDKey(shortIDHex))
	mac.Write([]byte("vks-wire\x00"))
	return hex.EncodeToString(mac.Sum(nil))
}

// RoomWakeKey computes the beacon token that wakes the given armed room on
// behalf of one user. Shared by the server (to match) and the client (to
// emit). The shortid replaces the old shared wire key: different users get
// different selectors for the same room, so a leaked selector identifies
// one user rather than the whole deployment.
func RoomWakeKey(shortIDHex, provider, roomURL string) string {
	mac := hmac.New(sha256.New, shortIDKey(shortIDHex))
	mac.Write([]byte("vks-wake\x00" + strings.ToLower(strings.TrimSpace(provider)) + "\x00" + roomURL))
	return hex.EncodeToString(mac.Sum(nil))[:24]
}

// ProviderWakeKey computes the beacon token that asks the server to CREATE
// (or assign) a room on the given provider for one user. The beacon carries
// this value; the server matches it against its enabled providers and
// responds with the room spec in the DNS TXT answer.
func ProviderWakeKey(shortIDHex, provider string) string {
	mac := hmac.New(sha256.New, shortIDKey(shortIDHex))
	mac.Write([]byte("vks-provider\x00" + strings.ToLower(strings.TrimSpace(provider))))
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
		w.dynamic[roomKey] = true
	}
	w.mu.Unlock()
	w.Wake(roomKey)
	return roomKey
}

// Wake joins the named room if it is configured and not already live. Safe
// for concurrent calls; a duplicate wake for a live room is a no-op (the
// existing join's idle timer keeps running).
func (w *WatchServer) Wake(roomKey string) {
	roomKey = strings.TrimSpace(roomKey)
	w.mu.Lock()
	cfg, known := w.rooms[roomKey]
	_, live := w.active[roomKey]
	dynamic := w.dynamic[roomKey]
	if !known || live {
		w.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.active[roomKey] = cancel
	w.mu.Unlock()

	log.Printf("vks watch: waking room %s (%s) on demand", cfg.RoomURL, cfg.Provider)
	w.mu.Lock()
	nativeServe := w.nativeServe
	w.mu.Unlock()
	go func() {
		defer func() {
			w.mu.Lock()
			delete(w.active, roomKey)
			// A dynamic room (beacon-created, not in the armed startup set)
			// is dead once released: its MTS meeting is deleted by
			// CleanupHook, its WB/Jazz room is abandoned. Keeping it in
			// w.rooms made the map grow without bound on a long-lived
			// server and let AssignRoom hand out a room whose meeting no
			// longer exists.
			if dynamic {
				delete(w.rooms, roomKey)
			}
			w.mu.Unlock()
			cancel()
			log.Printf("vks watch: room %s released (idle)", cfg.RoomURL)
			if cfg.CleanupHook != nil {
				cfg.CleanupHook() // MTS lifecycle: delete the meeting
			}
		}()
		if nativeServe != nil {
			if err := nativeServe(ctx, cfg); err != nil {
				log.Printf("vks watch: native room %s error: %v", cfg.RoomURL, err)
			}
			return
		}
		if err := RunServer(ctx, cfg, w.hooks); err != nil {
			log.Printf("vks watch: room %s error: %v", cfg.RoomURL, err)
		}
	}()
}

// AssignRoom is the beacon-assignment entry point: given a provider name it
// returns a room the client should join.
//
// Telemost: rooms are REUSABLE (anonymous join, no deletion), so an idle
// pool room (armed -vks-watch rooms + previously created rooms from the
// TelemostPool) is handed out first; a new one is created only when all
// are busy. WB/Jazz: the RoomCreator mints a FRESH room (full bandwidth
// per client). MTS: creator lifecycle, falling back to the armed pool.
//
// Room cap: when -vks-max-rooms N (N > 0) and the live room count is at
// N, no NEW room is joined — for telemost a busy pool room is shared
// (vp8channel carries many peers per room); for other providers an error
// comes back so the client fails over to the next provider.
//
// Errors: ErrLoginRequired (wrapped) when the provider's cookies are
// dead — the beacon answers with an empty spec plus login flags, never a
// silent fallback.
func (w *WatchServer) AssignRoom(ctx context.Context, provider string) (Config, error) {
	w.mu.Lock()
	creator := w.creator
	maxRooms := w.maxRooms
	w.mu.Unlock()

	// Telemost: reuse an idle pool room before creating anything.
	if provider == "telemost" {
		if cfg, ok := w.assignTelemostFromPool(maxRooms); ok {
			return cfg, nil
		}
	}

	if creator != nil {
		// Room cap: a full server must not join a new room. Telemost
		// still gets a busy pool room (shared, see below); the others
		// fail over.
		if maxRooms > 0 && w.ActiveRooms() >= maxRooms {
			if provider == "telemost" {
				if cfg, ok := w.shareBusyTelemost(); ok {
					return cfg, nil
				}
			}
			return Config{}, fmt.Errorf("vks watch: room cap %d reached for %s", maxRooms, provider)
		}
		cfg, err := creator(ctx, provider)
		if err == nil {
			cfg.IdleTimeout = w.idle
			if provider == "telemost" {
				w.rememberTelemostRoom(cfg.RoomURL)
			}
			w.Serve(cfg)
			return cfg, nil
		}
		if errors.Is(err, ErrLoginRequired) {
			return Config{}, err
		}
		if !errors.Is(err, ErrNoDynamicRoom) {
			return Config{}, err
		}
	}
	// Fall back: pick a room of this provider from the armed pool.
	w.mu.Lock()
	defer w.mu.Unlock()
	// Room cap applies here too: at the cap a busy armed room of the
	// provider is SHARED (it is already joined — no new room), but an
	// idle one must not be woken (that would be a new join). For
	// non-telemost providers the cap means fail-over.
	if maxRooms > 0 && len(w.active) >= maxRooms {
		if busyK := w.busyRoomOf(provider); busyK != "" && provider == "telemost" {
			return w.rooms[busyK], nil
		}
		return Config{}, fmt.Errorf("vks watch: room cap %d reached for %s", maxRooms, provider)
	}
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
		// All armed rooms of the provider are busy — wake one (shared).
		go w.Wake(busyK)
		return w.rooms[busyK], nil
	}
	return Config{}, fmt.Errorf("vks watch: provider %q has no armed rooms and no creator", provider)
}

// busyRoomOf returns the roomKey of any LIVE room of the provider, or "".
// Call with w.mu held.
func (w *WatchServer) busyRoomOf(provider string) string {
	for k, cfg := range w.rooms {
		if cfg.Provider != provider {
			continue
		}
		if _, live := w.active[k]; live {
			return k
		}
	}
	return ""
}

// assignTelemostFromPool returns an idle telemost room (armed or from the
// reusable pool) with its wake already scheduled. ok=false when no idle
// telemost room exists (the caller creates one — subject to the room cap).
func (w *WatchServer) assignTelemostFromPool(maxRooms int) (Config, bool) {
	// Fold pool rooms into the armed set once: they behave exactly like
	// -vks-watch telemost rooms (anonymous join, wake on demand, released
	// back to idle — never deleted).
	w.mu.Lock()
	if w.telemostPool != nil {
		for _, roomURL := range w.telemostPool.Rooms() {
			key := w.roomKey(Config{Provider: "telemost", RoomURL: roomURL})
			if _, known := w.rooms[key]; !known {
				cfg := Config{Provider: "telemost", RoomURL: roomURL, IdleTimeout: w.idle}
				w.rooms[key] = cfg
				w.dynamic[key] = false // pool rooms persist — never dropped on release
			}
		}
	}
	w.mu.Unlock()
	return w.pickIdleRoom("telemost", maxRooms)
}

// rememberTelemostRoom adds a freshly created telemost room to the
// persistent pool (dedup by URL).
func (w *WatchServer) rememberTelemostRoom(roomURL string) {
	w.mu.Lock()
	pool := w.telemostPool
	w.mu.Unlock()
	if pool != nil {
		pool.Add(roomURL)
	}
}

// shareBusyTelemost returns a live telemost room for sharing (vp8channel
// supports many peers per room). ok=false when no live telemost room
// exists — the caller then errors out (cap + no pool room).
func (w *WatchServer) shareBusyTelemost() (Config, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, cfg := range w.rooms {
		if cfg.Provider != "telemost" {
			continue
		}
		if _, live := w.active[k]; live {
			return cfg, true
		}
	}
	return Config{}, false
}

// pickIdleRoom returns one not-live room of the provider, waking it.
// Under the room cap it refuses instead (ok=false) — the cap means "join
// nothing new", including waking an idle armed room.
func (w *WatchServer) pickIdleRoom(provider string, maxRooms int) (Config, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if maxRooms > 0 && len(w.active) >= maxRooms {
		return Config{}, false
	}
	for k, cfg := range w.rooms {
		if cfg.Provider != provider {
			continue
		}
		if _, live := w.active[k]; !live {
			go w.Wake(k)
			return cfg, true
		}
	}
	return Config{}, false
}

// ActiveRooms reports the number of rooms currently joined (diagnostics).
func (w *WatchServer) ActiveRooms() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.active)
}
