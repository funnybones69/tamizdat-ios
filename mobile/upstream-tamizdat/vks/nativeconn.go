package vks

// nativeconn.go — the native VKS tunnel transport: TLS+masq over a VKS room
// datachannel, replacing the olcRTC epoch/keyHex/smux protocol with the
// native tamizdat session (shortid auth only — no separate wire key).
//
// Architecture:
//   - The provider engine (jazz/mts/wb/telemost SFU join + WebRTC) stays —
//    it is the VKS integration, not the olc protocol.
//   - The room datachannel (reliable+ordered, E2E DTLS-encrypted) becomes a
//    net.Conn. TLS requires an ordered reliable byte stream; the datachannel
//    provides exactly that, so TLS records reassemble correctly from the
//    ordered message stream without any sequence layer.
//   - The NATIVE tamizdat transport (utls + masq + shortid session-ID auth,
//    the same stack as the h2 transport) runs over that net.Conn:
//    client via Config.Dialer, server via Server.Serve(net.Listener).
//   - Peer discovery: the client broadcasts TMZD_HELLO; the server answers
//    TMZD_SERVER addressed to the client's peerID. After the handshake both
//    sides are peer-keyed (SendTo/OnPeerData by peerID), so multiple clients
//    in one room never interleave.

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/vks/olc/core/app/session"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport/vp8channel"
)

const (
	// dcMaxMessage caps ONE datachannel message, tag included. Every message is
	// prefixed with the 4-byte session tag, and the SFU drops anything over
	// 12 KiB, so a full-size payload chunk plus its tag would be 4 bytes too
	// large and the stream would hang with no error and no write failure to
	// trip the dead-session path.
	dcMaxMessage = 12 * 1024
	dcTagLen     = 4

	// discoveryBudget bounds the client's TMZD_HELLO discovery wait. It must
	// stay well below the join-grace window the on-demand server gives a
	// freshly assigned room (watchIdle join grace = IdleTimeout, default
	// 120 s), otherwise the client gives up and evicts the shared session
	// before the server has finished joining the room the beacon minted.
	discoveryBudget = 30 * time.Second

	// Discovery magics: client → room, server → client peer.
	tmzdHello  = "TMZD_HELLO"
	tmzdServer = "TMZD_SERVER"
)

// dcConn is a net.Conn over a VKS room datachannel, peer-keyed to one remote.
// Every message carries a 4-byte session tag so concurrent dial retries on the
// shared broadcast lane never interleave (each session reads only its own tag).
type dcConn struct {
	tr            transport.Transport
	mu            sync.Mutex
	peer          string // latched remote peerID; "" = broadcast (pre-discovery)
	sid           []byte // 4-byte session tag (client-generated; echoed both directions)
	rbuf          []byte
	notify        chan struct{}
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	local         net.Addr
	remote        net.Addr
	onClose       func()
	onWriteErr    func(error)
}

func newDcConn(tr transport.Transport, local, remote net.Addr) *dcConn {
	return &dcConn{tr: tr, notify: make(chan struct{}), local: local, remote: remote}
}

// latchPeer pins the remote peerID (post-discovery: all writes become SendTo).
func (c *dcConn) latchPeer(peerID string) {
	c.mu.Lock()
	if c.peer == "" {
		c.peer = peerID
	}
	c.mu.Unlock()
}

// feed appends an incoming message payload to the reassembly buffer. Only
// messages carrying this session's tag are admitted; anything else (a retried
// dial's stale bytes, another session) is dropped.
func (c *dcConn) feed(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A conn with no tag is pre-discovery broadcast state: nothing on the
	// tagged lanes belongs to it. The old code admitted ANY frame when sid
	// was nil (tag check skipped), so another dial's tagged bytes
	// interleaved into this conn's buffer and corrupted both streams.
	if c.sid == nil || c.closed {
		return
	}
	if len(data) < 4 || string(data[:4]) != string(c.sid) {
		return // not our session — drop
	}
	c.rbuf = append(c.rbuf, data[4:]...)
	close(c.notify)
	c.notify = make(chan struct{})
}

func (c *dcConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.rbuf) > 0 {
			n := copy(p, c.rbuf)
			c.rbuf = c.rbuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.closed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		ch := c.notify
		deadline := c.readDeadline
		c.mu.Unlock()

		if deadline.IsZero() {
			<-ch
			continue
		}
		t := time.NewTimer(time.Until(deadline))
		select {
		case <-ch:
			t.Stop()
		case <-t.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *dcConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	peer := c.peer
	sid := c.sid
	c.mu.Unlock()
	// Chunk into datachannel messages, each prefixed with the session tag so a
	// retried dial's bytes never interleave into this session's stream.
	//
	// The carrier's own framing consumes part of the engine's
	// maxDataChannelMessageSize (jazz: DataPacket envelope + 12-byte epoch
	// header; mts: 12-byte epoch header; jazz/mts Send also DROPS anything
	// larger outright, so an oversized chunk is a silent stall, not an error).
	// Budget for the worst overhead we know (envelope ~12 + epoch 12) and
	// keep tag+chunk inside it.
	chunk := dcMaxMessage - dcTagLen - 24
	for off := 0; off < len(p); off += chunk {
		end := off + chunk
		if end > len(p) {
			end = len(p)
		}
		msg := make([]byte, 0, 4+(end-off))
		msg = append(msg, sid...)
		msg = append(msg, p[off:end]...)
		var err error
		if peer != "" {
			err = sendTo(c.tr, peer, msg)
		} else {
			err = c.tr.Send(msg)
		}
		if err != nil {
			if c.onWriteErr != nil {
				c.onWriteErr(err)
			}
			return off, err
		}
	}
	return len(p), nil
}

func (c *dcConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.notify)
	c.notify = make(chan struct{})
	c.mu.Unlock()
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

func (c *dcConn) LocalAddr() net.Addr  { return c.local }
func (c *dcConn) RemoteAddr() net.Addr { return c.remote }

// InProcessTransport reports that this conn is manufactured by the in-process
// room datachannel rather than accepted from a socket, so server-side handling
// keyed on a real TCP peer — the PROXY-protocol trust gate, TCP socket
// options — must not apply. See tamizdat.isInProcessConn.
func (c *dcConn) InProcessTransport() bool { return true }

func (c *dcConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *dcConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	// Wake any blocked reader so it re-evaluates the new deadline.
	close(c.notify)
	c.notify = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *dcConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// dcAddr is a minimal net.Addr for a room peer.
type dcAddr string

func (a dcAddr) Network() string { return "vks-dc" }
func (a dcAddr) String() string  { return string(a) }

// peerSender is the SendTo-capable slice of a transport (PeerTransport).
type peerSender interface {
	SendTo(peerID string, data []byte) error
}

// sendTo routes a payload to a peer when the transport supports peer
// addressing AND the peerID is known; an empty peerID broadcasts to the room
// (the beacon-assignment model is 1 server + 1 client, so broadcast reaches
// the single remote peer).
func sendTo(tr transport.Transport, peerID string, data []byte) error {
	if peerID == "" {
		return tr.Send(data)
	}
	if ps, ok := tr.(peerSender); ok {
		return ps.SendTo(peerID, data)
	}
	return tr.Send(data)
}

// ---------------------------------------------------------------------------
// Client side: dial the native tamizdat session over a room datachannel.
// ---------------------------------------------------------------------------
// Shared room sessions
//
// A VKS room join is expensive (WS + ICE + datachannel open; measured ~3 s on
// jazz) and the SFU session must NOT be tied to a single dial's context: the
// client transport pool discards a dial as soon as it returns, so a per-dial
// session would die with it and the pool would re-join on every attempt - an
// unbounded join/re-dial loop in which no traffic ever flows. The room session
// is therefore hoisted into a cache keyed by (provider, room, key) with a
// lifecycle independent of any single dial; each dial opens only a fresh
// logical stream (its own 4-byte tag) over that shared session.
// ---------------------------------------------------------------------------

// dcJoinTimeout bounds a single room join, so a hung join cannot block later
// dials on the same key forever.
const dcJoinTimeout = 45 * time.Second

// dcDial is one logical stream (one dial) on a shared room session: its tag,
// its conn, and the callback that reports discovery for that dial.
type dcDial struct {
	sid    string
	conn   *dcConn
	notify func(peerID string)
}

// dcSession is a joined VKS room shared by every dial on the same key.
type dcSession struct {
	tr   transport.Transport
	dead atomic.Bool

	closeOnce sync.Once

	everHealthy atomic.Bool

	// cancelWatch stops the session's WatchConnection goroutine; nil until
	// the join succeeds.
	cancelWatch context.CancelFunc

	mu    sync.Mutex
	dials map[string]*dcDial
}

func newDcSession(tr transport.Transport) *dcSession {
	return &dcSession{tr: tr, dials: map[string]*dcDial{}}
}

func (s *dcSession) add(d *dcDial) {
	s.mu.Lock()
	s.dials[d.sid] = d
	s.mu.Unlock()
}

func (s *dcSession) remove(sid string) {
	s.mu.Lock()
	delete(s.dials, sid)
	s.mu.Unlock()
}

func (s *dcSession) lookup(sid string) *dcDial {
	s.mu.Lock()
	d := s.dials[sid]
	s.mu.Unlock()
	return d
}

// markDead invalidates the session and releases it. The engine websocket,
// PeerConnections and ping goroutines all hang off tr, so a dead room that is
// never closed leaks them (and leaves a ghost participant in the room).
func (s *dcSession) markDead() { s.dead.Store(true) }

// healthy reports whether any dial on this session completed peer discovery,
// i.e. the room was usable at least once.
func (s *dcSession) healthy() bool { return s.everHealthy.Load() }

// Close tears the room session down - every dial connector plus the underlying
// transport. Idempotent.
func (s *dcSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.dead.Store(true)
		if s.cancelWatch != nil {
			s.cancelWatch()
		}
		s.mu.Lock()
		dials := make([]*dcDial, 0, len(s.dials))
		for _, d := range s.dials {
			dials = append(dials, d)
		}
		s.dials = map[string]*dcDial{}
		tr := s.tr
		s.mu.Unlock()
		for _, d := range dials {
			_ = d.conn.Close()
		}
		if tr != nil {
			err = tr.Close()
		}
	})
	return err
}

func tagOf(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	return string(data[:4])
}

// onData routes one broadcast-lane frame to the dial it belongs to: the
// discovery answer by its embedded tag, tagged payload bytes to its conn.
func (s *dcSession) onData(data []byte) {
	if len(data) >= 15 && string(data[:11]) == tmzdServer {
		if d := s.lookup(string(data[11:15])); d != nil {
			d.notify("broadcast")
		}
		return
	}
	if len(data) >= 14 && string(data[:10]) == tmzdHello {
		return // our own hello, echoed back by the SFU
	}
	if d := s.lookup(tagOf(data)); d != nil {
		d.conn.feed(data)
	}
}

// onPeerData is onData for the peer-addressed lane.
func (s *dcSession) onPeerData(peerID string, data []byte) {
	if len(data) >= 15 && string(data[:11]) == tmzdServer {
		if d := s.lookup(string(data[11:15])); d != nil {
			d.notify(peerID)
		}
		return
	}
	if len(data) >= 14 && string(data[:10]) == tmzdHello {
		return
	}
	if d := s.lookup(tagOf(data)); d != nil {
		d.conn.feed(data)
	}
}

var (
	dcCacheMu sync.Mutex
	dcCache   = map[string]*dcSession{}  // key -> joined room session
	dcJoinMu  = map[string]*sync.Mutex{} // key -> join lock (single-flight)
	// dcEpoch invalidates joins that were already in flight when
	// ShutdownNativeSessions ran. A join can take up to dcJoinTimeout; the
	// shutdown empties dcCache meanwhile, so without this the finishing join
	// would re-insert a LIVE session that nothing owns any more — the SFU
	// websocket, PeerConnections and ping goroutine survive the teardown as a
	// ghost participant in the room.
	dcEpoch atomic.Uint64
)

func dcKey(cfg ClientConfig) string {
	return cfg.Provider + "\x00" + cfg.RoomURL + "\x00" + cfg.ShortIDHex
}

// resolvedName honours the documented contract (vks.go: "Name is the display
// name shown in the room. Empty = generated."). An empty name used to be
// passed through verbatim: jazz and mts tolerate it, but WB Stream's guest
// register rejects it with HTTP 400 ("invalid GuestRegisterRequest.DisplayName:
// value length must be at least 1 runes"), which killed the entire wbstream
// leg of the ladder. Name is not part of dcKey, so resolving it here cannot
// split a session.
func (c Config) resolvedName() string {
	if c.Name == "" {
		return DisplayName()
	}
	return c.Name
}

// dcJoinLock returns the per-key join lock, creating it on first use.
func dcJoinLock(key string) *sync.Mutex {
	dcCacheMu.Lock()
	defer dcCacheMu.Unlock()
	m := dcJoinMu[key]
	if m == nil {
		m = &sync.Mutex{}
		dcJoinMu[key] = m
	}
	return m
}

func dcCached(key string) *dcSession {
	dcCacheMu.Lock()
	s := dcCache[key]
	if s != nil && s.dead.Load() {
		delete(dcCache, key)
		dcCacheMu.Unlock()
		_ = s.Close()
		return nil
	}
	dcCacheMu.Unlock()
	return s
}

// evictDcSession drops sess if it is still the cached one and closes it, so a
// room that failed its discovery wait is not handed to the next dial.
func evictDcSession(cfg ClientConfig, sess *dcSession) {
	key := dcKey(cfg)
	dcCacheMu.Lock()
	if dcCache[key] == sess {
		delete(dcCache, key)
	}
	dcCacheMu.Unlock()
	_ = sess.Close()
}

// ShutdownNativeSessions closes every cached room session. The iOS network
// extension calls it when it stops the native upstream, so no SFU websocket,
// PeerConnection or ping goroutine survives the tunnel.
func ShutdownNativeSessions() {
	// Bump first: a join that is in flight right now must see the new epoch
	// when it finishes and discard its session instead of reviving the cache.
	dcEpoch.Add(1)
	dcCacheMu.Lock()
	sessions := make([]*dcSession, 0, len(dcCache))
	for k, s := range dcCache {
		sessions = append(sessions, s)
		delete(dcCache, k)
	}
	dcCacheMu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
}

var (
	specCacheMu sync.Mutex
	specCache   = map[string]string{}      // provider|shortid -> beacon-assigned spec
	specWakeMu  = map[string]*sync.Mutex{} // provider|shortid -> beacon lock
)

// wakeSpecLock returns the per-key beacon lock, creating it on first use.
func wakeSpecLock(key string) *sync.Mutex {
	specCacheMu.Lock()
	defer specCacheMu.Unlock()
	m := specWakeMu[key]
	if m == nil {
		m = &sync.Mutex{}
		specWakeMu[key] = m
	}
	return m
}

// wakeSpecKey identifies an on-demand assignment: the beacon is per provider
// and the assignment is authenticated by the user shortid.
func wakeSpecKey(cfg ClientConfig) string {
	return cfg.Provider + "\x00" + cfg.ShortIDHex
}

// dropWakeSpec forgets the cached assignment so the next dial beacons once
// more. Called only on a hard room failure, never per dial: the on-demand
// server mints a FRESH room for every beacon, so re-beaconing per dial is a
// room storm (and an idle-reaper backlog) on a single-CPU VPS.
func dropWakeSpec(key string) {
	specCacheMu.Lock()
	delete(specCache, key)
	specCacheMu.Unlock()
}

// resolveWakeSpec points cfg at the beacon-assigned room, reusing the cached
// assignment when there is one. It returns false when NO room was
// assigned (the beacon answered with an empty spec — e.g. the provider's
// cookies are dead on the server, or the room cap is hit): the dial must
// fail fast so NativeDialLadder moves to the next provider instead of
// dialing a stale static room. On a beacon transport failure (no answer
// at all) it keeps the static room (the on-demand server may simply be
// unreachable through this resolver).
func resolveWakeSpec(ctx context.Context, cfg *ClientConfig, key string) bool {
	// Single-flight per key. The check-then-beacon below used to be racy: the
	// first real flow and the ping prober's first probe dial at the same
	// moment, both found the cache empty and both sent a beacon. The on-demand
	// server mints a FRESH room for every beacon, so the two sides ended up in
	// different rooms and the dial timed out (observed: one dial produced three
	// rooms and no peer). One beacon per key, the rest wait for its result.
	lk := wakeSpecLock(key)
	lk.Lock()
	defer lk.Unlock()
	specCacheMu.Lock()
	spec, cached := specCache[key]
	specCacheMu.Unlock()
	if !cached {
		// The beacon runs detached from the caller's dial ctx: the RTT
		// prober dials with a 3 s budget, and a beacon cancelled mid-flight
		// by an expiring probe discarded the room the server had just
		// minted (the next dial re-beaconed and got another one — the
		// observed "one dial, three rooms" storm). The beacon carries its
		// own bounded deadline; the caller can still stop waiting via its
		// own ctx (it just fails this dial, the assignment stays cached).
		bctx, bcancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer bcancel()
		s, _, err := SendWakeProvider(bctx, cfg.WakeDNSServer, cfg.WakeZone, cfg.Provider, cfg.ShortIDHex)
		if err != nil {
			// Swallowing this made a dead wake channel look like a
			// configured static room that never answers: every dial fell
			// back silently and timed out with no attributable cause.
			log.Printf("[native] wake beacon for %s failed: %v (falling back to the static room)",
				cfg.Provider, err)
			return true
		}
		spec = s
		specCacheMu.Lock()
		specCache[key] = spec
		specCacheMu.Unlock()
	}
	if strings.TrimSpace(spec) == "" {
		// The server answered explicitly "no room for this provider". Cache
		// the refusal too: re-beaconing per dial would hammer the NS while
		// the server is in a login-required state, and the client has the
		// flags to prompt for re-upload (LoginRequiredProviders).
		log.Printf("[native] wake beacon for %s answered empty spec (login required: %v) — failing the dial",
			cfg.Provider, LoginRequiredProviders())
		return false
	}
	if p, r, ok := splitProviderRoom(spec); ok {
		cfg.Provider, cfg.RoomURL = p, r
	}
	return true
}

// acquireDcSession returns the cached room session for cfg, joining at most
// once per key at a time - a burst of SOCKS dials must not start N joins.
func acquireDcSession(ctx context.Context, cfg ClientConfig) (*dcSession, error) {
	key := dcKey(cfg)
	lk := dcJoinLock(key)
	lk.Lock()
	defer lk.Unlock()
	// Snapshot the epoch AFTER taking the join lock: a shutdown that ran
	// while this dial was parked on the lock must invalidate the join we
	// are about to start, not just one already in flight (snapshotting
	// earlier left exactly that window — a join started under a torn-down
	// native path and cached as a ghost).
	epoch := dcEpoch.Load()
	if s := dcCached(key); s != nil {
		return s, nil
	}
	s, err := joinDcSession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if dcEpoch.Load() != epoch {
		// The native path was shut down (or re-armed) while this join was
		// running: the session has no owner now, so close it and report the
		// dial as failed instead of reviving it into a cache nobody consults.
		// Name provider and room only - dcKey carries the shared room key.
		_ = s.Close()
		return nil, fmt.Errorf("native: session for %s/%s discarded: the native path was shut down during the join", cfg.Provider, cfg.RoomURL)
	}
	// Recheck and store under dcCacheMu: ShutdownNativeSessions empties the
	// cache under this same mutex, so a session stored after its bump is
	// collected by that shutdown instead of landing in an emptied map (the
	// recheck used to sit outside the lock, which left exactly that window).
	dcCacheMu.Lock()
	if dcEpoch.Load() != epoch {
		dcCacheMu.Unlock()
		_ = s.Close()
		return nil, fmt.Errorf("native: session for %s/%s discarded: the native path was shut down during the join", cfg.Provider, cfg.RoomURL)
	}
	dcCache[key] = s
	dcCacheMu.Unlock()
	return s, nil
}

// joinDcSession performs the one expensive room join for a key. The session
// runs on a context detached from the dial (context.WithoutCancel) so the SFU
// session survives the dial that created it; dcJoinTimeout keeps a hung join
// from blocking later dials on that key forever.
func joinDcSession(ctx context.Context, cfg ClientConfig) (*dcSession, error) {
	session.RegisterDefaults() // registers the provider auth flows (jazz/mts/wb/telemost)
	sessCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dcJoinTimeout)

	s := newDcSession(nil)
	// The carrier must match the provider, exactly as the olc path does.
	// transportName(): jazz -> datachannel, mts -> seichannel, telemost/wb ->
	// vp8channel. This used to be hardcoded to datachannel, so mts and
	// telemost ran their tunnel bytes over a carrier their SFU does not relay
	// (odin forwards only H264 SEI media, and only to subscribers; goolom
	// relays VP8): the session came up, the first frame went out, and the
	// channel died in the same second.
	tcfg := transport.Config{
		Provider:      cfg.Provider,
		RoomURL:       cfg.RoomURL,
		ProviderToken: cfg.ProviderToken,
		ChannelID:     cfg.ChannelID,
		Name:          cfg.resolvedName(),
		DNSServer:     cfg.DNSServer,
		Options:       cfg.transportOptions(),
		OnData:        s.onData,
		OnPeerData:    s.onPeerData,
	}
	if kcpCarrier(cfg.transportName()) {
		// One KCP state machine per pair. With OnPeerData set the KCP
		// carriers run in SERVER mode: a broadcast plane for sending plus a
		// per-peer session that receives the server's frames — two state
		// machines facing the server's one per-peer session, so ACKs landed
		// on the plane that did not send the data and the TLS flight never
		// completed. Client mode keeps a single data plane; the server's
		// discovery answer (addressed to our epoch) binds it.
		tcfg.OnPeerData = nil
		if o, ok := tcfg.Options.(vp8channel.Options); ok {
			o.AutoConfirmTargeted = true
			tcfg.Options = o
		}
	}
	tr, err := transport.New(sessCtx, cfg.transportName(), tcfg)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("native: open %s: %w", cfg.transportName(), err)
	}
	s.tr = tr
	log.Printf("[native] join %s: connecting room %s", cfg.Provider, cfg.RoomURL)
	if err := tr.Connect(sessCtx); err != nil {
		cancel()
		_ = tr.Close()
		return nil, fmt.Errorf("native: connect: %w", err)
	}
	cancel() // join phase done; the session itself is context-free

	// Own the session lifetime: WatchConnection parks until the engine
	// session ends (SFU closes the conference / WS / PC). Without this the
	// native path never learned the room died: the cached session stayed
	// "live" forever, every dial re-joined the corpse, and the SFU-side
	// zombie participant accumulated per churn cycle. The join timeout
	// ctx must NOT be reused here (it is already spent) — the watcher runs
	// under the session's own lifetime and ends via s.Close.
	watchCtx, watchCancel := context.WithCancel(context.WithoutCancel(ctx))
	s.cancelWatch = watchCancel
	tr.SetEndedCallback(func(reason string) {
		log.Printf("[native] join %s: room %s ended: %s — dropping the cached session", cfg.Provider, cfg.RoomURL, reason)
		evictDcSession(cfg, s)
	})
	tr.SetShouldReconnect(func() bool { return !s.dead.Load() })
	go func() {
		tr.WatchConnection(watchCtx)
		// WatchConnection returns when the engine session is over or the
		// session was closed locally: either way the cached session must
		// not be handed to new dials.
		evictDcSession(cfg, s)
	}()
	log.Printf("[native] join %s: room %s ready (session cached)", cfg.Provider, cfg.RoomURL)
	return s, nil
}

// NativeDialLadder dials the first spec in the ladder that comes up. The
// fallback exists for a primary that is not there: a provider that refuses
// fast (404 room, auth rejection, dead link) must not hold the whole dial, so
// the next spec is tried immediately.
//
// A primary that is merely SLOW is not covered here, and the bound is not the
// caller's per-flow budget: each leg's room join runs on a detached context
// (context.WithoutCancel plus dcJoinTimeout = 45s), and the Dialer is invoked
// synchronously, so a hung leg can hold the flow past the caller's own
// deadline before the ctx.Err() break below is reached. That case belongs to
// the outer olc ladder - and has no equivalent on the UDP path, which refuses
// outright rather than falling back.
func NativeDialLadder(ctx context.Context, cfgs []ClientConfig) (net.Conn, error) {
	var lastErr error
	for i := range cfgs {
		conn, err := NativeDial(ctx, cfgs[i])
		if err == nil {
			return conn, nil
		}
		lastErr = err
		log.Printf("[native] ladder: %s/%s failed: %v - trying the next spec", cfgs[i].Provider, cfgs[i].RoomURL, err)
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("native ladder: no spec to dial")
	}
	return nil, lastErr
}

// NativeDial returns a net.Conn ready for the native TLS+masq handshake. It
// reuses the shared room session for this (provider, room, key) - joining it
// once on first use - and discovers the server peer (TMZD_HELLO -> TMZD_SERVER)
// with a fresh 4-byte session tag. Used as Client.config.Dialer. When the wake
// beacon is configured it first asks the on-demand server for a room (the
// server creates/assigns one and answers in-band) and dials THAT room.
func NativeDial(ctx context.Context, cfg ClientConfig) (net.Conn, error) {
	// On-demand: point at the beacon-assigned room, reusing the cached
	// assignment so the server mints one room per (provider, key) rather than
	// one per dial. An empty spec (server-side login required / room cap)
	// fails THIS dial fast so the ladder moves on instead of joining a
	// stale static room.
	wakeKey := wakeSpecKey(cfg)
	if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
		if !resolveWakeSpec(ctx, &cfg, wakeKey) {
			return nil, fmt.Errorf("native dial: no room assigned for %s (login required: %v)",
				cfg.Provider, LoginRequiredProviders())
		}
	}
	sess, err := acquireDcSession(ctx, cfg)
	if err != nil {
		if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
			dropWakeSpec(wakeKey) // hard failure: re-beacon once on the next dial
		}
		return nil, fmt.Errorf("native dial: %w", err)
	}
	log.Printf("[native] dial %s: room %s session reused", cfg.Provider, cfg.RoomURL)

	// A random 4-byte session tag isolates this dial's byte stream from any
	// other dial on the shared room session (each stream reads only its own
	// tag; the server echoes it back so both directions are tagged alike).
	sid := make([]byte, 4)
	if _, err := rand.Read(sid); err != nil {
		return nil, fmt.Errorf("native dial: session id: %w", err)
	}
	conn := newDcConn(sess.tr, dcAddr("client"), dcAddr("server"))
	conn.sid = sid
	conn.onWriteErr = func(err error) {
		// Name the killer: this path used to drop the shared room session
		// silently, so the re-join cadence had no attributable cause.
		log.Printf("[native] dial %s: room %s write failed; marking room session dead: %v",
			cfg.Provider, cfg.RoomURL, err)
		sess.markDead()
	}
	conn.onClose = func() { sess.remove(string(sid)) }

	serverPeer := make(chan string, 1)
	sess.add(&dcDial{
		sid:  string(sid),
		conn: conn,
		notify: func(peerID string) {
			select {
			case serverPeer <- peerID:
			default:
			}
		},
	})

	// Broadcast the discovery probe (magic + session tag) until the server
	// answers. The wait runs on its own budget, NOT the caller's ctx: the
	// tamizdat pool's RTT prober dials every 1 s with a 3 s timeout, so a
	// caller deadline that expires while the on-demand server is still
	// joining the minted room used to evict the never-healthy session and
	// drop the wake spec — the next dial re-beaconed, got a FRESH room, and
	// the pool re-joined in a ~1 s churn loop that never converged.
	hello := append([]byte(tmzdHello), sid...)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	budget := time.NewTimer(discoveryBudget)
	defer budget.Stop()
	_ = sendTo(sess.tr, "", hello)
	for {
		select {
		case <-ctx.Done():
			// Caller gave up (RTT probe 3s, pool dial deadline): close THIS
			// dial's conn but do NOT evict the shared session or drop the
			// wake spec — the on-demand server may still be joining, and a
			// later dial reuses the room. Eviction on a caller deadline was
			// the re-beacon churn loop (one fresh room per probe).
			_ = conn.Close()
			return nil, ctx.Err()
		case <-budget.C:
			// The full discovery budget elapsed with no TMZD_SERVER: the
			// server peer is gone (server restart, ghost eviction, wrong
			// room). Evict UNCONDITIONALLY — a previously-healthy session
			// whose server vanished (engine still connected, SFU fine) is
			// the "reconnect to the same provider never re-handshakes"
			// wedge: HELLO retries go unanswered forever while the session
			// keeps its healthy flag. Closing it forces a fresh join (and
			// a fresh beacon) on the next dial.
			_ = conn.Close()
			evictDcSession(cfg, sess)
			if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
				dropWakeSpec(wakeKey)
			}
			return nil, fmt.Errorf("native dial %s: no server in room %s after %s (discovery timeout)",
				cfg.Provider, cfg.RoomURL, discoveryBudget)
		case peer := <-serverPeer:
			sess.everHealthy.Store(true)
			// The KCP carriers (vp8channel/seichannel) must stay on the
			// broadcast plane the hello went out on. Both native ends run
			// them in server mode (OnPeerData is set), so the server files
			// everything from this client under ONE per-peer KCP session; a
			// latched SendTo switched the client to a second KCP state
			// machine whose sequence numbers restart at zero, and the server
			// dropped the whole TLS flight as duplicates (telemost/mts
			// "TLS handshake: deadline"; see vp8channel
			// TestNativeLaneMixLoopback). Session tags already keep
			// concurrent dials apart on the broadcast lane.
			if peer != "broadcast" && !kcpCarrier(cfg.transportName()) {
				conn.latchPeer(peer)
			}
			log.Printf("[native] dial %s: server peer discovered: %s", cfg.Provider, peer)
			return conn, nil
		case <-ticker.C:
			_ = sendTo(sess.tr, "", hello)
		}
	}
}

// kcpCarrier reports whether a transport carries the native session over
// its own KCP planes (as opposed to a reliable datachannel).
func kcpCarrier(name string) bool {
	return name == "vp8channel" || name == "seichannel"
}

// ---------------------------------------------------------------------------
// Server side: accept native tamizdat sessions over a room datachannel.
// ---------------------------------------------------------------------------

// dcListener is a net.Listener over a VKS room datachannel: each client that
// completes the TMZD_HELLO discovery yields one dcConn via Accept.
type dcListener struct {
	tr      transport.Transport
	mu      sync.Mutex
	conns   map[string]*dcConn // peerID -> conn
	accept  chan *dcConn
	closed  bool
	closeCh chan struct{}
	addr    net.Addr
	// idle, when > 0, releases the room after this span with zero live
	// conns (the native analogue of Server.watchIdle: the watch server
	// arms woken rooms with IdleTimeout, but nothing implemented it on
	// this path, so every woken room lived forever — the server-side half
	// of the prod RSS growth and the room leak).
	idle time.Duration
	// pinPeer: the carrier keeps one KCP session per client (KCP
	// carriers), so the answer and every write of the accepted conn must go
	// to that client's session via SendTo, never the broadcast plane.
	pinPeer bool
}

// nativeListen joins the room as the host and returns a net.Listener whose
// Accept yields one dcConn per discovered client. Feed it to
// Server.Serve(listener) — the native TLS+masq+shortid handler runs unchanged.
func NativeListen(ctx context.Context, cfg Config) (*dcListener, error) {
	l := &dcListener{
		conns:   make(map[string]*dcConn),
		accept:  make(chan *dcConn, 16),
		closeCh: make(chan struct{}),
		addr:    dcAddr("server"),
		idle:    cfg.IdleTimeout,
		pinPeer: kcpCarrier(cfg.transportName()),
	}
	session.RegisterDefaults() // registers the provider auth flows (jazz/mts/wb/telemost)

	tr, err := transport.New(ctx, cfg.transportName(), transport.Config{
		Provider:      cfg.Provider,
		RoomURL:       cfg.RoomURL,
		ProviderToken: cfg.ProviderToken,
		ChannelID:     cfg.ChannelID,
		Name:          cfg.resolvedName(),
		DNSServer:     cfg.DNSServer,
		Options:       cfg.transportOptions(),
		OnData: func(data []byte) {
			// Discovery probe: "TMZD_HELLO" + 4-byte session tag.
			if len(data) >= 14 && string(data[:10]) == tmzdHello {
				l.handleHello("", data[10:14])
				return
			}
			// Post-discovery: session-tagged TLS/tunnel bytes — route by tag.
			l.route(data)
		},
		OnPeerData: func(peerID string, data []byte) {
			if len(data) >= 14 && string(data[:10]) == tmzdHello {
				l.handleHello(peerID, data[10:14])
				return
			}
			l.route(data)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("native listen: open %s: %w", cfg.transportName(), err)
	}
	l.tr = tr
	// If the caller's ctx dies while we are joining the room (or Connect
	// fails outright), the engine websocket/PeerConnections created by
	// transport.New must be closed here: nothing else owns tr yet. The
	// old path returned without closing it — a WS+PC+ping-goroutine leak
	// and a ghost participant on every failed watch-server wake.
	if err := tr.Connect(ctx); err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("native listen: connect: %w", err)
	}
	// The watch server cancels this ctx to release the room on idle; the
	// listener (and its engine session) must die with it, or the room is
	// leaked live: Serve sits in Accept forever and watch.Wake's teardown
	// goroutine never returns (CleanupHook never runs, room stays joined,
	// RSS climbs with every woken room).
	// The engine knows when the room actually dies (conference end, WS/PC
	// close). The native path never listened: a room the SFU kicked us out
	// of kept its listener "live" forever (watch marks it busy, Serve hangs
	// in Accept, the wake cache hands the corpse to later dials).
	tr.SetEndedCallback(func(reason string) {
		log.Printf("[native] listen %s: room %s ended: %s — closing listener", cfg.Provider, cfg.RoomURL, reason)
		_ = l.Close()
	})
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-l.closeCh:
		}
	}()
	if l.idle > 0 {
		go l.watchIdle()
	}
	log.Printf("[native] listen %s: room %s connected, awaiting client discovery", cfg.Provider, cfg.RoomURL)
	return l, nil
}

// handleHello answers a client discovery probe: bind a conn to the session
// tag, answer TMZD_SERVER+tag, and offer the conn to Accept. The tag isolates
// this session from any retried dial on the shared broadcast lane.
func (l *dcListener) handleHello(peerID string, sid []byte) {
	if !l.pinPeer {
		peerID = ""
	}
	key := string(sid)
	answer := append([]byte(tmzdServer), sid...)
	l.mu.Lock()
	if _, exists := l.conns[key]; exists {
		l.mu.Unlock()
		_ = sendTo(l.tr, peerID, answer) // re-answer a retry
		return
	}
	conn := newDcConn(l.tr, dcAddr("server"), dcAddr(key))
	conn.sid = sid
	conn.peer = peerID
	conn.onClose = func() {
		l.mu.Lock()
		delete(l.conns, key)
		l.mu.Unlock()
	}
	l.conns[key] = conn
	l.mu.Unlock()

	_ = sendTo(l.tr, peerID, answer)
	select {
	case l.accept <- conn:
	case <-l.closeCh:
	}
}

// route delivers an inbound session-tagged message to the matching conn.
func (l *dcListener) route(data []byte) {
	if len(data) < 4 {
		return
	}
	key := string(data[:4])
	l.mu.Lock()
	conn, ok := l.conns[key]
	l.mu.Unlock()
	if ok {
		conn.feed(data)
	}
}

func (l *dcListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accept:
		return conn, nil
	case <-l.closeCh:
		return nil, io.EOF
	}
}

func (l *dcListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.closeCh)
	conns := make([]*dcConn, 0, len(l.conns))
	for _, c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return l.tr.Close()
}

func (l *dcListener) Addr() net.Addr { return l.addr }

// liveConns reports how many accepted conns are still open. A conn that
// closed but has not yet been deleted from the map (its onClose runs
// asynchronously) does not count.
func (l *dcListener) liveConns() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.conns {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if !closed {
			n++
		}
	}
	return n
}

// watchIdle closes the listener once it has served zero live conns for the
// whole idle span — the native counterpart of Server.watchIdle. Without it
// a woken room (native serve) never released: Serve blocks in Accept
// forever, the engine session/PCs/WS leak, and every re-wake stacks another
// room on top.
func (l *dcListener) watchIdle() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	emptySince := time.Now()
	for {
		select {
		case <-l.closeCh:
			return
		case <-t.C:
			if l.liveConns() == 0 {
				if time.Since(emptySince) >= l.idle {
					log.Printf("[native] listen: room idle for %s — releasing", l.idle)
					_ = l.Close()
					return
				}
			} else {
				emptySince = time.Now()
			}
		}
	}
}
