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
	"sync"
	"sync/atomic"
	"time"

	"github.com/funnybones69/tamizdat/vks/olc/core/app/session"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport/datachannel"
)

const (
	// dcMaxMessage caps one datachannel payload; TLS records up to 16KB are
	// chunked across messages and reassemble in order on the receive side.
	// dcMaxMessage caps ONE datachannel message, tag included. Every message is
	// prefixed with the 4-byte session tag, and the SFU drops anything over
	// 12 KiB, so a full-size payload chunk plus its tag would be 4 bytes too
	// large and the stream would hang with no error and no write failure to
	// trip the dead-session path.
	dcMaxMessage = 12 * 1024
	dcTagLen     = 4

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
	onWriteErr    func()
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
	if c.sid != nil {
		if len(data) < 4 || string(data[:4]) != string(c.sid) {
			c.mu.Unlock()
			return // not our session — drop
		}
		data = data[4:]
	}
	c.rbuf = append(c.rbuf, data...)
	close(c.notify)
	c.notify = make(chan struct{})
	c.mu.Unlock()
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
	chunk := dcMaxMessage - dcTagLen
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
				c.onWriteErr()
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
)

func dcKey(cfg ClientConfig) string {
	return cfg.Provider + "\x00" + cfg.RoomURL + "\x00" + cfg.KeyHex
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

func dcStore(key string, s *dcSession) {
	dcCacheMu.Lock()
	dcCache[key] = s
	dcCacheMu.Unlock()
}

var (
	specCacheMu sync.Mutex
	specCache   = map[string]string{} // provider|keyHex -> beacon-assigned spec
)

// wakeSpecKey identifies an on-demand assignment: the beacon is per provider
// and the assignment is authenticated by the shared key.
func wakeSpecKey(cfg ClientConfig) string {
	return cfg.Provider + "\x00" + cfg.KeyHex
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
// assignment when there is one. On beacon failure it leaves the statically
// configured room in place.
func resolveWakeSpec(ctx context.Context, cfg *ClientConfig, key string) {
	specCacheMu.Lock()
	spec := specCache[key]
	specCacheMu.Unlock()
	if spec == "" {
		s, err := SendWakeProvider(ctx, cfg.WakeDNSServer, cfg.WakeZone, cfg.KeyHex, cfg.Provider, cfg.ShortIDHex)
		if err != nil {
			return
		}
		spec = s
		specCacheMu.Lock()
		specCache[key] = spec
		specCacheMu.Unlock()
	}
	if p, r, ok := splitProviderRoom(spec); ok {
		cfg.Provider, cfg.RoomURL = p, r
	}
}

// acquireDcSession returns the cached room session for cfg, joining at most
// once per key at a time - a burst of SOCKS dials must not start N joins.
func acquireDcSession(ctx context.Context, cfg ClientConfig) (*dcSession, error) {
	key := dcKey(cfg)
	lk := dcJoinLock(key)
	lk.Lock()
	defer lk.Unlock()
	if s := dcCached(key); s != nil {
		return s, nil
	}
	s, err := joinDcSession(ctx, cfg)
	if err != nil {
		return nil, err
	}
	dcStore(key, s)
	return s, nil
}

// joinDcSession performs the one expensive room join for a key. The session
// runs on a context detached from the dial (context.WithoutCancel) so the SFU
// session survives the dial that created it; dcJoinTimeout keeps a hung join
// from blocking later dials on that key forever.
func joinDcSession(ctx context.Context, cfg ClientConfig) (*dcSession, error) {
	session.RegisterDefaults() // registers the provider auth flows (jazz/mts/wb/telemost)
	sessCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dcJoinTimeout)
	defer cancel()

	s := newDcSession(nil)
	tr, err := datachannel.New(sessCtx, transport.Config{
		Provider:      cfg.Provider,
		RoomURL:       cfg.RoomURL,
		ProviderToken: cfg.ProviderToken,
		ChannelID:     cfg.ChannelID,
		Name:          cfg.Name,
		DNSServer:     cfg.DNSServer,
		OnData:        s.onData,
		OnPeerData:    s.onPeerData,
	})
	if err != nil {
		return nil, fmt.Errorf("native: open datachannel: %w", err)
	}
	s.tr = tr
	log.Printf("[native] join %s: connecting room %s", cfg.Provider, cfg.RoomURL)
	if err := tr.Connect(sessCtx); err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("native: connect: %w", err)
	}
	log.Printf("[native] join %s: room %s ready (session cached)", cfg.Provider, cfg.RoomURL)
	return s, nil
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
	// one per dial.
	wakeKey := wakeSpecKey(cfg)
	if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
		resolveWakeSpec(ctx, &cfg, wakeKey)
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
	conn.onWriteErr = sess.markDead
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
	// answers (retry while ctx).
	hello := append([]byte(tmzdHello), sid...)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	_ = sendTo(sess.tr, "", hello)
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			// Only a session that has never served a dial is treated as dead:
			// one dial giving up must not tear down a room other dials are using.
			if !sess.healthy() {
				evictDcSession(cfg, sess)
				if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
					dropWakeSpec(wakeKey)
				}
			}
			return nil, ctx.Err()
		case peer := <-serverPeer:
			sess.everHealthy.Store(true)
			if peer != "broadcast" {
				conn.latchPeer(peer)
			}
			log.Printf("[native] dial %s: server peer discovered: %s", cfg.Provider, peer)
			return conn, nil
		case <-ticker.C:
			_ = sendTo(sess.tr, "", hello)
		}
	}
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
	}
	session.RegisterDefaults() // registers the provider auth flows (jazz/mts/wb/telemost)

	tr, err := datachannel.New(ctx, transport.Config{
		Provider:      cfg.Provider,
		RoomURL:       cfg.RoomURL,
		ProviderToken: cfg.ProviderToken,
		ChannelID:     cfg.ChannelID,
		Name:          cfg.Name,
		DNSServer:     cfg.DNSServer,
		OnData: func(data []byte) {
			// Discovery probe: "TMZD_HELLO" + 4-byte session tag.
			if len(data) >= 14 && string(data[:10]) == tmzdHello {
				l.handleHello(data[10:14])
				return
			}
			// Post-discovery: session-tagged TLS/tunnel bytes — route by tag.
			l.route(data)
		},
		OnPeerData: func(peerID string, data []byte) {
			if len(data) >= 14 && string(data[:10]) == tmzdHello {
				l.handleHello(data[10:14])
				return
			}
			l.route(data)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("native listen: open datachannel: %w", err)
	}
	l.tr = tr
	if err := tr.Connect(ctx); err != nil {
		return nil, fmt.Errorf("native listen: connect: %w", err)
	}
	log.Printf("[native] listen %s: room %s connected, awaiting client discovery", cfg.Provider, cfg.RoomURL)
	return l, nil
}

// handleHello answers a client discovery probe: bind a conn to the session
// tag, answer TMZD_SERVER+tag, and offer the conn to Accept. The tag isolates
// this session from any retried dial on the shared broadcast lane.
func (l *dcListener) handleHello(sid []byte) {
	key := string(sid)
	l.mu.Lock()
	if _, exists := l.conns[key]; exists {
		l.mu.Unlock()
		_ = sendTo(l.tr, "", append([]byte(tmzdServer), sid...)) // re-answer a retry
		return
	}
	conn := newDcConn(l.tr, dcAddr("server"), dcAddr(key))
	conn.sid = sid
	conn.onClose = func() {
		l.mu.Lock()
		delete(l.conns, key)
		l.mu.Unlock()
	}
	l.conns[key] = conn
	l.mu.Unlock()

	_ = sendTo(l.tr, "", append([]byte(tmzdServer), sid...))
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
