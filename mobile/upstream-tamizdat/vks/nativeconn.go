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
	"time"

	"github.com/funnybones69/tamizdat/vks/olc/core/app/session"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport/datachannel"
)

const (
	// dcMaxMessage caps one datachannel payload; TLS records up to 16KB are
	// chunked across messages and reassemble in order on the receive side.
	dcMaxMessage = 12 * 1024

	// Discovery magics: client → room, server → client peer.
	tmzdHello  = "TMZD_HELLO"
	tmzdServer = "TMZD_SERVER"
)

// dcConn is a net.Conn over a VKS room datachannel, peer-keyed to one remote.
// Every message carries a 4-byte session tag so concurrent dial retries on the
// shared broadcast lane never interleave (each session reads only its own tag).
type dcConn struct {
	tr   transport.Transport
	mu   sync.Mutex
	peer string // latched remote peerID; "" = broadcast (pre-discovery)
	sid  []byte // 4-byte session tag (client-generated; echoed both directions)
	rbuf []byte
	notify chan struct{}
	closed       bool
	readDeadline  time.Time
	writeDeadline time.Time
	local  net.Addr
	remote net.Addr
	onClose func()
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
	for off := 0; off < len(p); off += dcMaxMessage {
		end := off + dcMaxMessage
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

// NativeDial joins the room, discovers the server peer (TMZD_HELLO →
// TMZD_SERVER), and returns a net.Conn ready for the native TLS+masq
// handshake. Used as Client.config.Dialer. When the wake beacon is
// configured it first asks the on-demand server for a room (the server
// creates/assigns one and answers in-band) and dials THAT room.
func NativeDial(ctx context.Context, cfg ClientConfig) (net.Conn, error) {
	// On-demand: beacon the provider, dial the server-assigned room.
	if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
		if spec, err := SendWakeProvider(ctx, cfg.WakeDNSServer, cfg.WakeZone, cfg.KeyHex, cfg.Provider); err == nil {
			if p, r, ok := splitProviderRoom(spec); ok {
				cfg.Provider, cfg.RoomURL = p, r
			}
		}
	}
	conn := newDcConn(nil, dcAddr("client"), dcAddr("server"))
	// A random 4-byte session tag isolates this dial's byte stream from any
	// retried dial on the shared broadcast lane (each session reads only its
	// own tag; the server echoes it back so both directions are tagged alike).
	sid := make([]byte, 4)
	if _, err := rand.Read(sid); err != nil {
		return nil, fmt.Errorf("native dial: session id: %w", err)
	}
	conn.sid = sid
	serverPeer := make(chan string, 1)
	session.RegisterDefaults() // registers the provider auth flows (jazz/mts/wb/telemost)

	tr, err := datachannel.New(ctx, transport.Config{
		Provider:      cfg.Provider,
		RoomURL:       cfg.RoomURL,
		ProviderToken: cfg.ProviderToken,
		ChannelID:     cfg.ChannelID,
		Name:          cfg.Name,
		DNSServer:     cfg.DNSServer,
		// Without the olc epoch there is no peer routing — both directions
		// use the broadcast lane (the beacon-assignment model is 1 server +
		// 1 client per room, so broadcast IS point-to-point).
		// Discovery + data share the broadcast lane; the 4-byte session tag
		// isolates this dial's stream from any retried dial's stale bytes.
		OnData: func(data []byte) {
			if len(data) >= 15 && string(data[:11]) == tmzdServer && string(data[11:15]) == string(sid) {
				select {
				case serverPeer <- "broadcast":
				default:
				}
				return
			}
			conn.feed(data)
		},
		OnPeerData: func(peerID string, data []byte) {
			if len(data) >= 15 && string(data[:11]) == tmzdServer && string(data[11:15]) == string(sid) {
				conn.latchPeer(peerID)
				select {
				case serverPeer <- peerID:
				default:
				}
				return
			}
			conn.feed(data)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("native dial: open datachannel: %w", err)
	}
	conn.tr = tr
	log.Printf("[native] dial %s: connecting room %s", cfg.Provider, cfg.RoomURL)
	if err := tr.Connect(ctx); err != nil {
		return nil, fmt.Errorf("native dial: connect: %w", err)
	}
	log.Printf("[native] dial %s: room connected, broadcasting discovery", cfg.Provider)
	// NOTE: no olc epoch WaitForPeer here — the native path discovers the
	// server peer via the TMZD_HELLO/TMZD_SERVER exchange below, not the olc
	// epoch handshake (which this transport no longer runs).

	// Broadcast the discovery probe (magic + session tag) until the server
	// answers (retry while ctx).
	hello := append([]byte(tmzdHello), sid...)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	_ = tr.Send(hello)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case peer := <-serverPeer:
			log.Printf("[native] dial %s: server peer discovered: %s", cfg.Provider, peer)
			return conn, nil
		case <-ticker.C:
			_ = tr.Send(hello)
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
