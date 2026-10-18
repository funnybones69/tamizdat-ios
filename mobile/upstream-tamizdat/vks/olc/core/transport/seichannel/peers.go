package seichannel

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/funnybones69/tamizdat/vks/olc/core/logger"
)

// Server-mode peer routing, mirroring the vp8channel design: every remote
// sender epoch (the src field of the epoch header) gets its own KCP plane,
// its own outbound queue and its own writer pump. The single outbound SEI
// video stream is shared - frames for different peers are multiplexed by
// their epoch headers: a frame for peer A carries dst = A's epoch, which
// every other client drops at the dst filter in handleIncomingPayload,
// exactly like vp8channel.

const (
	// peerIdleTTL is how long a per-peer session survives without traffic.
	// A client rotates its epoch on every reconnect, so without eviction each
	// reconnect would strand a KCP session, its reader goroutine, its writer
	// pump and a full outbound queue for the lifetime of the process.
	//
	// It has to comfortably exceed the liveness window upper layers run: a
	// live but momentarily quiet peer must not be collected out from under
	// an in-flight handshake.
	peerIdleTTL = 3 * time.Minute

	// peerSweepInterval is how often idle peers are collected.
	peerSweepInterval = 30 * time.Second

	// maxPeers caps how many remote epochs one transport tracks at once. A
	// hostile or badly broken room could otherwise mint epochs faster than
	// the TTL reclaims them. Beyond the cap the least recently used peer is
	// evicted, so ghost participants cannot grow memory without bound.
	maxPeers = 64
)

// peerSession is everything one remote epoch owns on the server side: its
// KCP session and the queue its downlink frames are pumped from.
type peerSession struct {
	epoch uint32
	data  *kcpRuntime
	out   chan *packetBuffer
	// done stops the writer pump. The queue itself is deliberately never
	// closed: kcp-go keeps a postProcess goroutine draining its transmit
	// queue after UDPSession.Close returns, so it can still be parked in
	// kcpConn.WriteTo's `case c.out <- packet`. Closing out there turns that
	// select case into a ready send on a closed channel, which panics as
	// soon as the scheduler picks it - a coin flip on every teardown.
	done      chan struct{}
	closeOnce sync.Once

	// lastSeen is a UnixNano timestamp refreshed by every inbound frame.
	lastSeen int64
}

// newPeerSession binds a freshly started KCP runtime to its outbound queue.
func newPeerSession(epoch uint32, data *kcpRuntime, out chan *packetBuffer) *peerSession {
	return &peerSession{epoch: epoch, data: data, out: out, done: make(chan struct{})}
}

func (s *peerSession) touch(now time.Time) {
	// Written under peerTable's lock, read under the same lock by sweep.
	s.lastSeen = now.UnixNano()
}

// close releases the KCP session and stops the writer pump. Safe to call
// more than once.
func (s *peerSession) close() {
	s.closeOnce.Do(func() {
		s.data.close()
		close(s.done)
	})
}

// peerTable tracks per-peer sessions with idle eviction. All mutation
// happens under mu; sessions handed out to callers stay valid because
// kcpRuntime and the queue tolerate use after close (writes fail, reads
// return).
//
// The zero value is ready to use: the map is created on first insert, so a
// transport that never sees a peer never allocates one.
type peerTable struct {
	mu       sync.RWMutex
	sessions map[uint32]*peerSession
	closed   bool

	// createMu serializes the get-or-create path in peerSessionFor. Frames
	// for the same brand-new epoch can arrive on different goroutines (each
	// RTP/track reader drives its own handleIncomingPayload loop), so two
	// callers can both miss in get() before either has installed a session
	// via add(). Without serializing the check-then-create sequence, both
	// build an independent KCP runtime for the same epoch; add() just
	// overwrites the map entry with the second one, but peerSessionFor
	// still hands each caller its own (possibly orphaned) session object.
	// That silently splits one peer's reliable byte stream across two
	// unrelated KCP state machines, which reassemble garbage that fails AEAD
	// authentication one layer up in muxconn - see olcrtc#142.
	createMu sync.Mutex
}

// get returns the session for epoch, refreshing its idle timer.
func (t *peerTable) get(epoch uint32) *peerSession {
	t.mu.Lock()
	defer t.mu.Unlock()

	sess := t.sessions[epoch]
	if sess != nil {
		sess.touch(time.Now())
	}

	return sess
}

// add installs a freshly created session, evicting the least recently used
// peer when the table is full. It returns false when the table is already
// closed or a session for this epoch is already installed, in which case
// the caller must release the session it built instead of using it. The
// latter should never happen in practice - peerSessionFor serializes
// creation via createMu - but refusing a silent overwrite here is a cheap
// backstop: without it, a second session for the same epoch would clobber
// the map entry while some other caller keeps using the orphaned first one,
// splitting that peer's KCP stream across two state machines. See
// olcrtc#142.
func (t *peerTable) add(sess *peerSession) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return false
	}

	if _, exists := t.sessions[sess.epoch]; exists {
		return false
	}

	if len(t.sessions) >= maxPeers {
		t.evictOldestLocked()
	}

	if t.sessions == nil {
		t.sessions = make(map[uint32]*peerSession)
	}

	sess.touch(time.Now())
	t.sessions[sess.epoch] = sess

	return true
}

// evictOldestLocked drops the least recently used peer. Callers hold mu.
func (t *peerTable) evictOldestLocked() {
	var (
		oldest *peerSession
		found  bool
	)

	for _, sess := range t.sessions {
		if !found || sess.lastSeen < oldest.lastSeen {
			oldest, found = sess, true
		}
	}

	if !found {
		return
	}

	logger.Infof("seichannel: peer table full, evicting epoch=0x%08x", oldest.epoch)
	delete(t.sessions, oldest.epoch)
	oldest.close()
}

// sweep evicts every session idle for longer than ttl.
func (t *peerTable) sweep(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl).UnixNano()

	t.mu.Lock()

	var stale []*peerSession

	for epoch, sess := range t.sessions {
		if sess.lastSeen < cutoff {
			stale = append(stale, sess)
			delete(t.sessions, epoch)
		}
	}

	t.mu.Unlock()

	for _, sess := range stale {
		logger.Infof("seichannel: peer session idle for %s, releasing epoch=0x%08x", ttl, sess.epoch)
		sess.close()
	}
}

// closeAll releases every session and marks the table closed so no further
// peers are admitted.
func (t *peerTable) closeAll() {
	t.mu.Lock()
	sessions := t.sessions
	t.sessions = nil
	t.closed = true
	t.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}
}

// len reports how many peers are currently tracked.
func (t *peerTable) len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.sessions)
}

func formatPeerID(epoch uint32) string {
	return fmt.Sprintf("%08x", epoch)
}

func parsePeerID(peerID string) (uint32, error) {
	v, err := strconv.ParseUint(peerID, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("parse peer id %q: %w", peerID, err)
	}

	return uint32(v), nil
}

// handlePeerFrame routes incoming KCP data to a per-peer session, creating
// one on demand. Each remote epoch gets its own independent KCP state
// machine so multiple clients can coexist in the same room; a participant
// restarting with a fresh epoch lands on a fresh plane, which is what keeps
// its from-zero sequence numbers out of the old plane's receive window.
func (p *streamTransport) handlePeerFrame(peerEpoch uint32, kcpPayload []byte) {
	// Registering the peer even for an empty payload is what refreshes its
	// idle timer, so a quiet-but-live client is not swept away.
	sess := p.peerSessionFor(peerEpoch)
	if sess == nil || len(kcpPayload) == 0 {
		return
	}

	splitKCPPayload(kcpPayload, sess.data.deliver)
}

// peerSessionFor returns the session for epoch, creating it on demand. It
// returns nil when the KCP session cannot be started or the transport is
// shutting down.
//
// The whole check-then-create sequence is serialized by peers.createMu so
// concurrent first-contact frames for the same new epoch (arriving on
// different reader goroutines) always converge on exactly one session
// instead of racing to install two independent KCP runtimes for it. See
// olcrtc#142.
func (p *streamTransport) peerSessionFor(epoch uint32) *peerSession {
	if sess := p.peers.get(epoch); sess != nil {
		return sess
	}

	p.peers.createMu.Lock()
	defer p.peers.createMu.Unlock()

	if sess := p.peers.get(epoch); sess != nil {
		return sess
	}

	peerID := formatPeerID(epoch)
	out := make(chan *packetBuffer, outboundQueueSize)

	// Address downlink frames to the specific client epoch so other clients
	// drop them at the dst filter instead of ingesting them.
	hdr := buildEpochHeaderTo(p.bindingToken, p.localEpoch.Load(), epoch)

	data, err := startKCP(out, func(payload []byte) {
		if p.onPeerData != nil {
			p.onPeerData(peerID, payload)
		}
	}, hdr)
	if err != nil {
		logger.Warnf("seichannel: startKCP for peer 0x%08x failed: %v", epoch, err)

		return nil
	}

	sess := newPeerSession(epoch, data, out)

	if !p.peers.add(sess) {
		sess.close()

		return nil
	}

	logger.Infof("seichannel: peer session created epoch=0x%08x peers=%d", epoch, p.peers.len())

	// Pump outbound frames from this peer's queue onto the shared track.
	go p.peerWriterPump(out, sess.done)

	return sess
}

// peerWriterPump drains a peer's outbound KCP queue onto the shared video
// track on the same frame ticker writerLoop uses, batching queued packets
// into one SEI payload per tick. Frames for different peers are multiplexed
// by their epoch headers - every packet this pump emits carries the header
// stamped at session creation (dst = that peer's epoch), so the addressed
// client ingests it and every other participant drops it at the dst filter.
// writeSample serializes the actual track writes against writerLoop and the
// other pumps, which is what keeps one peer's RTP sequence numbers
// contiguous on the wire. Stops when the peer session is released or the
// transport shuts down.
func (p *streamTransport) peerWriterPump(out chan *packetBuffer, done <-chan struct{}) {
	ticker := time.NewTicker(p.frameInterval)
	defer ticker.Stop()

	var au []byte
	var payload []byte
	var pending *packetBuffer

	defer func() {
		if pending != nil {
			pending.release()
		}
	}()

	for {
		select {
		case <-p.closeCh:
			return
		case <-done:
			return
		case <-ticker.C:
			frame := pending
			pending = nil
			if frame == nil {
				select {
				case next, ok := <-out:
					if !ok {
						return
					}
					frame = next
				default:
				}
			}
			if frame == nil {
				continue
			}
			// A failed write does not stop the pump (see writeTick): the
			// leftover batch is retried on the next tick, and KCP
			payload, pending = p.batchSampleFromQueue(out, frame, payload[:0])
			au = buildVideoAccessUnitInto(au[:0], payload)
			_ = p.writeSample(au)
		}
	}
}

// sweepPeers evicts idle peer sessions until the transport closes.
func (p *streamTransport) sweepPeers() {
	ticker := time.NewTicker(peerSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			p.peers.sweep(peerIdleTTL)
		}
	}
}
