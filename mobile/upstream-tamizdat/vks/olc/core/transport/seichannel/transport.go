// Package seichannel provides a byte transport over H264 SEI messages.
//
// Payloads ride SEI NAL units inside otherwise ordinary H264 access units, so
// an SFU that only inspects the video bitstream forwards them untouched. The
// reliable-delivery layer is KCP (the same machinery the vp8channel transport
// uses): KCP packets are batched into the SEI payload, giving windowed
// delivery instead of the per-fragment ack loop the common sender uses. This
// package owns the H264 provider, the batched writer and the epoch header that
// isolates concurrent sessions.
package seichannel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"

	"github.com/funnybones69/tamizdat/vks/olc/core/logger"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport/common"
)

const (
	defaultFragmentSize   = 900
	defaultAckTimeout     = 3 * time.Second
	defaultFPS            = 30
	defaultBatchSize      = 64
	defaultConnectTimeout = 30 * time.Second
	sampleBuilderMaxLate  = 128

	// peerRestartGrace is how long the latched peer must be silent before a
	// frame from a different epoch is read as the peer returning with a
	// fresh epoch (a server restart re-handshake). The peer emits an access
	// unit every frame tick even with no data, so a few missed beats is a
	// confident "the latched peer is gone and a fresh one took its place".
	peerRestartGrace = 6 * time.Second
	// outboundQueueSize bounds KCP packets waiting for the paced writer.
	outboundQueueSize = 1536
	// inboundQueueSize bounds reassembled KCP datagrams inside kcpConn.
	inboundQueueSize = 4096
	// canSendHighWatermark is the percent of the outbound queue above which
	// CanSend starts refusing, so Send applies backpressure before the queue
	// saturates.
	canSendHighWatermark = 90
	// defaultMaxPayloadSize caps one batched SEI payload.
	defaultMaxPayloadSize = 60 * 1024
)

// ErrTransportClosed is returned once the transport has been closed.
var ErrTransportClosed = errors.New("seichannel: transport closed")

// ErrAckTimeout historically reported the fragment ack loop giving up; the
// KCP plane never returns it, but upper layers still match on the sentinel.
var ErrAckTimeout = errors.New("seichannel: ack timeout")

type streamTransport struct {
	common.Lifecycle

	stream common.VideoSession
	track  *webrtc.TrackLocalStaticSample
	onData func([]byte)

	// onPeerData is the server-mode per-peer callback. serverMode records
	// which side of the link this is: the multi-peer (server) side keeps one
	// session per remote epoch; the single-peer (client) side latches onto
	// exactly one. Routing decisions read this flag instead of re-deriving
	// the mode from a callback being nil.
	onPeerData func(peerID string, data []byte)
	serverMode bool

	data       *kcpPlane
	localEpoch atomic.Uint32
	peerEpoch  atomic.Uint32

	// peerMu serializes latch updates (acceptPeerEpoch) against
	// restartPlane, so a reconnect callback cannot interleave with an
	// inbound frame's check-then-latch sequence. lastPeerFrameNano stamps
	// the wall-clock time of the most recent frame accepted from the
	// latched peer; a different epoch is only re-latched once that silence
	// exceeds peerRestartGrace.
	peerMu            sync.Mutex
	lastPeerFrameNano atomic.Int64

	// sampleWriter, when set, replaces the real track.WriteSample call.
	// Tests inject a writer here to observe the exact byte stream that
	// reaches the track and to run without a pion track. It must consume
	// data before returning. Always invoked under writeMu.
	sampleWriter func([]byte) bool
	writeMu      sync.Mutex
	closeCh         chan struct{}
	writerDone      chan struct{}
	closed          atomic.Bool
	writerUp        atomic.Bool
	peerReady       atomic.Bool
	diagAccepted    atomic.Uint64
	diagRejected    atomic.Uint64
	diagDecodeFails atomic.Uint64
	startWriter     sync.Once

	frameInterval time.Duration
	batchSize     int
	bindingToken  uint32
	shaper        *transport.Shaper

	// peers holds one session per remote epoch in server mode. Each session
	// owns an isolated KCP plane; the shared writer drains its packets
	// multiplexed by the epoch headers. Idle sessions are reclaimed by
	// sweepPeers; without that a client rotating its epoch on every
	// reconnect would strand goroutines and queues for the lifetime of the
	// process, and a hostile room could grow the table without bound.
	peers peerTable
}

// New creates a seichannel transport backed by a provider.
func New(ctx context.Context, cfg transport.Config) (transport.Transport, error) {
	opts, err := optionsFrom(cfg)
	if err != nil {
		return nil, err
	}

	// Payloads ride the video track, so the engine stays in pure-video mode:
	// no data callbacks, otherwise it would gate readiness on a bridge this
	// transport never uses and deliver provider bytes behind our back.
	engineCfg := cfg
	engineCfg.OnData = nil
	engineCfg.OnPeerData = nil

	session, err := engineCfg.OpenEngine(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := common.NewEngineVideoSession(session)
	if err != nil {
		return nil, fmt.Errorf("open video session: %w", err)
	}

	track, err := common.NewVideoTrack(webrtc.RTPCodecCapability{
		MimeType:    webrtc.MimeTypeH264,
		ClockRate:   90000,
		Channels:    0,
		SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
	}, "seichannel")
	if err != nil {
		return nil, fmt.Errorf("build video track: %w", err)
	}

	tr := newStreamTransport(stream, track, cfg, opts)

	if err := stream.AddTrack(track); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("attach local video track: %w", err)
	}
	stream.SetTrackHandler(tr.handleRemoteTrack)

	return tr, nil
}

func newStreamTransport(
	stream common.VideoSession,
	track *webrtc.TrackLocalStaticSample,
	cfg transport.Config,
	opts Options,
) *streamTransport {
	closeCh := make(chan struct{})
	tr := &streamTransport{
		Lifecycle:     common.NewLifecycle(stream),
		stream:        stream,
		track:         track,
		onData:        cfg.OnData,
		onPeerData:    cfg.OnPeerData,
		serverMode:    cfg.OnPeerData != nil,
		closeCh:       closeCh,
		writerDone:    make(chan struct{}),
		frameInterval: time.Second / time.Duration(opts.FPS),
		batchSize:     opts.BatchSize,
		bindingToken:  common.BindingToken(cfg.ChannelID, cfg.RoomURL),
	}
	tr.localEpoch.Store(randomEpoch())
	tr.data = newKCPPlane(outboundQueueSize, tr.onData)
	tr.shaper = transport.NewShaper(cfg.Traffic, tr.Features())

	return tr
}

// epochHeader builds the current outbound frame header for the shared plane:
// our epoch as src and the latched peer epoch (0 = broadcast) as dst. In
// server mode the shared plane serves room-wide traffic only (every
// peer-addressed frame goes through the peer's own plane, which is stamped
// with that peer's epoch at creation), so it always broadcasts - a latched
// dst would send room frames to one client and starve the rest.

func (p *streamTransport) epochHeader() [epochHdrLen]byte {
	if p.serverMode {
		return buildEpochHeaderTo(p.bindingToken, p.localEpoch.Load(), 0)
	}
	return buildEpochHeaderTo(p.bindingToken, p.localEpoch.Load(), p.peerEpoch.Load())
}

// Connect starts the transport connection.
func (p *streamTransport) Connect(ctx context.Context) error {
	connectCtx, cancel := context.WithTimeout(ctx, defaultConnectTimeout)
	defer cancel()

	if err := p.stream.Connect(connectCtx); err != nil {
		return fmt.Errorf("connect stream: %w", err)
	}

	if started, err := p.data.start(p.epochHeader()); err != nil {
		return fmt.Errorf("start kcp: %w", err)
	} else if started {
		logger.Infof("seichannel: KCP started localEpoch=0x%08x", p.localEpoch.Load())
	}

	p.startWriter.Do(func() {
		p.writerUp.Store(true)
		go p.writerLoop()

		// Only the multi-peer (server) side accumulates per-peer sessions,
		// so only that side needs the reaper.
		if p.serverMode {
			go p.sweepPeers()
		}
	})

	return nil
}

// SendTo transmits data to a specific peer identified by its epoch hex
// string, through that peer's own KCP plane (which addresses its frames to
// the peer's epoch). Mirrors the vp8channel peer routing surface so the olc
// server's per-peer smux sessions work identically over both carriers.
func (p *streamTransport) SendTo(peerID string, data []byte) error {
	return p.shaper.Send(func(payload []byte) error {
		return p.sendToPeer(peerID, payload)
	}, data)
}

// sendToPeer resolves peerID and sends through that peer's KCP plane, when
// the peer is known. An unknown peer fails with ErrTransportClosed - the
// same shape vp8channel gives - so the upper layer can drop or retry.
func (p *streamTransport) sendToPeer(peerID string, data []byte) error {
	if p.closed.Load() {
		return ErrTransportClosed
	}
	epoch, err := parsePeerID(peerID)
	if err != nil {
		return fmt.Errorf("seichannel: invalid peerID %q: %w", peerID, err)
	}
	sess := p.peers.get(epoch)
	if sess == nil {
		return ErrTransportClosed
	}
	if err := sess.data.send(data); err != nil {
		if errors.Is(err, ErrKCPMessageTooLarge) {
			return err
		}
		return fmt.Errorf("kcp send: %w", err)
	}
	return nil
}

// SupportsPeerRouting reports whether this transport can address individual
// peers. Only the multi-peer (server) side can: the client side latches a
// single peer.
func (p *streamTransport) SupportsPeerRouting() bool {
	return p.serverMode
}

// Send transmits data through the transport.
func (p *streamTransport) Send(data []byte) error {
	return p.shaper.Send(p.send, data)
}

func (p *streamTransport) send(data []byte) error {
	rt := p.data.get()
	if p.closed.Load() || rt == nil {
		return ErrTransportClosed
	}
	if err := rt.send(data); err != nil {
		if errors.Is(err, ErrKCPMessageTooLarge) {
			return err
		}
		return fmt.Errorf("kcp send: %w", err)
	}
	return nil
}

// Close terminates the transport.
func (p *streamTransport) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.closeCh)
		p.data.close()
		p.peers.closeAll()
		if p.writerUp.Load() {
			<-p.writerDone
		}
		if err := p.stream.Close(); err != nil {
			return fmt.Errorf("close stream: %w", err)
		}
	}
	return nil
}

// SetReconnectCallback registers reconnect handling. The peer latch and the
// KCP state describe a session the reconnect just replaced, so the plane is
// restarted with a fresh epoch before the upper layer runs.
func (p *streamTransport) SetReconnectCallback(cb func()) {
	p.stream.SetReconnectCallback(func() {
		p.restartPlane()
		if cb != nil {
			cb()
		}
	})
}

// PeerResetter is satisfied so the liveness layer can drop peer state without
// rebuilding the provider connection.
var _ transport.PeerResetter = (*streamTransport)(nil)

// ResetPeer forgets the current peer and restarts the KCP state machine so a
// replacement handshake is not parsed behind stale bytes.
func (p *streamTransport) ResetPeer() {
	p.restartPlane()
}

func (p *streamTransport) restartPlane() {
	p.peerMu.Lock()
	defer p.peerMu.Unlock()
	p.peerReady.Store(false)
	p.peerEpoch.Store(0)
	p.lastPeerFrameNano.Store(0)
	p.localEpoch.Store(randomEpoch())
	p.data.restart(p.epochHeader())
	// Per-peer sessions are deliberately kept, exactly like vp8channel: a
	// peer plane's KCP state is keyed by the client's epoch, which a server
	// restart does not change, so the session stays usable; stale planes
	// (whose headers still carry the old local epoch as src) are reclaimed
	// by the idle sweep, and a reconnecting client's frames mint fresh
	// sessions under the new epoch.
}

// CanSend reports whether transport is ready for sending.
func (p *streamTransport) CanSend() bool {
	rt := p.data.get()
	return !p.closed.Load() && rt != nil && p.stream.CanSend() &&
		len(p.data.out) < cap(p.data.out)*canSendHighWatermark/100
}

// Features describes the current seichannel transport semantics.
func (p *streamTransport) Features() transport.Features {
	return p.shaper.Features(transport.Features{
		MaxPayloadSize: defaultMaxPayloadSize,
	})
}

// RelaxedKeepAlive marks the seichannel as SFUSilent: datachannel-based SFUs
// (odin MTS Link) do not loop frames back to a lone peer, so the strict smux
// keepalive (10s/30s) kills a client-less session every ~27s. The relaxed
// window (SmuxConfigLong, 120s) keeps the on-demand server alive while it
// waits for the client to join.
func (p *streamTransport) RelaxedKeepAlive() bool { return true }

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	ticker := time.NewTicker(p.frameInterval)
	defer ticker.Stop()

	var scratch []byte
	var pending *packetBuffer

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			scratch, pending = p.writeTick(scratch, pending)
		}
	}
}

// writeTick emits one video sample: the batched KCP packets when any are
// queued, otherwise a bare decodable access unit that keeps the SFU's decoder
// alive. A batch left over from the previous tick is written first so packets
// are never dropped on the floor.
//
// A failed WriteSample does NOT stop the loop: the track writes fail during
// every transient provider hiccup (PC reconnecting, SFU resetting the
// transport), and the writer dying there strands every later KCP packet in
// the outbound queue while the session looks alive from above - KCP keeps
// retransmitting into a queue nobody drains. Instead the sample (and its
// leftover batch) is retried on the next tick.
func (p *streamTransport) writeTick(scratch []byte, pending *packetBuffer) ([]byte, *packetBuffer) {
	var sample []byte
	if pending != nil {
		sample, pending = p.batchSampleFrom(pending, sample)
	} else {
		select {
		case first := <-p.data.out:
			sample, pending = p.batchSampleFrom(first, sample)
		default:
			// Idle: a valid SPS+PPS+IDR access unit with no SEI.
			scratch = buildVideoAccessUnitInto(scratch[:0], nil)
			p.writeSample(scratch)
			return scratch, nil
		}
	}

	scratch = buildVideoAccessUnitInto(scratch[:0], sample)
	if !p.writeSample(scratch) {
		// Keep the leftover batch for the next tick; the scratch is
		// rebuilt from it, so nothing is lost.
		return scratch, pending
	}
	return scratch, pending
}

// writeSample serializes every WriteSample call on the shared video track
// behind a single mutex: pion's TrackLocalStaticSample.WriteSample is not
// safe for concurrent use, and interleaved RTP sequence numbers make the
// receiver's sample builder discard frames. sampleWriter, when set, replaces
// the real track write - tests inject a writer here to observe the exact
// byte stream that reaches the track. It must consume data before
// returning, matching TrackLocalStaticSample.WriteSample. Always invoked
// under writeMu.
func (p *streamTransport) writeSample(data []byte) bool {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	if p.sampleWriter != nil {
		return p.sampleWriter(data)
	}
	if err := p.track.WriteSample(media.Sample{Data: data, Duration: p.frameInterval}); err != nil {
		return false
	}
	return true
}

// batchSampleFrom coalesces up to batchSize KCP packets from the shared
// plane's queue into one SEI payload, bounded by defaultMaxPayloadSize. A
// leftover buffer is returned so the next tick writes it instead of
// dropping it.
func (p *streamTransport) batchSampleFrom(first *packetBuffer, sample []byte) ([]byte, *packetBuffer) {
	return p.batchSampleFromQueue(p.data.out, first, sample)
}

// batchSampleFromQueue is batchSampleFrom over any outbound queue. The
// per-peer writer pumps drain their own queues through it, so a peer's
// downlink batches exactly like the shared client->server path. Only
// packets from the same queue are batched together: every packet in one
// queue carries the same epoch header (the peer's), so the receiver's
// header check applies to the whole batch.
func (p *streamTransport) batchSampleFromQueue(
	src <-chan *packetBuffer,
	first *packetBuffer,
	sample []byte,
) ([]byte, *packetBuffer) {
	if len(first.data) <= epochHdrLen || p.batchSize <= 1 {
		out := append(sample, first.data...)
		first.release()
		return out, nil
	}

	sample = append(sample, first.data[:epochHdrLen]...)
	sample = append(sample, kcpBatchMagic[:]...)
	sample = appendBatchPacket(sample, first.data[epochHdrLen:])
	first.release()

	for packets := 1; packets < p.batchSize; packets++ {
		select {
		case frame, ok := <-src:
			if !ok {
				return sample, nil
			}
			if len(frame.data) <= epochHdrLen {
				frame.release()
				continue
			}
			payload := frame.data[epochHdrLen:]
			if len(sample)+2+len(payload) > defaultMaxPayloadSize {
				return sample, frame
			}
			sample = appendBatchPacket(sample, payload)
			frame.release()
		default:
			return sample, nil
		}
	}
	return sample, nil
}

func appendBatchPacket(dst, packet []byte) []byte {
	if len(packet) > 0xffff {
		return dst
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packet))) //nolint:gosec // bounded above
	dst = append(dst, lenBuf[:]...)
	return append(dst, packet...)
}

func (p *streamTransport) handleRemoteTrack(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
	go func() {
		sb := samplebuilder.New(sampleBuilderMaxLate, &codecs.H264Packet{}, track.Codec().ClockRate)

		popSamples := func() {
			for sample := sb.Pop(); sample != nil; sample = sb.Pop() {
				p.handleSample(sample.Data)
			}
		}

		for {
			packet, _, err := track.ReadRTP()
			if err != nil {
				sb.Flush()
				popSamples()
				return
			}

			sb.Push(packet)
			popSamples()
		}
	}()
}

func (p *streamTransport) handleSample(sample []byte) {
	// The track reader flushes the sample builder when the track ends, which
	// is exactly what Close causes: without this the application receives
	// data after Close has already returned.
	if p.closed.Load() {
		return
	}
	for _, payload := range extractVideoPayloads(sample) {
		p.handleIncomingPayload(payload)
	}
}

// handleIncomingPayload parses the epoch header, filters frames that are not
// ours, latches the peer epoch for replies and delivers the KCP packets.
func (p *streamTransport) handleIncomingPayload(payload []byte) {
	frameToken, src, dst, ok := parseEpochHeader(payload)
	if !ok {
		if n := p.diagDecodeFails.Add(1); n <= 5 {
			logger.Infof("seichannel: header parse failed (%d) payload=%d bytes", n, len(payload))
		}
		return
	}
	if frameToken != p.bindingToken {
		if n := p.diagRejected.Add(1); n <= 5 {
			logger.Infof("seichannel: binding mismatch: got=%08x want=%08x", frameToken, p.bindingToken)
		}
		return
	}
	if src == p.localEpoch.Load() {
		return // own loopback
	}
	if dst != 0 && dst != p.localEpoch.Load() {
		return // addressed to another participant
	}

	if p.serverMode {
		// Server mode: every sender epoch is its own client. Route the
		// KCP payload to that peer's plane - created on demand - and
		// never mix packets from different epochs into one KCP state
		// machine (their sequence spaces are unrelated). The dst filter
		// above already dropped frames addressed to other participants.
		p.handlePeerFrame(src, payload[epochHdrLen:])
		return
	}

	if !p.acceptPeerEpoch(src, dst) {
		return
	}
	p.peerReady.Store(true)
	if n := p.diagAccepted.Add(1); n <= 10 {
		logger.Infof("seichannel: frame accepted: src=%08x dst=%08x payload=%d", src, dst, len(payload))
	}

	rt := p.data.get()
	if rt == nil {
		return
	}
	splitKCPPayload(payload[epochHdrLen:], rt.deliver)
}

// acceptPeerEpoch updates the peer latch for a frame from epoch src and
// reports whether its payload should be delivered.
//
// A returning peer carries a fresh epoch and a fresh KCP state machine whose
// sequence numbering starts from zero; the old plane's receive sequence has
// already advanced past it, so every packet the restarted peer sends is
// silently discarded as a stale retransmit and the replacement handshake
// never completes - the "read welcome timeout" after a server restart. The
// KCP plane therefore has to be replaced together with the latch.
//
// A frame addressed to our epoch proves the sender knows this session, so it
// re-latches immediately. A broadcast from a different epoch is only trusted
// once the latched peer has been silent past peerRestartGrace, so an
// unrelated participant sharing the room cannot steal the session while our
// peer is live.
func (p *streamTransport) acceptPeerEpoch(src, dst uint32) bool {
	p.peerMu.Lock()
	defer p.peerMu.Unlock()

	prev := p.peerEpoch.Load()
	switch {
	case prev == src:
		// Already latched; refresh the liveness stamp below.
	case prev == 0:
		p.latchPeerLocked(src)
	default:
		targeted := dst == p.localEpoch.Load()
		last := p.lastPeerFrameNano.Load()
		silent := last == 0 || time.Since(time.Unix(0, last)) >= peerRestartGrace
		if !targeted && !silent {
			if n := p.diagRejected.Add(1); n <= 5 {
				logger.Infof("seichannel: foreign epoch %08x while peer %08x is live - dropped",
					src, prev)
			}
			return false
		}
		logger.Infof("seichannel: peer restart detected old=0x%08x new=0x%08x - restarting KCP plane",
			prev, src)
		p.relatchPeerLocked(src)
	}
	p.lastPeerFrameNano.Store(time.Now().UnixNano())
	return true
}

func (p *streamTransport) latchPeerLocked(src uint32) {
	p.peerEpoch.Store(src)
	if rt := p.data.get(); rt != nil {
		rt.setHeader(p.epochHeader())
	}
	logger.Infof("seichannel: peer latched epoch=0x%08x", src)
}

// relatchPeerLocked installs src as the peer with a fresh KCP state machine,
// dropping the old plane's queues and sequence state so the returning peer's
// from-zero packets are not read as stale retransmits.
func (p *streamTransport) relatchPeerLocked(src uint32) {
	p.peerReady.Store(false)
	p.peerEpoch.Store(0)
	p.data.restart(p.epochHeader())
	p.peerEpoch.Store(src)
	if rt := p.data.get(); rt != nil {
		rt.setHeader(p.epochHeader())
	}
}
