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

	data       *kcpPlane
	localEpoch atomic.Uint32
	peerEpoch  atomic.Uint32

	writeMu         sync.Mutex
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

// epochHeader builds the current outbound frame header: our epoch as src and
// the latched peer epoch (0 = broadcast) as dst.
func (p *streamTransport) epochHeader() [epochHdrLen]byte {
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
	})

	return nil
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
	p.peerReady.Store(false)
	p.peerEpoch.Store(0)
	p.localEpoch.Store(randomEpoch())
	p.data.restart(p.epochHeader())
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
			var ok bool
			scratch, pending, ok = p.writeTick(scratch, pending)
			if !ok {
				return
			}
		}
	}
}

// writeTick emits one video sample: the batched KCP packets when any are
// queued, otherwise a bare decodable access unit that keeps the SFU's decoder
// alive. A batch left over from the previous tick is written first so packets
// are never dropped on the floor.
func (p *streamTransport) writeTick(scratch []byte, pending *packetBuffer) ([]byte, *packetBuffer, bool) {
	var sample []byte
	if pending != nil {
		sample, pending = p.batchSampleFrom(nil, pending, sample)
	} else {
		select {
		case first := <-p.data.out:
			sample, pending = p.batchSampleFrom(nil, first, sample)
		default:
			// Idle: a valid SPS+PPS+IDR access unit with no SEI.
			scratch = buildVideoAccessUnitInto(scratch[:0], nil)
			if !p.writeSample(scratch) {
				return scratch, nil, false
			}
			return scratch, nil, true
		}
	}

	scratch = buildVideoAccessUnitInto(scratch[:0], sample)
	if !p.writeSample(scratch) {
		if pending != nil {
			pending.release()
		}
		return scratch, nil, false
	}
	return scratch, pending, true
}

// writeSample serializes every WriteSample call on the shared video track
// behind a single mutex: pion's TrackLocalStaticSample.WriteSample is not safe
// for concurrent use, and interleaved RTP sequence numbers make the receiver's
// sample builder discard frames.
func (p *streamTransport) writeSample(data []byte) bool {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.track.WriteSample(media.Sample{Data: data, Duration: p.frameInterval}); err != nil {
		return false
	}
	return true
}

// batchSampleFrom coalesces up to batchSize KCP packets into one SEI payload,
// bounded by defaultMaxPayloadSize. A leftover buffer is returned so the next
// tick writes it instead of dropping it.
func (p *streamTransport) batchSampleFrom(_ []byte, first *packetBuffer, sample []byte) ([]byte, *packetBuffer) {
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
		case frame, ok := <-p.data.out:
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

	if p.peerEpoch.Load() != src {
		p.peerEpoch.Store(src)
		if rt := p.data.get(); rt != nil {
			rt.setHeader(p.epochHeader())
		}
		if !p.peerReady.Load() {
			logger.Infof("seichannel: peer latched epoch=0x%08x", src)
		}
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
