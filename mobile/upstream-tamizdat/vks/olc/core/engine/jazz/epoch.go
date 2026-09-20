package jazz

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// Epoch framing isolates tunnel peers in multi-participant Jazz rooms: the
// SFU relays datachannel frames to EVERY participant, so without addressing
// two clients would handshake with each other instead of the server. Ported
// from the jitsi engine's epoch mechanism.
//
// Wire format: magic(4) + senderEpoch(4) + receiverEpoch(4) + body.
//   - receiverEpoch 0 = broadcast (server accepts; client drops when latched)
//   - receiverEpoch != 0 = targeted at that session's local epoch
//   - frames with senderEpoch == own local epoch are self-echoes, dropped

var jazzMagic = [4]byte{'O', 'L', 'J', '1'}

const (
	epochHeaderLen = 8
	maxPeerEpochs  = 256
)

// epochState is the peer-addressing bookkeeping shared by the engine paths.
type epochState struct {
	localEpoch    atomic.Uint32
	peerEpoch     atomic.Uint32 // client-mode latched remote epoch
	peerEpochsMu  sync.Mutex
	peerEpochs    map[string]uint32 // server-mode per-peer epochs
	requireTarget bool
	latched       atomic.Bool
	// lastPeerNano is when the latched peer last sent a frame. Server mode
	// uses it to re-latch after the peer goes silent: a reconnecting client
	// gets a fresh epoch, and without a stale-latch rule the server would
	// keep targeting the dead epoch forever and lock every newcomer out.
	lastPeerNano atomic.Int64
}

// staleLatchGrace is how long the latched peer must be silent before a frame
// from a different epoch is treated as the peer returning with a new epoch.
const staleLatchGrace = 15 * time.Second

func newEpochState(requireTarget bool) *epochState {
	es := &epochState{peerEpochs: map[string]uint32{}, requireTarget: requireTarget}
	es.localEpoch.Store(randomEpoch())
	return es
}

func randomEpoch() uint32 {
	for {
		v := binary.LittleEndian.Uint32([]byte(timeNowBytes()))
		if v != 0 {
			return v
		}
	}
}

func timeNowBytes() []byte {
	var b [4]byte
	t := time.Now().UnixNano()
	binary.LittleEndian.PutUint32(b[:], uint32(t)^uint32(t>>32))
	return b[:]
}

// encodeFrame wraps data with the epoch header. receiver 0 broadcasts; a
// non-zero value targets that remote epoch.
func (es *epochState) encodeFrame(data []byte, receiver uint32) []byte {
	out := make([]byte, len(jazzMagic)+epochHeaderLen+len(data))
	copy(out, jazzMagic[:])
	off := len(jazzMagic)
	binary.BigEndian.PutUint32(out[off:off+4], es.localEpoch.Load())
	binary.BigEndian.PutUint32(out[off+4:off+epochHeaderLen], receiver)
	copy(out[off+epochHeaderLen:], data)
	return out
}

// parseFrame validates the header and returns sender/receiver epochs + body.
func (es *epochState) parseFrame(payload []byte) (sender, receiver uint32, body []byte, ok bool) {
	if len(payload) < len(jazzMagic)+epochHeaderLen {
		return 0, 0, nil, false
	}
	off := len(jazzMagic)
	if payload[off-1] != jazzMagic[3] || payload[0] != jazzMagic[0] {
		return 0, 0, nil, false
	}
	sender = binary.BigEndian.Uint32(payload[off : off+4])
	receiver = binary.BigEndian.Uint32(payload[off+4 : off+epochHeaderLen])
	body = payload[off+epochHeaderLen:]
	if sender == 0 || sender == es.localEpoch.Load() {
		return 0, 0, nil, false
	}
	if receiver != 0 && receiver != es.localEpoch.Load() {
		return 0, 0, nil, false
	}
	return sender, receiver, body, true
}

// accept delivers a filtered body plus the sender epoch. Client mode drops
// broadcasts once latched (so other clients' CLIENT_HELLOs never reach the
// wire layer); server mode learns per-peer sender epochs for targeting.
func (es *epochState) accept(from string, payload []byte) ([]byte, uint32, bool) {
	sender, receiver, body, ok := es.parseFrame(payload)
	if !ok {
		return nil, 0, false
	}
	if es.requireTarget {
		// client: only frames addressed to us pass; broadcast accepted only
		// before latching (the server's handshake response targets us).
		if receiver == 0 && es.latched.Load() {
			return nil, 0, false
		}
		if receiver != 0 {
			es.latched.Store(true)
		}
		if es.peerEpoch.Load() == 0 {
			es.peerEpoch.Store(sender)
		}
	} else {
		// server: latch the first sender (single-peer datachannel flow) and
		// target all replies at it; frames from OTHER senders are dropped so
		// a second joining client cannot corrupt the established session.
		// A sender different from the latch is accepted once the latch has
		// been silent past staleLatchGrace: that is a reconnecting peer with
		// a fresh epoch, and locking it out strands the tunnel on a dead one.
		latched := es.peerEpoch.Load()
		switch {
		case latched == 0:
			es.peerEpoch.Store(sender)
			es.latched.Store(true)
		case sender != latched:
			silentFor := time.Since(time.Unix(0, es.lastPeerNano.Load()))
			if silentFor < staleLatchGrace {
				return nil, 0, false
			}
			es.peerEpoch.Store(sender)
			es.latched.Store(true)
		}
		if from != "" {
			es.peerEpochsMu.Lock()
			if _, known := es.peerEpochs[from]; !known && len(es.peerEpochs) < maxPeerEpochs {
				es.peerEpochs[from] = sender
			} else if known {
				es.peerEpochs[from] = sender
			}
			es.peerEpochsMu.Unlock()
		}
	}
	es.lastPeerNano.Store(time.Now().UnixNano())
	return body, sender, true
}

// targetFor returns the receiver epoch for outbound frames: the latched
// peer (both modes latch the first/only remote) or a known peer's epoch.
func (es *epochState) targetFor(from string) uint32 {
	if es.requireTarget || from == "" {
		return es.peerEpoch.Load()
	}
	es.peerEpochsMu.Lock()
	defer es.peerEpochsMu.Unlock()
	return es.peerEpochs[from]
}

// reset clears latched state for a fresh session.
func (es *epochState) reset() {
	es.peerEpoch.Store(0)
	es.latched.Store(false)
	es.lastPeerNano.Store(0)
	es.peerEpochsMu.Lock()
	es.peerEpochs = map[string]uint32{}
	es.peerEpochsMu.Unlock()
}

func (es *epochState) waitLatched(ctx context.Context) bool {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if es.latched.Load() || es.peerEpoch.Load() != 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
		}
	}
}
