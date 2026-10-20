package seichannel

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestVideoAccessUnitRoundTrip(t *testing.T) {
	payloads := [][]byte{
		bytes.Repeat([]byte{0x00}, 64), // worst-case emulation prevention
		append([]byte{0x00, 0x00, 0x01, 0x02, 0x03}, bytes.Repeat([]byte{0xff}, 512)...),
		{0x00, 0x00, 0x03, 0x00, 0x00, 0x03},
		bytes.Repeat([]byte{0x00}, 700), // > 255 payload size encoding
	}
	for _, want := range payloads {
		au := buildVideoAccessUnit(want)
		got := extractVideoPayloads(au)
		if len(got) != 1 {
			t.Fatalf("extracted %d payloads, want 1 (payload %d bytes)", len(got), len(want))
		}
		if !bytes.Equal(got[0], want) {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got[0]), len(want))
		}
	}
}
func TestBuildVideoAccessUnitIntoReusesBuffer(t *testing.T) {
	var scratch []byte
	for i := range 3 {
		scratch = buildVideoAccessUnitInto(scratch[:0], []byte("payload"))
		got := extractVideoPayloads(scratch)
		if len(got) != 1 || string(got[0]) != "payload" {
			t.Fatalf("reused scratch produced bad AU at iteration %d: %v", i, got)
		}
	}
}

func TestExtractVideoPayloadsMalformed(t *testing.T) {
	// Truncated SEI, stray NALs and garbage must not panic or hang.
	for _, au := range [][]byte{
		{0x00, 0x00, 0x00, 0x01, 0x06, 0x05},                   // SEI header, no size/payload
		{0x00, 0x00, 0x00, 0x01, 0x06, 0x05, 0xff, 0xff, 0xff}, // size runs past the buffer
		{0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84},             // bare IDR, no SEI
		{0x00, 0x00, 0x00, 0x01, 0x06, 0x05, 0x10, 0x00},       // SEI shorter than the UUID
		{0x00, 0x00, 0x00, 0x01, 0x06, 0x05, 0x15, bytes.Repeat([]byte{0x41}, 17)[0], 0x80},
	} {
		extractVideoPayloads(au) // must not panic
	}
}

func TestSplitKCPPayloadBatch(t *testing.T) {
	var delivered [][]byte
	splitKCPPayload([]byte{0x01, 0x02}, func(p []byte) { delivered = append(delivered, p) })
	if len(delivered) != 1 || !bytes.Equal(delivered[0], []byte{0x01, 0x02}) {
		t.Fatalf("single packet passthrough broken: %v", delivered)
	}

	delivered = nil
	batch := append([]byte{}, kcpBatchMagic[:]...)
	batch = appendBatchPacket(batch, []byte("one"))
	batch = appendBatchPacket(batch, []byte("two"))
	batch = append(batch, 0x99, 0x99) // trailing garbage: len < 2 → ignored
	splitKCPPayload(batch, func(p []byte) { delivered = append(delivered, p) })
	if len(delivered) != 2 || string(delivered[0]) != "one" || string(delivered[1]) != "two" {
		t.Fatalf("batch unpack broken: %v", delivered)
	}
}

func TestParseEpochHeaderCRC(t *testing.T) {
	hdr := buildEpochHeaderTo(0xdeadbeef, 0x11111111, 0x22222222)
	token, src, dst, ok := parseEpochHeader(hdr[:])
	if !ok || token != 0xdeadbeef || src != 0x11111111 || dst != 0x22222222 {
		t.Fatalf("header round-trip failed: %x %x %x %v", token, src, dst, ok)
	}
	corrupted := append([]byte{}, hdr[:]...)
	corrupted[3] ^= 0xff
	if _, _, _, ok := parseEpochHeader(corrupted); ok {
		t.Fatal("corrupted header must fail the CRC check")
	}
	if _, _, _, ok := parseEpochHeader(hdr[:15]); ok {
		t.Fatal("short header must be rejected")
	}
}

// testFrame builds a wire payload: epoch header plus one body byte.
func testFrame(token, src, dst uint32) []byte {
	hdr := buildEpochHeaderTo(token, src, dst)
	return append(hdr[:], 0x42)
}
func TestHandleIncomingPayloadPeerRelatch(t *testing.T) {
	tr := newTestTransport(t)
	local := tr.localEpoch.Load()
	oldPeer, newPeer := uint32(0x11111111), uint32(0x22222222)

	// First frame from oldPeer latches it.
	tr.handleIncomingPayload(testFrame(tr.bindingToken, oldPeer, 0))
	if tr.peerEpoch.Load() != oldPeer {
		t.Fatalf("peer not latched: %08x", tr.peerEpoch.Load())
	}

	// A foreign broadcast while the latch is live must be dropped and must
	// NOT steal the latch (a second participant in a shared room).
	tr.handleIncomingPayload(testFrame(tr.bindingToken, newPeer, 0))
	if tr.peerEpoch.Load() != oldPeer {
		t.Fatalf("foreign epoch stole the live latch: %08x", tr.peerEpoch.Load())
	}

	// A targeted frame from a different epoch proves the peer restarted:
	// re-latch immediately and restart the KCP plane.
	tr.handleIncomingPayload(testFrame(tr.bindingToken, newPeer, local))
	if tr.peerEpoch.Load() != newPeer {
		t.Fatalf("targeted restart frame not latched: %08x", tr.peerEpoch.Load())
	}

	// A broadcast after the latch has been silent past the grace also
	// re-latches (client churn / server restart with fresh epoch).
	tr.handleIncomingPayload(testFrame(tr.bindingToken, oldPeer, 0))
	if tr.peerEpoch.Load() != newPeer {
		t.Fatalf("live latch was stolen by a broadcast: %08x", tr.peerEpoch.Load())
	}
	tr.lastPeerFrameNano.Store(time.Now().Add(-2 * peerRestartGrace).UnixNano())
	tr.handleIncomingPayload(testFrame(tr.bindingToken, oldPeer, 0))
	if tr.peerEpoch.Load() != oldPeer {
		t.Fatalf("stale latch not re-latched after silence: %08x", tr.peerEpoch.Load())
	}

	// Own loopback and foreign bindings are always ignored.
	tr.handleIncomingPayload(testFrame(tr.bindingToken, local, 0))
	tr.handleIncomingPayload(testFrame(tr.bindingToken+1, 0x33333333, 0))
	if tr.peerEpoch.Load() != oldPeer {
		t.Fatalf("loopback/binding-mismatch changed the latch: %08x", tr.peerEpoch.Load())
	}
}

func TestTargetedClientIgnoresForeignBroadcast(t *testing.T) {
	tr := newTestTransport(t)
	tr.autoConfirmTargeted = true
	local := tr.localEpoch.Load()
	foreign := uint32(0x11111111)
	tr.handleIncomingPayload(testFrame(tr.bindingToken, foreign, 0))
	if got := tr.peerEpoch.Load(); got != 0 {
		t.Fatalf("foreign broadcast latched peer 0x%08x", got)
	}
	tr.handleIncomingPayload(testFrame(tr.bindingToken, foreign, local))
	if got := tr.peerEpoch.Load(); got != foreign {
		t.Fatalf("targeted frame did not latch peer 0x%08x", got)
	}
}

func TestHandleIncomingPayloadRestartsKCPPlaneOnRelatch(t *testing.T) {
	tr := newTestTransport(t)
	oldPeer, newPeer := uint32(0xaaaaaaa), uint32(0xbbbbbbb)
	local := tr.localEpoch.Load()

	tr.handleIncomingPayload(testFrame(tr.bindingToken, oldPeer, 0))
	first := tr.data.get()
	if first == nil {
		t.Fatal("KCP plane not started after latch")
	}

	// Targeted frame from a fresh epoch must replace the KCP runtime: the
	// old one's receive sequence would eat the restarted peer's from-zero
	// packets as stale retransmits ("read welcome timeout").
	tr.handleIncomingPayload(testFrame(tr.bindingToken, newPeer, local))
	second := tr.data.get()
	if second == nil || second == first {
		t.Fatal("KCP plane not replaced on peer restart")
	}

	// The outbound header must address the new peer epoch.
	second.conn.hdrMu.RLock()
	hdr := second.conn.epochHdr
	second.conn.hdrMu.RUnlock()
	gotDst := binary.BigEndian.Uint32(hdr[dstOff:crcOff])
	if gotDst != newPeer {
		t.Fatalf("outbound header addresses %08x, want the new peer %08x", gotDst, newPeer)
	}
}

// newTestTransport builds a streamTransport whose KCP plane runs over the
// in-memory fake conn; no engine or network is involved.
func newTestTransport(t *testing.T) *streamTransport {
	t.Helper()
	tr := &streamTransport{
		bindingToken:  0x1234abcd,
		frameInterval: time.Second / 30,
		batchSize:     2,
	}
	tr.localEpoch.Store(randomEpoch())
	tr.data = newKCPPlane(outboundQueueSize, nil)
	if _, err := tr.data.start(tr.epochHeader()); err != nil {
		t.Fatalf("start KCP plane: %v", err)
	}
	t.Cleanup(tr.data.close)
	return tr
}
