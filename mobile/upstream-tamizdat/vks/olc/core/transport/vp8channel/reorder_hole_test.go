package vp8channel

import (
	"testing"
	"time"

	"github.com/pion/rtp"
)

// TestReorderBufferSkipsPermanentHoles replays the sequence Telemost's SFU
// forwarded live for a low-rate track: whole frames dropped WITHOUT
// renumbering, so every gap is permanent. The count bound alone (reorderWindow
// = 256) held delivery until 256 packets piled up behind the first hole —
// ~25 s at ~10 packets/s — which is exactly the native discovery stall. With
// the time bound every packet is delivered within about one packet interval.
func TestReorderBufferSkipsPermanentHoles(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newReorderBuffer()
	b.now = func() time.Time { return clock }

	seqs := []uint16{1, 6, 10, 15, 22, 23, 29, 34, 36, 37, 40, 45}
	var delivered []uint16
	deliver := func(p *rtp.Packet) { delivered = append(delivered, p.SequenceNumber) }

	for _, s := range seqs {
		b.push(&rtp.Packet{Header: rtp.Header{SequenceNumber: s}, Payload: []byte{0}}, deliver)
		clock = clock.Add(100 * time.Millisecond) // ~10 packets/s
	}

	// Everything except the newest packet (still waiting out its hole) must
	// be out, in order, after ~1.1 s — not after 256 packets.
	if len(delivered) < len(seqs)-1 {
		t.Fatalf("delivered %v of %v: the buffer stalled behind a permanent hole", delivered, seqs)
	}
	for i := 1; i < len(delivered); i++ {
		if !seqLess(delivered[i-1], delivered[i]) {
			t.Fatalf("out of order delivery: %v", delivered)
		}
	}
}

// TestReorderBufferStillReorders checks a genuine short reorder (filled well
// inside reorderHoleWait) is still restored instead of skipped.
func TestReorderBufferStillReorders(t *testing.T) {
	clock := time.Unix(0, 0)
	b := newReorderBuffer()
	b.now = func() time.Time { return clock }
	var delivered []uint16
	deliver := func(p *rtp.Packet) { delivered = append(delivered, p.SequenceNumber) }

	for _, s := range []uint16{100, 102, 101, 103} {
		b.push(&rtp.Packet{Header: rtp.Header{SequenceNumber: s}, Payload: []byte{0}}, deliver)
		clock = clock.Add(5 * time.Millisecond)
	}
	want := []uint16{100, 101, 102, 103}
	if len(delivered) != len(want) {
		t.Fatalf("delivered %v, want %v", delivered, want)
	}
	for i := range want {
		if delivered[i] != want[i] {
			t.Fatalf("delivered %v, want %v", delivered, want)
		}
	}
}
