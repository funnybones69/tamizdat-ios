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

// TestReorderNewHoleGetsItsOwnClock is the regression for a hole inheriting
// the age of the hole that was just filled.
//
// Sequence from the review: 100 and 102 at t=0 (hole at 101), 104 at t=90ms,
// then 101 at t=100ms and 103 at t=105ms. Filling 101 makes 103 the missing
// head, but 103 has only been missing for microseconds. Reusing the old
// hole's 100 ms age skipped straight past 103 and dropped it — even though it
// arrived 5 ms later, well inside the reorder window the buffer exists to
// absorb.
func TestReorderNewHoleGetsItsOwnClock(t *testing.T) {
	now := time.Unix(0, 0)
	b := newReorderBuffer()
	b.now = func() time.Time { return now }

	var got []uint16
	deliver := func(p *rtp.Packet) { got = append(got, p.SequenceNumber) }

	b.push(mkPkt(100), deliver) // t=0
	b.push(mkPkt(102), deliver) // t=0, hole at 101
	if len(got) != 1 {
		t.Fatalf("after 100/102 delivered %v, want just [100]", got)
	}

	now = now.Add(90 * time.Millisecond)
	b.push(mkPkt(104), deliver) // still inside the hole wait
	if len(got) != 1 {
		t.Fatalf("90ms in, delivered %v; 102 must still be held", got)
	}

	now = now.Add(10 * time.Millisecond) // t=100ms: the old hole is now due
	b.push(mkPkt(101), deliver)
	if len(got) != 3 {
		t.Fatalf("after 101 delivered %v, want [100 101 102]", got)
	}

	now = now.Add(5 * time.Millisecond) // t=105ms
	b.push(mkPkt(103), deliver)

	want := []uint16{100, 101, 102, 103, 104}
	if len(got) != len(want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivered %v, want %v", got, want)
		}
	}
}

func mkPkt(seq uint16) *rtp.Packet {
	return &rtp.Packet{Header: rtp.Header{SequenceNumber: seq}, Payload: []byte{0}}
}
