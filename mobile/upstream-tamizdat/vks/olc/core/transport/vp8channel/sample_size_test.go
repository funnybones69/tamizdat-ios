package vp8channel

import (
	"testing"
	"time"
)

// maxOneSegmentSample is the largest sample that still carries exactly one KCP
// segment: the epoch header, the batch magic, the segment and its CRC.
const maxOneSegmentSample = epochHdrLen + len(kcpBatchMagic) + 2 + kcpMTU + wireCRCLen

// TestSampleNeverExceedsOneRTPPacket pins the wire shape Telemost's SFU
// accepts. The SFU forwards a published frame only when it fits in a single
// RTP packet; a sample that packetizes into two or more is dropped whole, so
// every multi-packet message (a TLS ServerHello, for instance) silently
// vanished and the tunnel could not complete a handshake.
func TestSampleNeverExceedsOneRTPPacket(t *testing.T) {
	if maxSampleBytes < maxOneSegmentSample {
		t.Fatalf("maxSampleBytes=%d cannot hold one %d-byte KCP segment: every "+
			"full segment would be split into a second sample", maxSampleBytes, maxOneSegmentSample)
	}
	// Two segments must NOT fit in one sample: the second would be the second
	// RTP packet.
	twoSegments := epochHdrLen + len(kcpBatchMagic) + 2*(2+kcpMTU+wireCRCLen)
	if maxSampleBytes >= twoSegments {
		t.Fatalf("maxSampleBytes=%d admits two segments (%d bytes)", maxSampleBytes, twoSegments)
	}

	p := &streamTransport{
		batchSize:    64,
		frameInterval: time.Second / 30,
	}
	if got := p.prepareBatchBuffer(nil, nil, make([]byte, maxOneSegmentSample)); cap(got) > maxSampleBytes {
		t.Fatalf("prepareBatchBuffer reserved %d bytes, want at most %d", cap(got), maxSampleBytes)
	}

	// The batcher must stop before adding a payload that would push the sample
	// past the cap, and must emit the first segment as a sample of its own.
	src := make(chan *packetBuffer, 8)
	first := &packetBuffer{data: make([]byte, maxOneSegmentSample)}
	sample, pending := p.batchSampleFrom(src, first, nil)
	if len(sample) > maxSampleBytes {
		t.Fatalf("batched sample is %d bytes, want at most %d", len(sample), maxSampleBytes)
	}
	if pending != nil {
		pending.release()
	}
}
