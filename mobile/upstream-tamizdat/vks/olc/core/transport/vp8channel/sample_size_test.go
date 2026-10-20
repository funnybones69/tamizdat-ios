package vp8channel

import (
	"testing"

	"github.com/funnybones69/tamizdat/vks/olc/core/transport/common"
	"time"
)

// maxOneSegmentSample is the largest sample that still carries exactly one KCP
// segment: the epoch header, the batch magic, the segment and its CRC.
const maxOneSegmentSample = epochHdrLen + len(kcpBatchMagic) + 2 + kcpMTU + wireCRCLen

// rtpVP8Payload is what pion packs into one RTP packet: 1200 MTU minus the
// 12-byte RTP header and the 4-byte VP8 payload descriptor.
const rtpVP8Payload = 1200 - 12 - 4

// batchOf is the size of a sample batching n full KCP segments.
func batchOf(n int) int {
	return epochHdrLen + len(kcpBatchMagic) + n*(2+kcpMTU+wireCRCLen)
}

// TestSampleFitsFourRTPPackets pins the wire shape Telemost's SFU forwards:
// interframes of up to four RTP packets pass, five or more are dropped whole
// (so a multi-packet TLS flight would silently vanish and the handshake
// never completes).
func TestSampleFitsFourRTPPackets(t *testing.T) {
	if packets := (maxSampleBytes + rtpVP8Payload - 1) / rtpVP8Payload; packets > 4 {
		t.Fatalf("maxSampleBytes=%d packetizes into %d RTP packets, want at most 4", maxSampleBytes, packets)
	}
	if maxSampleBytes < batchOf(4) {
		t.Fatalf("maxSampleBytes=%d cannot hold four %d-byte segments (%d bytes)",
			maxSampleBytes, maxOneSegmentSample, batchOf(4))
	}
	if maxSampleBytes >= batchOf(5) {
		t.Fatalf("maxSampleBytes=%d admits five segments (%d bytes)", maxSampleBytes, batchOf(5))
	}

	p := &streamTransport{
		batchSize:     64,
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

// TestDataSamplesAreInterframes pins the frame tag that lets Telemost's SFU
// forward multi-packet samples: data samples carry the VP8 interframe bit,
// the bare keepalive stays a keyframe so the SFU can resynchronise on it.
func TestDataSamplesAreInterframes(t *testing.T) {
	var got [][]byte
	p := &streamTransport{
		frameInterval: time.Second / 90,
		limiter:       common.NewPublishLimiter(0, publishBurstBytes),
		sampleWriter: func(b []byte) bool {
			got = append(got, append([]byte(nil), b...))
			return true
		},
	}
	hdr := buildEpochHeader(7, 0x11111111)
	keepalive := append([]byte(nil), hdr[:]...)
	data := append(append([]byte(nil), hdr[:]...), make([]byte, 100)...)
	p.writeSampleLocked(keepalive)
	p.writeSampleLocked(data)
	if got[0][0]&0x01 != 0 {
		t.Fatalf("keepalive tagged as interframe (frame tag %#02x)", got[0][0])
	}
	if got[1][0]&0x01 != 1 {
		t.Fatalf("data sample tagged as keyframe (frame tag %#02x)", got[1][0])
	}
	if _, _, _, ok := parseEpochHeader(got[1]); !ok {
		t.Fatal("interframe tag broke the epoch header")
	}
}
