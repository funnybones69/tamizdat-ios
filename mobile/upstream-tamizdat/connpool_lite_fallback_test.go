package tamizdat

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestRealtimeFallsBackToBulkWhenLiteIsFull is the regression for a total
// data-plane outage on the room carriers.
//
// The pool keeps one bulk transport plus (when maxTransports > 1) one lite
// transport for realtime flows. When the lite transport's stream slots were
// exhausted, getLiteTransport returned ErrPoolBackpressure instead of
// degrading — and that error went straight back to the caller. UDP flows are
// classified realtime, so DNS, QUIC and APNs died while TCP kept working, and
// a live log showed it 176 times in a few minutes:
//
//	vks-native udp 17.248.214.70:443 failed: getting transport:
//	tamizdat: pool at MaxTransports cap: cap=2
//
// Running a realtime flow over bulk is the established fallback — strict
// single-H2 and the lite-spawn warm-up window both do it — so a full lite
// transport must degrade, not fail.
func TestRealtimeFallsBackToBulkWhenLiteIsFull(t *testing.T) {
	var created atomic.Int32
	pool := newConnPool(1, time.Minute, 1, 2, 0, -1, false, 0, func(_ context.Context, class TrafficClass) (*h2Transport, error) {
		created.Add(1)
		if class == TrafficRealtime {
			// One slot, so the lite transport fills on first use.
			return &h2Transport{maxStreams: 1}, nil
		}
		return &h2Transport{maxStreams: 8}, nil
	})
	defer pool.close()

	ctx := context.Background()

	// Occupy bulk and lite.
	if _, err := pool.getTransportForClass(ctx, TrafficBulk); err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if _, err := pool.getTransportForClass(ctx, TrafficRealtime); err != nil {
		t.Fatalf("first realtime: %v", err)
	}

	// The lite transport is now full. The next realtime request must still be
	// served — over bulk — instead of failing with the cap error.
	tr, err := pool.getTransportForClass(ctx, TrafficRealtime)
	if err != nil {
		t.Fatalf("realtime at cap returned %v, want a bulk fallback", err)
	}
	if tr == nil {
		t.Fatal("realtime at cap returned a nil transport")
	}
}
