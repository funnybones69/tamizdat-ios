package socksstub

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	tamizdat "github.com/funnybones69/tamizdat"
)

// fakeUpstream is a minimal upstreamClient whose DialContext behaviour the
// test controls.
type fakeUpstream struct {
	err error
}

func (f fakeUpstream) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, f.err
}

func (fakeUpstream) DialUDP(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("no udp")
}
func (fakeUpstream) Close() error                             { return nil }
func (fakeUpstream) ShapeMode() string                        { return "" }
func (fakeUpstream) RealShapeMode() string                    { return "" }
func (fakeUpstream) ActiveRealtimeCount() int                 { return 0 }
func (fakeUpstream) LockedRealtimeCount() int32               { return 0 }
func (fakeUpstream) LiteTransportAlive() int32                { return 0 }
func (fakeUpstream) RTTProbeSnapshot() tamizdat.RTTProbeStats { return tamizdat.RTTProbeStats{} }

// TestCallerTimeoutDoesNotLatchCarrier is the regression for a total outage.
//
// dialWhitelistVKS latched the carrier off for vksNativeFailLatch after ANY
// dial error. The ping prober dials with a 3 s budget while a room dial
// legitimately takes longer, so probe timeouts — which say nothing about the
// carrier — kept the latch set. Outside Main mode there is no fallback, so
// while latched every flow in the app was refused: "нет интернета" on a
// tunnel that was actually up.
func TestCallerTimeoutDoesNotLatchCarrier(t *testing.T) {
	prevMode := CurrentUpstreamMode()
	SetUpstreamMode("vks")
	t.Cleanup(func() { SetUpstreamMode(prevMode) })

	rt.mu.Lock()
	prevClient := rt.vksNativeClient
	rt.mu.Unlock()
	t.Cleanup(func() {
		rt.mu.Lock()
		rt.vksNativeClient = prevClient
		rt.mu.Unlock()
		rt.vksNativeFailUntil.Store(0)
	})

	// A carrier that reports the CALLER's deadline.
	rt.mu.Lock()
	rt.vksNativeClient = fakeUpstream{err: context.DeadlineExceeded}
	rt.mu.Unlock()
	rt.vksNativeFailUntil.Store(0)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()

	if _, err := dialWhitelistVKS(ctx, "example.com:443"); err == nil {
		t.Fatal("expected the dial to fail")
	}
	if until := rt.vksNativeFailUntil.Load(); until != 0 {
		t.Fatalf("a caller-budget failure latched the carrier for %s; it must not latch",
			time.Until(time.Unix(0, until)))
	}

	// A carrier failure proper (no caller deadline) still latches, so a dead
	// room does not make every flow pay a discovery timeout.
	rt.mu.Lock()
	rt.vksNativeClient = fakeUpstream{err: errors.New("no server in room after 30s")}
	rt.mu.Unlock()
	if _, err := dialWhitelistVKS(context.Background(), "example.com:443"); err == nil {
		t.Fatal("expected the dial to fail")
	}
	if rt.vksNativeFailUntil.Load() == 0 {
		t.Fatal("a real carrier failure must still latch")
	}
	if vksNativeFailLatch > 10*time.Second {
		t.Fatalf("latch is %s; with no fallback in whitelist mode it must be short", vksNativeFailLatch)
	}
}
