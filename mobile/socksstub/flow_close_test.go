package socksstub

import (
	"net"
	"sync"
	"testing"
)

// trackingConn records Close so the test can prove a flow was torn down.
type trackingConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func newTrackingConn() *trackingConn {
	return &trackingConn{closed: make(chan struct{})}
}

func (c *trackingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// TestCloseAllFlowsDropsParkedHandlers is the regression for extension
// memory growth across reconnects.
//
// A SOCKS handler parks in a bidirectional copy with no read deadline once
// its handshake is done, so a flow whose upstream stops answering never
// returns and never deregisters. Those handlers are real memory and they
// outlive the carrier that stranded them: a live log showed 151 of them at
// once and iOS killed the extension for it. Closing every registered flow
// when the carrier is replaced or stopped is what bounds that.
func TestCloseAllFlowsDropsParkedHandlers(t *testing.T) {
	flowRegistry.Range(func(k, _ any) bool { flowRegistry.Delete(k); return true })

	a, b := newTrackingConn(), newTrackingConn()
	flowRegistry.Store(uint64(9001), &flowState{conn: a})
	flowRegistry.Store(uint64(9002), &flowState{conn: b})

	if n := closeAllFlows("test"); n != 2 {
		t.Fatalf("closed %d flows, want 2", n)
	}
	for i, c := range []*trackingConn{a, b} {
		select {
		case <-c.closed:
		default:
			t.Fatalf("flow %d was not closed", i)
		}
	}
}
