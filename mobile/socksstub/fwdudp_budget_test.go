package socksstub

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetFwdUDPBudgetForTest(t *testing.T) {
	t.Helper()
	if got := len(fwdUDPGlobalSlots); got != 0 {
		t.Fatalf("global FWD_UDP target budget is dirty before test: %d", got)
	}
	if got := len(fwdUDPGlobalSessionSlots); got != 0 {
		t.Fatalf("global FWD_UDP session budget is dirty before test: %d", got)
	}
	rt = &runtimeState{logsMax: 100}
	fwdUDPBudgetLogAt.Store(0)
	fwdUDPBudgetDrops.Store(0)
	fwdUDPSessionBudgetLogAt.Store(0)
	fwdUDPSessionBudgetDrops.Store(0)
	t.Cleanup(func() {
		for len(fwdUDPGlobalSlots) > 0 {
			releaseFwdUDPGlobalEntry()
		}
		for len(fwdUDPGlobalSessionSlots) > 0 {
			releaseFwdUDPGlobalSession()
		}
	})
}

func waitFwdUDPBudgetLen(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(fwdUDPGlobalSlots) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("global FWD_UDP budget len=%d, want %d", len(fwdUDPGlobalSlots), want)
}

func waitAtomicAtLeast(t *testing.T, value *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if value.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter=%d, want at least %d", value.Load(), want)
}

func waitAtomicUintAtLeast(t *testing.T, value *atomic.Uint64, want uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if value.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter=%d, want at least %d", value.Load(), want)
}

func startFwdUDPTestSession(t *testing.T, idx uint64, dial fwdUDPDialFunc) (net.Conn, <-chan struct{}) {
	t.Helper()
	server, client := net.Pipe()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set pipe deadline: %v", err)
	}
	done := make(chan struct{})
	go func() {
		handleFwdUDPWithDial(context.Background(), server, idx, dial)
		_ = server.Close()
		close(done)
	}()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read FWD_UDP reply: %v", err)
	}
	if reply[0] != socksVersion5 || reply[1] != socksReplySuccess {
		t.Fatalf("FWD_UDP reply=%v", reply)
	}
	return client, done
}

func writeFwdUDPTestFrame(t *testing.T, client net.Conn, port uint16) {
	t.Helper()
	// datlen=1, hdrlen=10, atyp=IPv4, 127.0.0.1:port, one payload byte.
	frame := []byte{0, 1, 10, socksAtypIPv4, 127, 0, 0, 1, 0, 0, 0x42}
	binary.BigEndian.PutUint16(frame[8:10], port)
	if _, err := client.Write(frame); err != nil {
		t.Fatalf("write FWD_UDP frame: %v", err)
	}
}

func closeFwdUDPTestSession(t *testing.T, client net.Conn, done <-chan struct{}) {
	t.Helper()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FWD_UDP session did not stop")
	}
}

type fwdUDPTestPacketConn struct {
	closed chan struct{}
	once   sync.Once
	closes *atomic.Int64
}

func newFwdUDPTestPacketConn(closes *atomic.Int64) *fwdUDPTestPacketConn {
	return &fwdUDPTestPacketConn{closed: make(chan struct{}), closes: closes}
}

func (c *fwdUDPTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, net.ErrClosed
}
func (*fwdUDPTestPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *fwdUDPTestPacketConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		if c.closes != nil {
			c.closes.Add(1)
		}
	})
	return nil
}
func (*fwdUDPTestPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*fwdUDPTestPacketConn) SetDeadline(time.Time) error      { return nil }
func (*fwdUDPTestPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*fwdUDPTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestFwdUDPGlobalEntryBudget(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	for i := 0; i < fwdUDPGlobalMaxEntries; i++ {
		if !tryAcquireFwdUDPGlobalEntry() {
			t.Fatalf("slot %d rejected before cap %d", i, fwdUDPGlobalMaxEntries)
		}
	}
	if tryAcquireFwdUDPGlobalEntry() {
		t.Fatalf("entry above global cap %d was accepted", fwdUDPGlobalMaxEntries)
	}
	for i := 0; i < fwdUDPGlobalMaxEntries; i++ {
		releaseFwdUDPGlobalEntry()
	}
	// Defensive underflow must return immediately rather than deadlock.
	releaseFwdUDPGlobalEntry()
	if got := len(fwdUDPGlobalSlots); got != 0 {
		t.Fatalf("global FWD_UDP budget leaked %d slots", got)
	}
}

func TestFwdUDPGlobalBudgetReleasesOnOuterSessionClose(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	var closes atomic.Int64
	dialed := make(chan struct{}, 1)
	client, done := startFwdUDPTestSession(t, 1, func(context.Context, string) (net.PacketConn, error) {
		dialed <- struct{}{}
		return newFwdUDPTestPacketConn(&closes), nil
	})
	writeFwdUDPTestFrame(t, client, 10001)
	<-dialed
	waitFwdUDPBudgetLen(t, 1)
	closeFwdUDPTestSession(t, client, done)
	waitFwdUDPBudgetLen(t, 0)
	if got := closes.Load(); got != 1 {
		t.Fatalf("closed PacketConns=%d, want 1", got)
	}
}

func TestFwdUDPGlobalBudgetReleasesOnDialError(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	dialed := make(chan struct{}, 1)
	client, done := startFwdUDPTestSession(t, 2, func(context.Context, string) (net.PacketConn, error) {
		dialed <- struct{}{}
		return nil, errors.New("forced dial failure")
	})
	writeFwdUDPTestFrame(t, client, 10002)
	<-dialed
	waitFwdUDPBudgetLen(t, 0)
	closeFwdUDPTestSession(t, client, done)
}

func TestFwdUDPGlobalBudgetReleasesOnIdleSweep(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	oldIdle, oldSweep := fwdUDPIdleTimeout, fwdUDPSweepInterval
	fwdUDPIdleTimeout = 10 * time.Millisecond
	fwdUDPSweepInterval = 2 * time.Millisecond
	defer func() {
		fwdUDPIdleTimeout = oldIdle
		fwdUDPSweepInterval = oldSweep
	}()

	var closes atomic.Int64
	client, done := startFwdUDPTestSession(t, 3, func(context.Context, string) (net.PacketConn, error) {
		return newFwdUDPTestPacketConn(&closes), nil
	})
	writeFwdUDPTestFrame(t, client, 10003)
	waitFwdUDPBudgetLen(t, 1)
	waitAtomicAtLeast(t, &closes, 1)
	waitFwdUDPBudgetLen(t, 0)
	closeFwdUDPTestSession(t, client, done)
}

func TestFwdUDPGlobalBudgetReleasesOnLRUEviction(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	var dials, closes atomic.Int64
	client, done := startFwdUDPTestSession(t, 4, func(context.Context, string) (net.PacketConn, error) {
		dials.Add(1)
		return newFwdUDPTestPacketConn(&closes), nil
	})
	for i := 0; i <= fwdUDPGlobalMaxEntries; i++ {
		writeFwdUDPTestFrame(t, client, uint16(11000+i))
	}
	waitAtomicAtLeast(t, &dials, int64(fwdUDPGlobalMaxEntries+1))
	waitAtomicAtLeast(t, &closes, 1)
	waitFwdUDPBudgetLen(t, fwdUDPGlobalMaxEntries)
	closeFwdUDPTestSession(t, client, done)
	waitFwdUDPBudgetLen(t, 0)
}

func TestFwdUDPGlobalBudgetBoundsConcurrentSessions(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	var dials, closes atomic.Int64
	dial := func(context.Context, string) (net.PacketConn, error) {
		dials.Add(1)
		return newFwdUDPTestPacketConn(&closes), nil
	}

	clients := make([]net.Conn, fwdUDPGlobalMaxEntries)
	dones := make([]<-chan struct{}, len(clients))
	for i := range clients {
		clients[i], dones[i] = startFwdUDPTestSession(t, uint64(100+i), dial)
		writeFwdUDPTestFrame(t, clients[i], uint16(12000+i))
	}
	waitAtomicAtLeast(t, &dials, int64(fwdUDPGlobalMaxEntries))
	waitFwdUDPBudgetLen(t, fwdUDPGlobalMaxEntries)
	// A second target in an already-admitted session must be rejected while the
	// process-wide target budget is full.
	writeFwdUDPTestFrame(t, clients[0], 13000)
	waitAtomicUintAtLeast(t, &fwdUDPBudgetDrops, 1)
	if got := dials.Load(); got != int64(fwdUDPGlobalMaxEntries) {
		t.Fatalf("concurrent dials=%d, want capped at %d", got, fwdUDPGlobalMaxEntries)
	}
	for i := range clients {
		closeFwdUDPTestSession(t, clients[i], dones[i])
	}
	waitFwdUDPBudgetLen(t, 0)
	if got := closes.Load(); got != int64(fwdUDPGlobalMaxEntries) {
		t.Fatalf("closed PacketConns=%d, want %d", got, fwdUDPGlobalMaxEntries)
	}
}

func TestFwdUDPGlobalSessionBudgetRejectsBeforeAllocatingTargetResources(t *testing.T) {
	resetFwdUDPBudgetForTest(t)
	for i := 0; i < fwdUDPGlobalMaxSessions; i++ {
		if !tryAcquireFwdUDPGlobalSession() {
			t.Fatalf("session slot %d rejected before cap %d", i, fwdUDPGlobalMaxSessions)
		}
	}

	server, client := net.Pipe()
	done := make(chan struct{})
	var dials atomic.Int64
	go func() {
		handleFwdUDPWithDial(context.Background(), server, 999, func(context.Context, string) (net.PacketConn, error) {
			dials.Add(1)
			return newFwdUDPTestPacketConn(nil), nil
		})
		_ = server.Close()
		close(done)
	}()
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read rejected FWD_UDP reply: %v", err)
	}
	if reply[0] != socksVersion5 || reply[1] != 0x01 {
		t.Fatalf("rejected FWD_UDP reply=%v, want general failure", reply)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("rejected FWD_UDP session did not stop")
	}
	_ = client.Close()
	if got := dials.Load(); got != 0 {
		t.Fatalf("rejected session allocated %d target resources, want 0", got)
	}
	if got := fwdUDPSessionBudgetDrops.Load(); got != 1 {
		t.Fatalf("session budget drops=%d, want 1", got)
	}
	if got := len(fwdUDPGlobalSessionSlots); got != fwdUDPGlobalMaxSessions {
		t.Fatalf("rejected session leaked slot: active=%d, want %d", got, fwdUDPGlobalMaxSessions)
	}

	for len(fwdUDPGlobalSessionSlots) > 0 {
		releaseFwdUDPGlobalSession()
	}
	acceptedClient, acceptedDone := startFwdUDPTestSession(t, 1000, func(context.Context, string) (net.PacketConn, error) {
		return newFwdUDPTestPacketConn(nil), nil
	})
	if got := len(fwdUDPGlobalSessionSlots); got != 1 {
		t.Fatalf("accepted session slots=%d, want 1", got)
	}
	closeFwdUDPTestSession(t, acceptedClient, acceptedDone)
	if got := len(fwdUDPGlobalSessionSlots); got != 0 {
		t.Fatalf("closed session leaked slot: %d", got)
	}
}
