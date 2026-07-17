package socksstub

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var accepted net.Conn
	l.once.Do(func() { accepted = l.conn })
	if accepted != nil {
		return accepted, nil
	}
	return nil, net.ErrClosed
}

func (*singleConnListener) Close() error   { return nil }
func (*singleConnListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestSocksFlowBudgetShrinksWithTURNWorkerPool(t *testing.T) {
	cases := []struct {
		required bool
		workers  int64
		want     int64
	}{
		{required: false, workers: 80, want: socksFlowDefaultLimit},
		{required: true, workers: 20, want: socksFlowOneRoomLimit},
		{required: true, workers: 40, want: socksFlowTwoRoomLimit},
		{required: true, workers: 60, want: socksFlowThreePlusRoomLimit},
		{required: true, workers: 80, want: socksFlowThreePlusRoomLimit},
	}
	for _, tc := range cases {
		if got := socksFlowLimit(tc.required, tc.workers); got != tc.want {
			t.Fatalf("required=%t workers=%d limit=%d, want %d", tc.required, tc.workers, got, tc.want)
		}
	}
}

func TestSocksFlowBudgetConcurrentAdmissionIsBounded(t *testing.T) {
	state := &runtimeState{logsMax: 100}
	const attempts = 512
	var admitted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			if tryAcquireSocksFlow(state, socksFlowThreePlusRoomLimit) {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != socksFlowThreePlusRoomLimit {
		t.Fatalf("admitted=%d, want %d", got, socksFlowThreePlusRoomLimit)
	}
	if got := state.connsActive.Load(); got != socksFlowThreePlusRoomLimit {
		t.Fatalf("active=%d, want %d", got, socksFlowThreePlusRoomLimit)
	}
	for i := int64(0); i < admitted.Load(); i++ {
		releaseSocksFlow(state)
	}
	if got := state.connsActive.Load(); got != 0 {
		t.Fatalf("active after release=%d, want 0", got)
	}
}

func TestAcceptLoopRejectsBeforeHandlerAtFlowBudget(t *testing.T) {
	oldRT := rt
	oldRequired := vkturnRequired.Load()
	oldExpected := vkturnExpectedWorkers.Load()
	oldDrops := socksFlowBudgetDrops.Load()
	oldLogAt := socksFlowBudgetLogAt.Load()
	t.Cleanup(func() {
		rt = oldRT
		vkturnRequired.Store(oldRequired)
		vkturnExpectedWorkers.Store(oldExpected)
		socksFlowBudgetDrops.Store(oldDrops)
		socksFlowBudgetLogAt.Store(oldLogAt)
	})

	state := &runtimeState{logsMax: 100}
	rt = state
	vkturnRequired.Store(true)
	vkturnExpectedWorkers.Store(80)
	limit := currentSocksFlowLimit()
	state.connsActive.Store(limit)
	socksFlowBudgetDrops.Store(0)
	socksFlowBudgetLogAt.Store(0)

	server, client := net.Pipe()
	defer client.Close()
	acceptLoop(state, context.Background(), &singleConnListener{conn: server})

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("over-budget accepted flow stayed open")
	}
	if got := state.connsActive.Load(); got != limit {
		t.Fatalf("active=%d after rejection, want unchanged %d", got, limit)
	}
	if got := state.connsTotal.Load(); got != 0 {
		t.Fatalf("total handlers=%d, want 0", got)
	}
	if got := socksFlowBudgetDrops.Load(); got != 1 {
		t.Fatalf("budget drops=%d, want 1", got)
	}
}

func TestConnectTURNPendingReturnsGeneralFailure(t *testing.T) {
	oldRT := rt
	oldRequired := vkturnRequired.Load()
	oldNet := vkturnNet.Load()
	oldPendingDrops := vkturnPendingDrops.Load()
	oldPendingLogAt := vkturnPendingLogAt.Load()
	t.Cleanup(func() {
		rt = oldRT
		vkturnRequired.Store(oldRequired)
		vkturnNet.Store(oldNet)
		vkturnPendingDrops.Store(oldPendingDrops)
		vkturnPendingLogAt.Store(oldPendingLogAt)
	})

	rt = &runtimeState{logsMax: 100}
	vkturnRequired.Store(true)
	vkturnNet.Store(nil)
	vkturnPendingDrops.Store(0)
	vkturnPendingLogAt.Store(0)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		handleConnect(context.Background(), server, 1, "192.0.2.1:443")
		_ = server.Close()
		close(done)
	}()

	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read pending CONNECT reply: %v", err)
	}
	if reply[0] != socksVersion5 || reply[1] != socksReplyGeneral {
		t.Fatalf("pending CONNECT reply=%v, want SOCKS general failure", reply)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending CONNECT handler did not stop")
	}
	if got := vkturnPendingDrops.Load(); got != 1 {
		t.Fatalf("pending drops=%d, want 1", got)
	}
}
