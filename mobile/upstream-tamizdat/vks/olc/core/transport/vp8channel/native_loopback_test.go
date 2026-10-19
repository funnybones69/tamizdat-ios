package vp8channel

import (
	"bytes"
	"testing"
	"time"
)

// loopRx collects what one side's data callback received.
type loopRx struct{ ch chan []byte }

func (r *loopRx) on(data []byte) { r.ch <- append([]byte(nil), data...) }

func (r *loopRx) onPeer(_ string, data []byte) { r.on(data) }

func (r *loopRx) wait(t *testing.T, want []byte, d time.Duration) bool {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case got := <-r.ch:
			if bytes.Equal(got, want) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// newLoopTransport builds the native server end (server mode, per-peer
// sessions) or the native client end (client mode, ONE data plane bound by
// the first frame addressed to it).
func newLoopTransport(t *testing.T, epoch uint32, rx *loopRx, server bool) *streamTransport {
	t.Helper()
	tr := &streamTransport{
		serverMode:       server,
		autoConfirm:      !server,
		bindingToken:     7,
		localEpoch:       epoch,
		datagram:         make(chan []byte, 4),
		closeCh:          make(chan struct{}),
		writerDone:       make(chan struct{}),
		frameInterval:    5 * time.Millisecond,
		peerRestartGrace: defaultPeerRestartGrace,
		batchSize:        64,
	}
	if server {
		tr.onPeerData = rx.onPeer
	}
	tr.data = newKCPPlane(outboundQueueSize, rx.on)
	tr.control = newKCPPlane(controlOutboundQueueSize, func([]byte) {})
	if _, err := tr.data.start(tr.epochHeader()); err != nil {
		t.Fatalf("start data plane: %v", err)
	}
	if _, err := tr.control.start(tr.controlEpochHeader()); err != nil {
		t.Fatalf("start control plane: %v", err)
	}
	return tr
}

// room fans every published sample out to all other members, like an SFU.
type room struct{ members []*streamTransport }

func (r *room) join(tr *streamTransport) {
	r.members = append(r.members, tr)
	tr.sampleWriter = func(d []byte) bool {
		for _, m := range r.members {
			if m != tr {
				m.handleIncomingFrame(append([]byte(nil), d...))
			}
		}
		return true
	}
	go func() {
		for {
			select {
			case f := <-tr.data.out:
				tr.writeSampleLocked(f.data)
				f.release()
			case <-tr.closeCh:
				return
			}
		}
	}()
}

func closeLoop(trs ...*streamTransport) {
	for _, tr := range trs {
		close(tr.closeCh)
		tr.data.close()
		tr.control.close()
	}
}

// TestNativeKCPPairLoopback is the regression for native// telemost/mts. The client used to run its KCP carrier in SERVER mode (it
// passed OnPeerData): a broadcast plane for sending and a separate per-peer
// session receiving the server — two KCP state machines facing the server's
// one per-peer session, so ACKs landed on the plane that never sent the data
// and the TLS flight stalled. Now the client runs client mode with
// AutoConfirmTargeted and the server answers every client on its own
// per-peer session (SendTo). Two clients share the room to pin isolation.
func TestNativeKCPPairLoopback(t *testing.T) {
	const srvEpoch = 0x0000aaaa
	srvRx := &loopRx{ch: make(chan []byte, 256)}
	srv := newLoopTransport(t, srvEpoch, srvRx, true)
	r := &room{}
	r.join(srv)
	clients := []uint32{0x0000bbbb, 0x0000cccc}
	rxs := make([]*loopRx, len(clients))
	trs := make([]*streamTransport, len(clients))
	for i, e := range clients {
		rxs[i] = &loopRx{ch: make(chan []byte, 256)}
		trs[i] = newLoopTransport(t, e, rxs[i], false)
		r.join(trs[i])
	}
	defer closeLoop(append([]*streamTransport{srv}, trs...)...)

	for i, cli := range trs {
		hello := []byte("TMZD_HELLOtag" + string(rune('A'+i)))
		if err := cli.data.get().send(hello); err != nil {
			t.Fatalf("client %d hello: %v", i, err)
		}
		if !srvRx.wait(t, hello, 3*time.Second) {
			t.Fatalf("server never got client %d hello", i)
		}
		answer := []byte("TMZD_SERVERtag" + string(rune('A'+i)))
		if err := srv.SendTo(formatPeerID(clients[i]), answer); err != nil {
			t.Fatalf("server answer %d: %v", i, err)
		}
		if !rxs[i].wait(t, answer, 3*time.Second) {
			t.Fatalf("client %d never got its answer", i)
		}
		if got := cli.peerEpoch.Load(); got != srvEpoch {
			t.Fatalf("client %d bound to 0x%08x, want server 0x%08x", i, got, srvEpoch)
		}
	}
	for round := range 3 {
		for i, cli := range trs {
			up := bytes.Repeat([]byte{byte(0x20 + 8*i + round)}, 3000)
			if err := cli.data.get().send(up); err != nil {
				t.Fatalf("client %d send: %v", i, err)
			}
			if !srvRx.wait(t, up, 3*time.Second) {
				t.Fatalf("round %d: client %d -> server lost", round, i)
			}
			down := bytes.Repeat([]byte{byte(0x60 + 8*i + round)}, 6000)
			if err := srv.SendTo(formatPeerID(clients[i]), down); err != nil {
				t.Fatalf("server send %d: %v", i, err)
			}
			if !rxs[i].wait(t, down, 3*time.Second) {
				t.Fatalf("round %d: server -> client %d lost", round, i)
			}
		}
	}
}
