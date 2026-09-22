package wgturnclient

import (
	"container/heap"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

// WireGuard transport data message layout (wireguard-go device/noise-protocol.go):
//   [0]    type = 4 (1 byte) + 3 reserved
//   [4:8]  receiver index (uint32 LE)
//   [8:16] counter (uint64 LE)
// The server spreads one device's downlink across all its DTLS sessions (each
// a TURN allocation with its own relay path + latency), so WG packets arrive
// out of order. The inner TCP collapses on reordering (dup-ACK / fast
// retransmit). This buffer resequences by the WG transport counter so the
// flow can aggregate multiple allocations' bandwidth instead of collapsing.
const (
	wgTransportDataType  = 4
	wgCounterOffset      = 8
	reorderMaxHold       = 40 * time.Millisecond // bound added latency on gaps
	reorderHeapCap       = 8192
	reorderRekeyJumpBack = 1 << 40 // counter jumping back this far = rekey
)

type reorderPkt struct {
	counter uint64
	data    []byte
}

type pktHeap []reorderPkt

func (h pktHeap) Len() int            { return len(h) }
func (h pktHeap) Less(i, j int) bool  { return h[i].counter < h[j].counter }
func (h pktHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *pktHeap) Push(x any)         { *h = append(*h, x.(reorderPkt)) }
func (h *pktHeap) Pop() any           { old := *h; n := len(old); it := old[n-1]; *h = old[:n-1]; return it }

// wgReorderer resequences downlink WG transport messages by their counter
// before they hit the netstack. In-order packets pass through with zero added
// latency; out-of-order ones are held briefly until the gap fills or a short
// hold budget expires.
type wgReorderer struct {
	out        net.PacketConn
	addrPtr    *atomic.Pointer[net.Addr]
	stats      *Stats
	h          pktHeap
	next       uint64
	started    bool
	lastDeliv  time.Time
	droppedDup atomic.Int64
	reordered  atomic.Int64
}

func newWGReorderer(out net.PacketConn, addrPtr *atomic.Pointer[net.Addr], stats *Stats) *wgReorderer {
	return &wgReorderer{out: out, addrPtr: addrPtr, stats: stats}
}

// handle ingests one decrypted WG packet from a worker session.
func (r *wgReorderer) handle(pkt []byte) {
	if len(pkt) < 16 || pkt[0] != wgTransportDataType {
		r.deliver(pkt) // handshake/keepalive — pass through
		return
	}
	counter := binary.LittleEndian.Uint64(pkt[wgCounterOffset : wgCounterOffset+8])
	if !r.started {
		r.started = true
		r.next = counter
	}
	// Rekey resets the counter to ~0; detect a huge backward jump.
	if counter+reorderRekeyJumpBack < r.next {
		r.flushAll()
		r.next = counter
	}
	switch {
	case counter < r.next:
		r.droppedDup.Add(1) // duplicate / too old
	case counter == r.next:
		r.deliver(pkt)
		r.next++
		r.drain()
	default: // ahead — buffer
		heap.Push(&r.h, reorderPkt{counter: counter, data: pkt})
		r.reordered.Add(1)
		if r.h.Len() > reorderHeapCap {
			r.flushAll()
		}
	}
}

// drain delivers every buffered packet that is now in order.
func (r *wgReorderer) drain() {
	for r.h.Len() > 0 && r.h[0].counter == r.next {
		it := heap.Pop(&r.h).(reorderPkt)
		r.deliver(it.data)
		r.next++
	}
}

// flushGap skips a missing (lost) counter so the buffer never stalls.
func (r *wgReorderer) flushGap() {
	if r.h.Len() == 0 {
		return
	}
	r.next = r.h[0].counter
	r.drain()
}

// flushGapIfStale delivers buffered packets when the expected one is lost and
// the hold budget has elapsed — bounds the added latency.
func (r *wgReorderer) flushGapIfStale() {
	if r.h.Len() == 0 || time.Since(r.lastDeliv) < reorderMaxHold {
		return
	}
	r.flushGap()
}

func (r *wgReorderer) flushAll() {
	for r.h.Len() > 0 {
		it := heap.Pop(&r.h).(reorderPkt)
		r.deliver(it.data)
	}
}

func (r *wgReorderer) deliver(pkt []byte) {
	addrPtr := r.addrPtr.Load()
	if addrPtr == nil {
		return
	}
	if _, err := r.out.WriteTo(pkt, *addrPtr); err == nil {
		atomic.AddInt64(&r.stats.TotalBytesDown, int64(len(pkt)))
	}
	r.lastDeliv = time.Now()
}
