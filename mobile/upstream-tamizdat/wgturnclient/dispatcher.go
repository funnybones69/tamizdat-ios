package wgturnclient

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const returnChBuf = 384

type WorkerSlot struct {
	ID     int
	SendCh chan []byte
}

type Dispatcher struct {
	localConn  net.PacketConn
	clientAddr atomic.Pointer[net.Addr]
	mu         sync.Mutex
	workers    []*WorkerSlot
	rrIndex    int
	ReturnCh   chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	stats      *Stats
}

func NewDispatcher(ctx context.Context, localConn net.PacketConn, stats *Stats) *Dispatcher {
	dctx, dcancel := context.WithCancel(ctx)
	d := &Dispatcher{
		localConn: localConn,
		ReturnCh:  make(chan []byte, returnChBuf),
		ctx:       dctx,
		cancel:    dcancel,
		stats:     stats,
	}

	d.wg.Add(2)
	go d.readLoop()
	go d.writeLoop()
	return d
}

func (d *Dispatcher) Shutdown() {
	d.cancel()
	d.wg.Wait()
}

func (d *Dispatcher) Register(w *WorkerSlot) {
	d.mu.Lock()
	d.workers = append(d.workers, w)
	count := len(d.workers)
	d.mu.Unlock()
	log.Printf("[ДИСП] Воркер #%d зарегистрирован (всего: %d)", w.ID, count)
}

func (d *Dispatcher) Unregister(slot *WorkerSlot) {
	d.mu.Lock()
	for i, w := range d.workers {
		if w == slot {
			d.workers = append(d.workers[:i], d.workers[i+1:]...)
			break
		}
	}
	remaining := len(d.workers)
	d.mu.Unlock()
	log.Printf("[ДИСП] Воркер #%d отключён (осталось: %d)", slot.ID, remaining)
}

func (d *Dispatcher) readLoop() {
	defer d.wg.Done()

	buf := make([]byte, readBufSize)
	for {
		if err := d.ctx.Err(); err != nil {
			return
		}

		n, addr, err := d.localConn.ReadFrom(buf)
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		d.clientAddr.Store(&addr)
		atomic.AddInt64(&d.stats.TotalBytesUp, int64(n))

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		d.mu.Lock()
		nw := len(d.workers)
		if nw == 0 {
			d.mu.Unlock()
			continue
		}

		sent := false
		startIdx := d.rrIndex % nw
		for i := 0; i < nw; i++ {
			idx := (startIdx + i) % nw
			w := d.workers[idx]
			select {
			case w.SendCh <- pkt:
				d.rrIndex = (idx + 1) % nw
				sent = true
			default:
			}
			if sent {
				break
			}
		}
		if !sent {
			d.rrIndex = (startIdx + 1) % nw
		}
		d.mu.Unlock()
	}
}

func (d *Dispatcher) writeLoop() {
	defer d.wg.Done()

	// The server spreads downlink across all worker sessions (each a TURN
	// allocation with its own latency), so WG packets arrive out of order.
	// The reorderer resequences by the WG transport counter — without it the
	// inner TCP collapses on dup-ACKs and the per-allocation bandwidth can't
	// aggregate.
	re := newWGReorderer(d.localConn, &d.clientAddr, d.stats)
	gapTick := time.NewTicker(10 * time.Millisecond)
	defer gapTick.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case pkt := <-d.ReturnCh:
			re.handle(pkt)
		case <-gapTick.C:
			re.flushGapIfStale()
		}
	}
}
