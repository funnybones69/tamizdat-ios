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
	RoomID int
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

	bondV2             bool
	bondSeq            atomic.Uint64
	bondLatencySeq     atomic.Uint64
	bondSched          *bondScheduler
	bondReorder        *bondReorderBuffer
	bondLatencyReorder *bondReorderBuffer
	bondEvent          EventFunc
	bondRooms          int
	reorderTicker      *time.Ticker
}

func NewDispatcher(ctx context.Context, localConn net.PacketConn, stats *Stats) *Dispatcher {
	return NewDispatcherWithOptions(ctx, localConn, stats, false, 0, nil)
}

func NewDispatcherWithOptions(ctx context.Context, localConn net.PacketConn, stats *Stats, bondV2 bool, rooms int, onEvent EventFunc) *Dispatcher {
	dctx, dcancel := context.WithCancel(ctx)
	d := &Dispatcher{
		localConn: localConn,
		ReturnCh:  make(chan []byte, returnChBuf),
		ctx:       dctx,
		cancel:    dcancel,
		stats:     stats,
		bondV2:    bondV2,
		bondEvent: onEvent,
		bondRooms: rooms,
	}
	if d.stats == nil {
		d.stats = NewStats()
	}
	if bondV2 {
		d.bondSched = newBondScheduler()
		d.bondReorder = newBondReorderBuffer(d.stats)
		d.bondLatencyReorder = newBondReorderBuffer(d.stats)
		d.reorderTicker = time.NewTicker(bondReorderHold / 2)
	}

	d.wg.Add(2)
	go d.readLoop()
	go d.writeLoop()
	return d
}

func (d *Dispatcher) Shutdown() {
	d.cancel()
	// ReadFrom is otherwise allowed to block forever while Runner still owns
	// the socket (defer ordering calls Dispatcher.Shutdown before Close).
	_ = d.localConn.SetReadDeadline(time.Now())
	if d.reorderTicker != nil {
		d.reorderTicker.Stop()
	}
	d.wg.Wait()
}

func (d *Dispatcher) Register(w *WorkerSlot) {
	d.mu.Lock()
	d.workers = append(d.workers, w)
	count := len(d.workers)
	d.mu.Unlock()
	if d.bondV2 {
		log.Printf("[ДИСП] Bond v2 воркер #%d room=%d зарегистрирован (всего: %d)", w.ID, w.RoomID, count)
		return
	}
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
		if d.bondV2 {
			d.dispatchBond(pkt)
			continue
		}
		d.dispatchLegacy(pkt)
	}
}

func (d *Dispatcher) dispatchLegacy(pkt []byte) {
	d.mu.Lock()
	nw := len(d.workers)
	if nw == 0 {
		d.mu.Unlock()
		return
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

func (d *Dispatcher) dispatchBond(payload []byte) {
	flags := uint16(0)
	seq := d.bondSeq.Add(1)
	if len(payload) <= bondSmallPacketMax {
		flags = bondFlagLatency
		seq = d.bondLatencySeq.Add(1)
	}
	frame, err := encodeBondFrame(bondFrame{Type: bondFrameData, Flags: flags, Seq: seq, Payload: payload})
	if err != nil {
		emitEvent(d.bondEvent, "error", "bond encode data error err=%s", sanitizeErrForEvent(err))
		return
	}
	d.mu.Lock()
	if len(d.workers) == 0 {
		d.mu.Unlock()
		return
	}
	w, sent := d.bondSched.chooseAndSend(d.workers, frame, len(payload))
	if sent {
		atomic.AddInt64(&d.stats.BondFramesUp, 1)
		atomic.AddInt64(&d.stats.BondBytesUp, int64(len(payload)))
		if w.RoomID >= 0 && w.RoomID < len(d.stats.BondRoomPackets) {
			atomic.AddInt64(&d.stats.BondRoomPackets[w.RoomID], 1)
			atomic.AddInt64(&d.stats.BondRoomBytes[w.RoomID], int64(len(payload)))
		}
	} else {
		atomic.AddInt64(&d.stats.BondQueueDrops, 1)
		for _, room := range activeRooms(d.workers) {
			if room >= 0 && room < len(d.stats.BondRoomDrops) {
				atomic.AddInt64(&d.stats.BondRoomDrops[room], 1)
			}
		}
	}
	d.mu.Unlock()
}

func (d *Dispatcher) writeLoop() {
	defer d.wg.Done()

	for {
		if !d.bondV2 {
			select {
			case <-d.ctx.Done():
				return
			case pkt := <-d.ReturnCh:
				d.writeWGPacket(pkt)
			}
			continue
		}
		select {
		case <-d.ctx.Done():
			return
		case pkt := <-d.ReturnCh:
			d.handleBondReturn(pkt)
		case <-d.reorderTicker.C:
			for _, payload := range d.bondReorder.flushExpired() {
				d.writeWGPacket(payload)
			}
			for _, payload := range d.bondLatencyReorder.flushExpired() {
				d.writeWGPacket(payload)
			}
		}
	}
}

func (d *Dispatcher) handleBondReturn(pkt []byte) {
	frame, err := decodeBondFrame(pkt)
	if err != nil {
		atomic.AddInt64(&d.stats.BondReorderLate, 1)
		emitEvent(d.bondEvent, "warn", "bond downlink invalid frame err=%s", sanitizeErrForEvent(err))
		return
	}
	if frame.Type == bondFrameKeepalive {
		return
	}
	if frame.Type == bondFrameError {
		emitEvent(d.bondEvent, "error", "bond server error err=%s", sanitizeErrForEvent(stringError(frame.Payload)))
		return
	}
	if frame.Type != bondFrameData {
		emitEvent(d.bondEvent, "warn", "bond downlink unexpected type=%d", frame.Type)
		return
	}
	if frame.Flags & ^bondKnownDataFlags != 0 {
		atomic.AddInt64(&d.stats.BondReorderLate, 1)
		emitEvent(d.bondEvent, "warn", "bond downlink unknown flags=%d", frame.Flags)
		return
	}
	atomic.AddInt64(&d.stats.BondFramesDown, 1)
	atomic.AddInt64(&d.stats.BondBytesDown, int64(len(frame.Payload)))
	reorder := d.bondReorder
	if frame.Flags&bondFlagLatency != 0 {
		reorder = d.bondLatencyReorder
	}
	for _, payload := range reorder.push(frame.Seq, frame.Payload) {
		d.writeWGPacket(payload)
	}
}

func (d *Dispatcher) writeWGPacket(pkt []byte) {
	addrPtr := d.clientAddr.Load()
	if addrPtr == nil {
		return
	}
	addr := *addrPtr
	if _, err := d.localConn.WriteTo(pkt, addr); err != nil {
		return
	}
	atomic.AddInt64(&d.stats.TotalBytesDown, int64(len(pkt)))
}

type stringError []byte

func (e stringError) Error() string { return string(e) }
