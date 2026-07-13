package wgturnclient

import (
	"log"
	"sync/atomic"
	"time"
)

type Stats struct {
	ActiveConnections int32
	Reconnects        int64
	TotalBytesUp      int64
	TotalBytesDown    int64
	CredsErrors       int64

	BondFramesUp    int64
	BondFramesDown  int64
	BondBytesUp     int64
	BondBytesDown   int64
	BondQueueDrops  int64
	BondReorderGaps int64
	BondReorderLate int64
	BondRoomPackets [maxRooms]int64
	BondRoomBytes   [maxRooms]int64
	BondRoomDrops   [maxRooms]int64
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdown:
			return
		case <-ticker.C:
			active := atomic.LoadInt32(&s.ActiveConnections)
			up := atomic.LoadInt64(&s.TotalBytesUp)
			down := atomic.LoadInt64(&s.TotalBytesDown)
			totalMB := float64(up+down) / (1024.0 * 1024.0)

			log.Printf("[СТАТИСТИКА] Активных: %d | Трафик: %.2f МБ", active, totalMB)
			bondUp := atomic.LoadInt64(&s.BondFramesUp)
			bondDown := atomic.LoadInt64(&s.BondFramesDown)
			if bondUp+bondDown > 0 {
				roomPackets := make([]int64, len(s.BondRoomPackets))
				roomBytes := make([]int64, len(s.BondRoomBytes))
				roomDrops := make([]int64, len(s.BondRoomDrops))
				for i := range roomPackets {
					roomPackets[i] = atomic.LoadInt64(&s.BondRoomPackets[i])
					roomBytes[i] = atomic.LoadInt64(&s.BondRoomBytes[i])
					roomDrops[i] = atomic.LoadInt64(&s.BondRoomDrops[i])
				}
				log.Printf("[BOND] frames up=%d down=%d bytes_up=%d bytes_down=%d queue_drops=%d reorder_gaps=%d late=%d room_packets=%v room_bytes=%v room_drops=%v",
					bondUp, bondDown, atomic.LoadInt64(&s.BondBytesUp), atomic.LoadInt64(&s.BondBytesDown),
					atomic.LoadInt64(&s.BondQueueDrops), atomic.LoadInt64(&s.BondReorderGaps), atomic.LoadInt64(&s.BondReorderLate),
					roomPackets, roomBytes, roomDrops)
			}
		}
	}
}
