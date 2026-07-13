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

	BondFramesUp        int64
	BondFramesDown      int64
	BondBytesUp         int64
	BondBytesDown       int64
	BondQueueDrops      int64
	BondReorderGaps     int64
	BondReorderLate     int64
	BondRoomPackets     [maxRooms]int64
	BondRoomBytes       [maxRooms]int64
	BondRoomDrops       [maxRooms]int64
	BondRoomDownPackets [maxRooms]int64
	BondRoomDownBytes   [maxRooms]int64
}

// StatsSnapshot is an atomic, gomobile-safe view used by physical A/B telemetry.
type StatsSnapshot struct {
	ActiveConnections int32           `json:"active_connections"`
	Reconnects        int64           `json:"reconnects"`
	TotalBytesUp      int64           `json:"total_bytes_up"`
	TotalBytesDown    int64           `json:"total_bytes_down"`
	CredsErrors       int64           `json:"credential_errors"`
	BondFramesUp      int64           `json:"bond_frames_up"`
	BondFramesDown    int64           `json:"bond_frames_down"`
	BondBytesUp       int64           `json:"bond_bytes_up"`
	BondBytesDown     int64           `json:"bond_bytes_down"`
	BondQueueDrops    int64           `json:"bond_queue_drops"`
	BondReorderGaps   int64           `json:"bond_reorder_gaps_down"`
	BondReorderLate   int64           `json:"bond_reorder_late_down"`
	RoomUpPackets     [maxRooms]int64 `json:"room_up_packets"`
	RoomUpBytes       [maxRooms]int64 `json:"room_up_bytes"`
	RoomDrops         [maxRooms]int64 `json:"room_drops"`
	RoomDownPackets   [maxRooms]int64 `json:"room_down_packets"`
	RoomDownBytes     [maxRooms]int64 `json:"room_down_bytes"`
}

func NewStats() *Stats {
	return &Stats{}
}

func (s *Stats) Snapshot() StatsSnapshot {
	out := StatsSnapshot{
		ActiveConnections: atomic.LoadInt32(&s.ActiveConnections),
		Reconnects:        atomic.LoadInt64(&s.Reconnects),
		TotalBytesUp:      atomic.LoadInt64(&s.TotalBytesUp),
		TotalBytesDown:    atomic.LoadInt64(&s.TotalBytesDown),
		CredsErrors:       atomic.LoadInt64(&s.CredsErrors),
		BondFramesUp:      atomic.LoadInt64(&s.BondFramesUp),
		BondFramesDown:    atomic.LoadInt64(&s.BondFramesDown),
		BondBytesUp:       atomic.LoadInt64(&s.BondBytesUp),
		BondBytesDown:     atomic.LoadInt64(&s.BondBytesDown),
		BondQueueDrops:    atomic.LoadInt64(&s.BondQueueDrops),
		BondReorderGaps:   atomic.LoadInt64(&s.BondReorderGaps),
		BondReorderLate:   atomic.LoadInt64(&s.BondReorderLate),
	}
	for i := 0; i < maxRooms; i++ {
		out.RoomUpPackets[i] = atomic.LoadInt64(&s.BondRoomPackets[i])
		out.RoomUpBytes[i] = atomic.LoadInt64(&s.BondRoomBytes[i])
		out.RoomDrops[i] = atomic.LoadInt64(&s.BondRoomDrops[i])
		out.RoomDownPackets[i] = atomic.LoadInt64(&s.BondRoomDownPackets[i])
		out.RoomDownBytes[i] = atomic.LoadInt64(&s.BondRoomDownBytes[i])
	}
	return out
}

func recordBondRoomDown(stats *Stats, roomID int, packet []byte) {
	if stats == nil || roomID < 0 || roomID >= maxRooms {
		return
	}
	frame, err := decodeBondFrame(packet)
	if err != nil || frame.Type != bondFrameData || frame.Flags&^bondKnownDataFlags != 0 {
		return
	}
	// Count wire-valid transport DATA at the worker boundary immediately after
	// DTLS read. This raw attribution intentionally includes a frame that cannot
	// enqueue because shutdown wins; TotalBytesDown counts only local WG writes.
	atomic.AddInt64(&stats.BondFramesDown, 1)
	atomic.AddInt64(&stats.BondBytesDown, int64(len(frame.Payload)))
	atomic.AddInt64(&stats.BondRoomDownPackets[roomID], 1)
	atomic.AddInt64(&stats.BondRoomDownBytes[roomID], int64(len(frame.Payload)))
}

func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	s.RunLoopWithCallback(shutdown, nil)
}

func (s *Stats) RunLoopWithCallback(shutdown <-chan struct{}, onSnapshot func(StatsSnapshot)) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	emit := func() {
		snapshot := s.Snapshot()
		totalMB := float64(snapshot.TotalBytesUp+snapshot.TotalBytesDown) / (1024.0 * 1024.0)
		log.Printf("[СТАТИСТИКА] Активных: %d | Трафик: %.2f МБ", snapshot.ActiveConnections, totalMB)
		if snapshot.BondFramesUp+snapshot.BondFramesDown > 0 {
			log.Printf("[BOND] frames up=%d down=%d bytes_up=%d bytes_down=%d queue_drops=%d reorder_gaps=%d late=%d room_up_packets=%v room_up_bytes=%v room_down_packets=%v room_down_bytes=%v room_drops=%v",
				snapshot.BondFramesUp, snapshot.BondFramesDown, snapshot.BondBytesUp, snapshot.BondBytesDown,
				snapshot.BondQueueDrops, snapshot.BondReorderGaps, snapshot.BondReorderLate,
				snapshot.RoomUpPackets, snapshot.RoomUpBytes, snapshot.RoomDownPackets, snapshot.RoomDownBytes, snapshot.RoomDrops)
		}
		if onSnapshot != nil {
			onSnapshot(snapshot)
		}
	}

	for {
		select {
		case <-shutdown:
			emit()
			return
		case <-ticker.C:
			emit()
		}
	}
}
