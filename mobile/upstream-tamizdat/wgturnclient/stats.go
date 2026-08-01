package wgturnclient

import (
	"log"
	"sync/atomic"
	"time"
)

const (
	defaultStatsRoomCount = MaxRooms
	quotaStormMinErrors   = 8
	quotaStormMinAgeSecs  = 15
)

type Stats struct {
	ActiveConnections int32
	Reconnects        int64
	TotalBytesUp      int64
	TotalBytesDown    int64
	CredsErrors       int64
	lastAllocOKUnix   int64
	quotaErrStreak    int64
	runnerStartedUnix int64

	BondFramesUp             int64
	BondFramesDown           int64
	BondBytesUp              int64
	BondBytesDown            int64
	BondQueueDrops           int64
	BondShaperDrops          int64
	BondReorderGaps          int64
	BondReorderLate          int64
	BondRoomPackets          []int64
	BondRoomBytes            []int64
	BondRoomDrops            []int64
	BondRoomDownPackets      []int64
	BondRoomDownBytes        []int64
	BondRoomCredentialErrors []int64
	BondRoomSessionErrors    []int64
	BondRoomQuotaErrors      []int64
}

// StatsSnapshot is an atomic view used by physical A/B telemetry.
// Per-room arrays are sized to the configured room count instead of a protocol
// constant, so adding rooms does not silently discard telemetry after room 4.
type StatsSnapshot struct {
	ActiveConnections    int32   `json:"active_connections"`
	Reconnects           int64   `json:"reconnects"`
	TotalBytesUp         int64   `json:"total_bytes_up"`
	TotalBytesDown       int64   `json:"total_bytes_down"`
	CredsErrors          int64   `json:"credential_errors"`
	LastAllocOKUnix      int64   `json:"last_alloc_ok_unix"`
	QuotaErrStreak       int64   `json:"quota_error_streak"`
	QuotaStorm           bool    `json:"quota_storm"`
	BondFramesUp         int64   `json:"bond_frames_up"`
	BondFramesDown       int64   `json:"bond_frames_down"`
	BondBytesUp          int64   `json:"bond_bytes_up"`
	BondBytesDown        int64   `json:"bond_bytes_down"`
	BondQueueDrops       int64   `json:"bond_queue_drops"`
	BondShaperDrops      int64   `json:"bond_shaper_drops"`
	BondReorderGaps      int64   `json:"bond_reorder_gaps_down"`
	BondReorderLate      int64   `json:"bond_reorder_late_down"`
	RoomUpPackets        []int64 `json:"room_up_packets"`
	RoomUpBytes          []int64 `json:"room_up_bytes"`
	RoomDrops            []int64 `json:"room_drops"`
	RoomDownPackets      []int64 `json:"room_down_packets"`
	RoomDownBytes        []int64 `json:"room_down_bytes"`
	RoomCredentialErrors []int64 `json:"room_credential_errors"`
	RoomSessionErrors    []int64 `json:"room_session_errors"`
	RoomQuotaErrors      []int64 `json:"room_quota_errors"`
}

// NewStats accepts an optional configured room count. The variadic form keeps
// existing unit-test and legacy single-room call sites source-compatible.
func NewStats(roomCounts ...int) *Stats {
	rooms := defaultStatsRoomCount
	if len(roomCounts) > 0 {
		rooms = roomCounts[0]
		if rooms < 1 {
			rooms = 1
		}
	}
	return &Stats{
		runnerStartedUnix:        time.Now().Unix(),
		BondRoomPackets:          make([]int64, rooms),
		BondRoomBytes:            make([]int64, rooms),
		BondRoomDrops:            make([]int64, rooms),
		BondRoomDownPackets:      make([]int64, rooms),
		BondRoomDownBytes:        make([]int64, rooms),
		BondRoomCredentialErrors: make([]int64, rooms),
		BondRoomSessionErrors:    make([]int64, rooms),
		BondRoomQuotaErrors:      make([]int64, rooms),
	}
}

func (s *Stats) Snapshot() StatsSnapshot {
	return s.snapshotAtUnix(time.Now().Unix())
}

func (s *Stats) snapshotAtUnix(nowUnix int64) StatsSnapshot {
	rooms := len(s.BondRoomPackets)
	active := atomic.LoadInt32(&s.ActiveConnections)
	lastAllocOKUnix := atomic.LoadInt64(&s.lastAllocOKUnix)
	quotaErrStreak := atomic.LoadInt64(&s.quotaErrStreak)
	out := StatsSnapshot{
		ActiveConnections:    active,
		Reconnects:           atomic.LoadInt64(&s.Reconnects),
		TotalBytesUp:         atomic.LoadInt64(&s.TotalBytesUp),
		TotalBytesDown:       atomic.LoadInt64(&s.TotalBytesDown),
		CredsErrors:          atomic.LoadInt64(&s.CredsErrors),
		LastAllocOKUnix:      lastAllocOKUnix,
		QuotaErrStreak:       quotaErrStreak,
		QuotaStorm:           quotaStormActive(active, quotaErrStreak, lastAllocOKUnix, s.runnerStartedUnix, nowUnix),
		BondFramesUp:         atomic.LoadInt64(&s.BondFramesUp),
		BondFramesDown:       atomic.LoadInt64(&s.BondFramesDown),
		BondBytesUp:          atomic.LoadInt64(&s.BondBytesUp),
		BondBytesDown:        atomic.LoadInt64(&s.BondBytesDown),
		BondQueueDrops:       atomic.LoadInt64(&s.BondQueueDrops),
		BondShaperDrops:      atomic.LoadInt64(&s.BondShaperDrops),
		BondReorderGaps:      atomic.LoadInt64(&s.BondReorderGaps),
		BondReorderLate:      atomic.LoadInt64(&s.BondReorderLate),
		RoomUpPackets:        make([]int64, rooms),
		RoomUpBytes:          make([]int64, rooms),
		RoomDrops:            make([]int64, rooms),
		RoomDownPackets:      make([]int64, rooms),
		RoomDownBytes:        make([]int64, rooms),
		RoomCredentialErrors: make([]int64, rooms),
		RoomSessionErrors:    make([]int64, rooms),
		RoomQuotaErrors:      make([]int64, rooms),
	}
	for i := 0; i < rooms; i++ {
		out.RoomUpPackets[i] = atomic.LoadInt64(&s.BondRoomPackets[i])
		out.RoomUpBytes[i] = atomic.LoadInt64(&s.BondRoomBytes[i])
		out.RoomDrops[i] = atomic.LoadInt64(&s.BondRoomDrops[i])
		out.RoomDownPackets[i] = atomic.LoadInt64(&s.BondRoomDownPackets[i])
		out.RoomDownBytes[i] = atomic.LoadInt64(&s.BondRoomDownBytes[i])
		out.RoomCredentialErrors[i] = atomic.LoadInt64(&s.BondRoomCredentialErrors[i])
		out.RoomSessionErrors[i] = atomic.LoadInt64(&s.BondRoomSessionErrors[i])
		out.RoomQuotaErrors[i] = atomic.LoadInt64(&s.BondRoomQuotaErrors[i])
	}
	return out
}

func quotaStormActive(activeWorkers int32, quotaErrStreak, lastAllocOKUnix, runnerStartedUnix, nowUnix int64) bool {
	if activeWorkers != 0 || quotaErrStreak < quotaStormMinErrors {
		return false
	}
	referenceUnix := lastAllocOKUnix
	if referenceUnix == 0 {
		referenceUnix = runnerStartedUnix
	}
	return referenceUnix > 0 && nowUnix >= referenceUnix && nowUnix-referenceUnix >= quotaStormMinAgeSecs
}

func (s *Stats) recordAllocateError(quota bool) {
	if s != nil && quota {
		atomic.AddInt64(&s.quotaErrStreak, 1)
	}
}

func (s *Stats) recordAllocateOK(now time.Time) {
	if s == nil {
		return
	}
	atomic.StoreInt64(&s.lastAllocOKUnix, now.Unix())
	atomic.StoreInt64(&s.quotaErrStreak, 0)
}

func recordBondRoomDown(stats *Stats, roomID int, packet []byte) {
	if stats == nil || roomID < 0 || roomID >= len(stats.BondRoomDownPackets) {
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
			log.Printf("[BOND] frames up=%d down=%d bytes_up=%d bytes_down=%d queue_drops=%d shaper_drops=%d reorder_gaps=%d late=%d room_up_packets=%v room_up_bytes=%v room_down_packets=%v room_down_bytes=%v room_drops=%v",
				snapshot.BondFramesUp, snapshot.BondFramesDown, snapshot.BondBytesUp, snapshot.BondBytesDown,
				snapshot.BondQueueDrops, snapshot.BondShaperDrops, snapshot.BondReorderGaps, snapshot.BondReorderLate,
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
