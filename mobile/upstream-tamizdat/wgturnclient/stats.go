package wgturnclient

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultStatsRoomCount = MaxRooms
	quotaStormMinErrors   = 8
	quotaStormMinAgeSecs  = 15
	// maxTelemetryWorkers caps the per-worker telemetry arrays (worker IDs are
	// 1-based; runner clamps total workers to 6 rooms × 20).
	maxTelemetryWorkers = 128
)

type Stats struct {
	ActiveConnections int32
	Reconnects        int64
	TotalBytesUp      int64
	TotalBytesDown    int64
	CredsErrors       int64
	userTraffic       userTrafficTracker
	turnAllocations   allocationGenerationTracker
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

	// Per-worker telemetry (diag 345): cumulative bytes by 1-based worker ID
	// and the TURN endpoint address each worker dialed. Lets a field log show
	// which allocations/servers starve instead of one aggregate pot.
	BondWorkerBytesUp   []int64
	BondWorkerBytesDown []int64
	workerEndpoints     [maxTelemetryWorkers]string
	workerEndpointsMu   sync.RWMutex
}

// StatsSnapshot is an atomic view used by physical A/B telemetry.
// Per-room arrays are sized to the configured room count instead of a protocol
// constant, so adding rooms does not silently discard telemetry after room 4.
type StatsSnapshot struct {
	ActiveConnections    int32   `json:"active_connections"`
	Reconnects           int64   `json:"reconnects"`
	TotalBytesUp         int64   `json:"total_bytes_up"`
	TotalBytesDown       int64   `json:"total_bytes_down"`
	CredsErrors       int64   `json:"credential_errors"`
	TURNReallocations int64   `json:"turn_reallocations"`
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
	// WorkerUpBytes[j] / WorkerDownBytes[j] belong to worker ID j+1 (IDs are
	// 1-based; the unused index-0 slot is trimmed from the snapshot).
	WorkerUpBytes     []int64          `json:"worker_up_bytes,omitempty"`
	WorkerDownBytes   []int64          `json:"worker_down_bytes,omitempty"`
	EndpointDownBytes map[string]int64 `json:"endpoint_down_bytes,omitempty"`
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
		BondWorkerBytesUp:        make([]int64, maxTelemetryWorkers),
		BondWorkerBytesDown:      make([]int64, maxTelemetryWorkers),
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
		CredsErrors:       atomic.LoadInt64(&s.CredsErrors),
		TURNReallocations: s.currentTURNReallocations(),
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
	out.WorkerUpBytes, out.WorkerDownBytes = s.workerBytesSnapshot()
	out.EndpointDownBytes = s.endpointDownSnapshot()
	return out
}

// workerBytesSnapshot returns per-worker cumulative byte counters trimmed to
// the highest worker ID that ever carried traffic. Element j = worker ID j+1.
func (s *Stats) workerBytesSnapshot() (up, down []int64) {
	maxWorker := 0
	for i := 1; i < maxTelemetryWorkers; i++ {
		if atomic.LoadInt64(&s.BondWorkerBytesUp[i]) != 0 || atomic.LoadInt64(&s.BondWorkerBytesDown[i]) != 0 {
			maxWorker = i
		}
	}
	if maxWorker == 0 {
		return nil, nil
	}
	up = make([]int64, maxWorker)
	down = make([]int64, maxWorker)
	for i := 1; i <= maxWorker; i++ {
		up[i-1] = atomic.LoadInt64(&s.BondWorkerBytesUp[i])
		down[i-1] = atomic.LoadInt64(&s.BondWorkerBytesDown[i])
	}
	return up, down
}

// endpointDownSnapshot folds per-worker down bytes into per-TURN-server
// totals using the endpoint each worker dialed. A sick TURN server shows up
// here as an address whose aggregate lags the pool.
func (s *Stats) endpointDownSnapshot() map[string]int64 {
	s.workerEndpointsMu.RLock()
	defer s.workerEndpointsMu.RUnlock()
	var out map[string]int64
	for i := 1; i < maxTelemetryWorkers; i++ {
		ep := s.workerEndpoints[i]
		if ep == "" {
			continue
		}
		if out == nil {
			out = make(map[string]int64)
		}
		out[ep] += atomic.LoadInt64(&s.BondWorkerBytesDown[i])
	}
	return out
}

func (s *Stats) recordWorkerUp(workerID, n int) {
	if s == nil || workerID <= 0 || workerID >= maxTelemetryWorkers {
		return
	}
	atomic.AddInt64(&s.BondWorkerBytesUp[workerID], int64(n))
}

func (s *Stats) recordWorkerDown(workerID, n int) {
	if s == nil || workerID <= 0 || workerID >= maxTelemetryWorkers {
		return
	}
	atomic.AddInt64(&s.BondWorkerBytesDown[workerID], int64(n))
}

func (s *Stats) registerWorkerEndpoint(workerID int, addr string) {
	if s == nil || workerID <= 0 || workerID >= maxTelemetryWorkers {
		return
	}
	s.workerEndpointsMu.Lock()
	s.workerEndpoints[workerID] = addr
	s.workerEndpointsMu.Unlock()
}

func (s *Stats) unregisterWorkerEndpoint(workerID int) {
	if s == nil || workerID <= 0 || workerID >= maxTelemetryWorkers {
		return
	}
	s.workerEndpointsMu.Lock()
	s.workerEndpoints[workerID] = ""
	s.workerEndpointsMu.Unlock()
}

// formatEndpointBytes renders the endpoint map with sorted keys so successive
// telemetry lines are diff-stable (Go map iteration order is random).
func formatEndpointBytes(m map[string]int64) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s:%d", k, m[k])
	}
	b.WriteByte('}')
	return b.String()
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

func recordBondRoomDown(stats *Stats, roomID, workerID int, packet []byte) {
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
	stats.recordWorkerDown(workerID, len(frame.Payload))
}

func (s *Stats) RunLoop(shutdown <-chan struct{}) {
	s.RunLoopWithCallback(shutdown, nil)
}

func (s *Stats) RunLoopWithCallback(shutdown <-chan struct{}, onSnapshot func(StatsSnapshot)) {
	ticker := time.NewTicker(workerStatsInterval)
	defer ticker.Stop()

	emit := func() {
		snapshot := s.Snapshot()
		totalMB := float64(snapshot.TotalBytesUp+snapshot.TotalBytesDown) / (1024.0 * 1024.0)
		log.Printf("[СТАТИСТИКА] Активных: %d | Трафик: %.2f МБ | Переаллокаций TURN: %d", snapshot.ActiveConnections, totalMB, snapshot.TURNReallocations)
		if snapshot.BondFramesUp+snapshot.BondFramesDown > 0 {
			log.Printf("[BOND] frames up=%d down=%d bytes_up=%d bytes_down=%d queue_drops=%d shaper_drops=%d reorder_gaps=%d late=%d room_up_packets=%v room_up_bytes=%v room_down_packets=%v room_down_bytes=%v room_drops=%v worker_up=%v worker_down=%v ep_down=%s",
				snapshot.BondFramesUp, snapshot.BondFramesDown, snapshot.BondBytesUp, snapshot.BondBytesDown,
				snapshot.BondQueueDrops, snapshot.BondShaperDrops, snapshot.BondReorderGaps, snapshot.BondReorderLate,
				snapshot.RoomUpPackets, snapshot.RoomUpBytes, snapshot.RoomDownPackets, snapshot.RoomDownBytes, snapshot.RoomDrops,
				snapshot.WorkerUpBytes, snapshot.WorkerDownBytes, formatEndpointBytes(snapshot.EndpointDownBytes))
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
		case now := <-ticker.C:
			if s.shouldEmitPeriodicStatsAt(now) {
				emit()
			}
		}
	}
}
