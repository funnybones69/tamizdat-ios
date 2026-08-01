package wgturnclient

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// User traffic keeps the existing worker cadence. After 30 seconds without
	// payload traffic the bond is idle: only keepalives remain, capped at 30s.
	workerKeepaliveActiveInterval = 10 * time.Second
	workerKeepaliveIdleInterval   = 30 * time.Second
	userTrafficIdleAfter          = 30 * time.Second
	workerStatsInterval           = 10 * time.Second

	// TURN sockets are per worker. 24 KiB in each direction is ample for the
	// approximately 64 kbit/s worker ceiling without multiplying kernel buffers.
	workerSocketBufferSize = 24 * 1024
)

type userTrafficTracker struct {
	lastUnixNano atomic.Int64
}

func (t *userTrafficTracker) record(now time.Time) {
	next := now.UnixNano()
	for {
		last := t.lastUnixNano.Load()
		if next <= last || t.lastUnixNano.CompareAndSwap(last, next) {
			return
		}
	}
}

func (t *userTrafficTracker) idleAt(now time.Time) bool {
	last := t.lastUnixNano.Load()
	if last == 0 {
		return true
	}
	elapsed := now.UnixNano() - last
	return elapsed >= int64(userTrafficIdleAfter)
}

func (s *Stats) recordUserTraffic(now time.Time) {
	if s != nil {
		s.userTraffic.record(now)
	}
}

func (s *Stats) userTrafficIdleAt(now time.Time) bool {
	return s == nil || s.userTraffic.idleAt(now)
}

func (s *Stats) workerKeepaliveIntervalAt(now time.Time) time.Duration {
	if s.userTrafficIdleAt(now) {
		return workerKeepaliveIdleInterval
	}
	return workerKeepaliveActiveInterval
}

func (s *Stats) shouldEmitPeriodicStatsAt(now time.Time) bool {
	return !s.userTrafficIdleAt(now)
}

func workerKeepaliveDue(now, last time.Time, interval time.Duration) bool {
	return last.IsZero() || !now.Before(last.Add(interval))
}

type allocationGeneration struct {
	username      string
	workers       map[int]struct{}
	reallocations int64
}

type retiredAllocationGenerations struct {
	usernames [4]string
	next      int
}

func (r *retiredAllocationGenerations) contains(username string) bool {
	for _, retired := range r.usernames {
		if retired == username {
			return true
		}
	}
	return false
}

func (r *retiredAllocationGenerations) add(username string) {
	r.usernames[r.next%len(r.usernames)] = username
	r.next++
}

type allocationGenerationTracker struct {
	mu      sync.Mutex
	rooms   map[int]*allocationGeneration
	retired map[int]*retiredAllocationGenerations
	total   int64
}

// record counts a successful TURN Allocate as a reallocation only when the
// same worker has already allocated with the same room credential username.
// A new username resets that room generation without exposing it to logs.
func (t *allocationGenerationTracker) record(roomID, workerID int, username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rooms == nil {
		t.rooms = make(map[int]*allocationGeneration)
		t.retired = make(map[int]*retiredAllocationGenerations)
	}
	generation := t.rooms[roomID]
	if generation == nil || generation.username != username {
		if generation != nil {
			retired := t.retired[roomID]
			if retired == nil {
				retired = &retiredAllocationGenerations{}
				t.retired[roomID] = retired
			}
			if retired.contains(username) {
				return
			}
			retired.add(generation.username)
			t.total -= generation.reallocations
		}
		generation = &allocationGeneration{
			username: username,
			workers:  make(map[int]struct{}),
		}
		t.rooms[roomID] = generation
	}
	if _, seen := generation.workers[workerID]; !seen {
		generation.workers[workerID] = struct{}{}
		return
	}
	generation.reallocations++
	t.total++
}

func (t *allocationGenerationTracker) snapshot() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

func (s *Stats) recordTURNAllocation(roomID, workerID int, username string) {
	if s != nil {
		s.turnAllocations.record(roomID, workerID, username)
	}
}

func (s *Stats) currentTURNReallocations() int64 {
	if s == nil {
		return 0
	}
	return s.turnAllocations.snapshot()
}
