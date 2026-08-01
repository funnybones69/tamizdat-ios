package wgturnclient

import (
	"testing"
	"time"
)

func TestUserTrafficSwitchesWorkerCadenceAndStatsSilence(t *testing.T) {
	stats := NewStats()
	base := time.Unix(1_000, 0)
	if !stats.userTrafficIdleAt(base) {
		t.Fatal("new bond must be idle before its first payload")
	}
	if got := stats.workerKeepaliveIntervalAt(base); got != workerKeepaliveIdleInterval {
		t.Fatalf("initial keepalive interval=%s want=%s", got, workerKeepaliveIdleInterval)
	}
	if stats.shouldEmitPeriodicStatsAt(base) {
		t.Fatal("idle bond must suppress periodic stats")
	}

	stats.recordUserTraffic(base)
	activeAt := base.Add(userTrafficIdleAfter - time.Nanosecond)
	if stats.userTrafficIdleAt(activeAt) {
		t.Fatal("bond became idle before threshold")
	}
	if got := stats.workerKeepaliveIntervalAt(activeAt); got != workerKeepaliveActiveInterval {
		t.Fatalf("active keepalive interval=%s want=%s", got, workerKeepaliveActiveInterval)
	}
	if !stats.shouldEmitPeriodicStatsAt(activeAt) {
		t.Fatal("active bond suppressed periodic stats")
	}

	idleAt := base.Add(userTrafficIdleAfter)
	if !stats.userTrafficIdleAt(idleAt) {
		t.Fatal("bond did not become idle at threshold")
	}
	if got := stats.workerKeepaliveIntervalAt(idleAt); got != workerKeepaliveIdleInterval {
		t.Fatalf("idle keepalive interval=%s want=%s", got, workerKeepaliveIdleInterval)
	}
}

func TestWorkerKeepaliveDueHonorsActiveAndIdleIntervals(t *testing.T) {
	last := time.Unix(2_000, 0)
	if workerKeepaliveDue(last.Add(workerKeepaliveActiveInterval-time.Nanosecond), last, workerKeepaliveActiveInterval) {
		t.Fatal("active keepalive fired early")
	}
	if !workerKeepaliveDue(last.Add(workerKeepaliveActiveInterval), last, workerKeepaliveActiveInterval) {
		t.Fatal("active keepalive did not fire on time")
	}
	if workerKeepaliveDue(last.Add(workerKeepaliveIdleInterval-time.Nanosecond), last, workerKeepaliveIdleInterval) {
		t.Fatal("idle keepalive fired early")
	}
	if !workerKeepaliveDue(last.Add(workerKeepaliveIdleInterval), last, workerKeepaliveIdleInterval) {
		t.Fatal("idle keepalive did not fire on time")
	}
}

func TestTURNReallocationsResetPerRoomCredentialGeneration(t *testing.T) {
	stats := NewStats(2)
	stats.recordTURNAllocation(0, 1, "generation-a")
	stats.recordTURNAllocation(0, 2, "generation-a")
	if got := stats.currentTURNReallocations(); got != 0 {
		t.Fatalf("initial worker allocations counted as reallocations: %d", got)
	}

	stats.recordTURNAllocation(0, 1, "generation-a")
	stats.recordTURNAllocation(1, 3, "generation-b")
	stats.recordTURNAllocation(1, 3, "generation-b")
	if got := stats.currentTURNReallocations(); got != 2 {
		t.Fatalf("same-generation reallocations=%d want=2", got)
	}

	stats.recordTURNAllocation(0, 1, "generation-c")
	if got := stats.currentTURNReallocations(); got != 1 {
		t.Fatalf("room generation reset changed unrelated room or retained old count: %d", got)
	}
	stats.recordTURNAllocation(0, 1, "generation-a")
	if got := stats.currentTURNReallocations(); got != 1 {
		t.Fatalf("late allocation from retired generation changed count: %d", got)
	}
	stats.recordTURNAllocation(0, 1, "generation-c")
	if got := stats.currentTURNReallocations(); got != 2 {
		t.Fatalf("new-generation reallocation=%d want=2 aggregate", got)
	}
}
