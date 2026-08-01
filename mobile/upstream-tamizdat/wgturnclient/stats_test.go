package wgturnclient

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionReturnCountsValidBondDataBeforeCancelledEnqueue(t *testing.T) {
	stats := NewStats()
	d := &Dispatcher{ReturnCh: make(chan []byte, 1)}
	d.ReturnCh <- []byte("occupied")
	data, err := encodeBondFrame(bondFrame{Type: bondFrameData, Seq: 1, Payload: []byte("received-before-shutdown")})
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := encodeBondFrame(bondFrame{Type: bondFrameData, Flags: 1 << 15, Seq: 2, Payload: []byte("reject")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if enqueueSessionReturn(ctx, d, stats, 2, data, true) {
		t.Fatal("cancelled enqueue unexpectedly succeeded")
	}
	if enqueueSessionReturn(ctx, d, stats, 2, invalid, true) {
		t.Fatal("cancelled invalid enqueue unexpectedly succeeded")
	}
	if enqueueSessionReturn(ctx, d, stats, 2, data, false) {
		t.Fatal("cancelled legacy enqueue unexpectedly succeeded")
	}
	snapshot := stats.Snapshot()
	if snapshot.BondFramesDown != 1 || snapshot.BondBytesDown != int64(len("received-before-shutdown")) || snapshot.RoomDownPackets[2] != 1 || snapshot.RoomDownBytes[2] != int64(len("received-before-shutdown")) {
		t.Fatalf("raw downlink attribution=%+v", snapshot)
	}
	if snapshot.TotalBytesDown != 0 || len(d.ReturnCh) != 1 {
		t.Fatalf("cancelled enqueue delivered bytes=%d queue=%d", snapshot.TotalBytesDown, len(d.ReturnCh))
	}
}

func TestStatsSnapshotIncludesPerRoomDirectionsAndFinalCallback(t *testing.T) {
	stats := NewStats()
	atomic.StoreInt32(&stats.ActiveConnections, 7)
	atomic.StoreInt64(&stats.BondFramesUp, 11)
	atomic.StoreInt64(&stats.BondFramesDown, 13)
	atomic.StoreInt64(&stats.BondRoomBytes[2], 101)
	atomic.StoreInt64(&stats.BondRoomDownBytes[2], 202)
	atomic.StoreInt64(&stats.BondRoomDownPackets[2], 3)
	dataFrame, err := encodeBondFrame(bondFrame{Type: bondFrameData, Flags: bondFlagLatency, Seq: 1, Payload: []byte("room-one")})
	if err != nil {
		t.Fatal(err)
	}
	controlFrame, err := encodeBondFrame(bondFrame{Type: bondFrameKeepalive})
	if err != nil {
		t.Fatal(err)
	}
	unknownFlagsFrame, err := encodeBondFrame(bondFrame{Type: bondFrameData, Flags: 1 << 15, Seq: 2, Payload: []byte("reject")})
	if err != nil {
		t.Fatal(err)
	}
	recordBondRoomDown(stats, 1, dataFrame)
	recordBondRoomDown(stats, 1, controlFrame)
	recordBondRoomDown(stats, 1, unknownFlagsFrame)
	recordBondRoomDown(stats, 1, []byte("invalid"))
	recordBondRoomDown(stats, len(stats.BondRoomDownPackets), dataFrame)

	snapshot := stats.Snapshot()
	if snapshot.ActiveConnections != 7 || snapshot.BondFramesUp != 11 || snapshot.BondFramesDown != 14 || snapshot.BondBytesDown != int64(len("room-one")) {
		t.Fatalf("snapshot counters=%+v", snapshot)
	}
	if snapshot.RoomUpBytes[2] != 101 || snapshot.RoomDownBytes[2] != 202 || snapshot.RoomDownPackets[2] != 3 {
		t.Fatalf("room snapshot=%+v", snapshot)
	}
	if snapshot.RoomDownPackets[1] != 1 || snapshot.RoomDownBytes[1] != int64(len("room-one")) {
		t.Fatalf("directional DATA attribution=%+v", snapshot)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"room_up_bytes", "room_down_bytes", "bond_reorder_gaps_down", "turn_reallocations"} {
		if !strings.Contains(string(encoded), `"`+key+`"`) {
			t.Fatalf("snapshot JSON missing %q: %s", key, encoded)
		}
	}

	shutdown := make(chan struct{})
	close(shutdown)
	callbacks := 0
	stats.RunLoopWithCallback(shutdown, func(final StatsSnapshot) {
		callbacks++
		if final.RoomDownBytes[2] != 202 {
			t.Fatalf("final callback snapshot=%+v", final)
		}
	})
	if callbacks != 1 {
		t.Fatalf("callbacks=%d want=1", callbacks)
	}
}

func TestStatsSupportsRoomsBeyondLegacyFour(t *testing.T) {
	stats := NewStats(7)
	atomic.StoreInt64(&stats.BondRoomBytes[6], 606)
	snapshot := stats.Snapshot()
	if len(snapshot.RoomUpBytes) != 7 || snapshot.RoomUpBytes[6] != 606 {
		t.Fatalf("dynamic room telemetry=%v", snapshot.RoomUpBytes)
	}
}

func TestQuotaStormActive(t *testing.T) {
	const now = int64(1_000)
	tests := []struct {
		name        string
		active      int32
		streak      int64
		lastOK      int64
		runnerStart int64
		want        bool
	}{
		{name: "active worker", active: 1, streak: 8, lastOK: 900, runnerStart: 900},
		{name: "below streak", streak: 7, lastOK: 900, runnerStart: 900},
		{name: "recent allocation", streak: 8, lastOK: 986, runnerStart: 900},
		{name: "last allocation old enough", streak: 8, lastOK: 985, runnerStart: 900, want: true},
		{name: "never allocated runner too young", streak: 8, runnerStart: 986},
		{name: "never allocated runner old enough", streak: 8, runnerStart: 985, want: true},
		{name: "future timestamp", streak: 8, lastOK: 1_001, runnerStart: 900},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := quotaStormActive(tc.active, tc.streak, tc.lastOK, tc.runnerStart, now); got != tc.want {
				t.Fatalf("quotaStormActive()=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestStatsAllocateEventsDriveQuotaStormSnapshot(t *testing.T) {
	stats := NewStats()
	stats.runnerStartedUnix = 100
	for range 8 {
		stats.recordAllocateError(true)
	}
	if got := stats.snapshotAtUnix(114); got.QuotaStorm {
		t.Fatalf("quota storm activated too early: %+v", got)
	}
	if got := stats.snapshotAtUnix(115); !got.QuotaStorm || got.QuotaErrStreak != 8 || got.LastAllocOKUnix != 0 {
		t.Fatalf("quota storm snapshot=%+v", got)
	}

	stats.recordAllocateOK(time.Unix(120, 0))
	got := stats.snapshotAtUnix(200)
	if got.QuotaStorm || got.QuotaErrStreak != 0 || got.LastAllocOKUnix != 120 {
		t.Fatalf("allocate success did not reset storm state: %+v", got)
	}
}
