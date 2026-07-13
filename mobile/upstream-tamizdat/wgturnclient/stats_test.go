package wgturnclient

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

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
	recordBondRoomDown(stats, maxRooms, dataFrame)

	snapshot := stats.Snapshot()
	if snapshot.ActiveConnections != 7 || snapshot.BondFramesUp != 11 || snapshot.BondFramesDown != 13 {
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
	for _, key := range []string{"room_up_bytes", "room_down_bytes", "bond_reorder_gaps_down"} {
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
