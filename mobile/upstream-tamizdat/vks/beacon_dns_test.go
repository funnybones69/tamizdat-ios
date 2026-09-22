package vks

import (
	"context"
	"testing"
	"time"
)

func TestBeaconQNameRoundTrip(t *testing.T) {
	name := "abcdef0123456789abcdef01.w.example.com."
	q := buildAQuery(name)
	got, end, ok := decodeQName(q, 12)
	if !ok {
		t.Fatalf("decodeQName failed")
	}
	if got != "abcdef0123456789abcdef01.w.example.com" {
		t.Fatalf("qname = %q", got)
	}
	// question end must leave room for QTYPE+QCLASS
	if end+4 > len(q) {
		t.Fatalf("qend %d beyond len %d", end, len(q))
	}
}

func TestRoomWakeKeyDeterministic(t *testing.T) {
	k := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	a := RoomWakeKey(k, "wbstream", "stab_gw")
	b := RoomWakeKey(k, "wbstream", "stab_gw")
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	if len(a) != 24 {
		t.Fatalf("len = %d", len(a))
	}
	// different key or room -> different token
	if RoomWakeKey(k, "wbstream", "other") == a {
		t.Fatalf("room not mixed into key")
	}
	other := "ff23456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
	if RoomWakeKey(other, "wbstream", "stab_gw") == a {
		t.Fatalf("key not mixed into token")
	}
}

func TestWatchWakeSelectsRoom(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := Config{Provider: "wbstream", RoomURL: "stab_gw", KeyHex: key}
	// A no-op hooks set: the join will fail fast against the real provider,
	// but Wake must mark the room active first.
	w := NewWatchServer([]Config{cfg}, ServerHooks{}, 1)
	rk := RoomWakeKey(key, "wbstream", "stab_gw")
	if _, ok := w.rooms[rk]; !ok {
		t.Fatalf("room not registered under its wake key")
	}
	// Unknown key must not wake anything.
	w.Wake("deadbeefdeadbeefdeadbeef")
	if w.ActiveRooms() != 0 {
		t.Fatalf("unknown key woke a room")
	}
}

func TestBeaconNSWakesRoom(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg := Config{Provider: "wbstream", RoomURL: "stab_gw", KeyHex: key}
	w := NewWatchServer([]Config{cfg}, ServerHooks{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = RunBeaconDNS(ctx, "127.0.0.1:15353", "w.example.com", w) }()
	time.Sleep(300 * time.Millisecond) // let the listener bind
	rk := RoomWakeKey(key, "wbstream", "stab_gw")
	if err := SendWake(ctx, "127.0.0.1:15353", "w.example.com", rk); err != nil {
		t.Fatalf("SendWake: %v", err)
	}
	// The wake must activate the room (RunServer then fails on the real
	// network, but the activation is what we assert).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if w.ActiveRooms() > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("beacon did not wake the room")
}
