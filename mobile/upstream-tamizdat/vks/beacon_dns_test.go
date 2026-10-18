package vks

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	testShortID      = "00112233"
	otherTestShortID = "ffeeddcc"
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
	a := RoomWakeKey(testShortID, "wbstream", "stab_gw")
	b := RoomWakeKey(testShortID, "wbstream", "stab_gw")
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	if len(a) != 24 {
		t.Fatalf("len = %d", len(a))
	}
	// different user, provider or room -> different token
	if RoomWakeKey(otherTestShortID, "wbstream", "stab_gw") == a {
		t.Fatalf("shortid not mixed into token")
	}
	if RoomWakeKey(testShortID, "wbstream", "other") == a {
		t.Fatalf("room not mixed into key")
	}
	if RoomWakeKey(testShortID, "jazz", "stab_gw") == a {
		t.Fatalf("provider not mixed into key")
	}
}

func TestProviderWakeKeyPerUser(t *testing.T) {
	a := ProviderWakeKey(testShortID, "telemost")
	if a != ProviderWakeKey(testShortID, "telemost") {
		t.Fatalf("non-deterministic")
	}
	if len(a) != 24 {
		t.Fatalf("len = %d", len(a))
	}
	if ProviderWakeKey(otherTestShortID, "telemost") == a {
		t.Fatalf("shortid not mixed into provider selector")
	}
	if ProviderWakeKey(testShortID, "jazz") == a {
		t.Fatalf("provider not mixed into selector")
	}
	if got := matchProviderKey(a, testShortID); got != "telemost" {
		t.Fatalf("matchProviderKey = %q, want telemost", got)
	}
	if got := matchProviderKey(a, otherTestShortID); got != "" {
		t.Fatalf("selector matched a different user's shortid: %q", got)
	}
}

func TestWatchWakeSelectsRoom(t *testing.T) {
	cfg := Config{Provider: "wbstream", RoomURL: "stab_gw"}
	// A no-op hooks set: the join will fail fast against the real provider,
	// but Wake must mark the room active first.
	w := NewWatchServer([]Config{cfg}, ServerHooks{}, 1)
	key := w.roomKey(cfg)
	if _, ok := w.rooms[key]; !ok {
		t.Fatalf("room not registered under its internal key")
	}
	// The per-user selector resolves to the armed room; a different user's
	// selector does not.
	if got, ok := w.matchRoomKey(RoomWakeKey(testShortID, "wbstream", "stab_gw"), testShortID); !ok || got != key {
		t.Fatalf("matchRoomKey = %q, %v; want %q, true", got, ok, key)
	}
	if _, ok := w.matchRoomKey(RoomWakeKey(testShortID, "wbstream", "stab_gw"), otherTestShortID); ok {
		t.Fatalf("user A's selector matched when derived for user B")
	}
	// Unknown key must not wake anything.
	w.Wake("deadbeefdeadbeefdeadbeef")
	if w.ActiveRooms() != 0 {
		t.Fatalf("unknown key woke a room")
	}
}

func TestBeaconNSWakesRoom(t *testing.T) {
	cfg := Config{Provider: "wbstream", RoomURL: "stab_gw"}
	w := NewWatchServer([]Config{cfg}, ServerHooks{}, 1)
	w.SetShortIDValidator(func(shortIDHex string) bool { return shortIDHex == testShortID })
	// Hold the woken room open for the duration of the test instead of
	// letting the olcRTC RunServer fail on the missing legacy wire key.
	w.SetNativeServe(func(ctx context.Context, cfg Config) error { <-ctx.Done(); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = RunBeaconDNS(ctx, "127.0.0.1:15353", "w.example.com", w) }()
	time.Sleep(300 * time.Millisecond) // let the listener bind
	rk := RoomWakeKey(testShortID, "wbstream", "stab_gw")
	if err := SendWake(ctx, "127.0.0.1:15353", "w.example.com", testShortID, rk); err != nil {
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

func TestProviderBeaconShortIDAcceptedAndRejected(t *testing.T) {
	cfg := Config{Provider: "wbstream", RoomURL: "stab_gw"}
	w := NewWatchServer([]Config{cfg}, ServerHooks{}, 1)
	w.SetShortIDValidator(func(shortIDHex string) bool { return shortIDHex == testShortID })
	w.SetNativeServe(func(ctx context.Context, cfg Config) error { <-ctx.Done(); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = RunBeaconDNS(ctx, "127.0.0.1:15354", "w.example.com", w) }()
	time.Sleep(300 * time.Millisecond)

	// A known user's beacon is accepted and gets the armed room assigned.
	spec, _, err := SendWakeProvider(ctx, "127.0.0.1:15354", "w.example.com", "wbstream", testShortID)
	if err != nil {
		t.Fatalf("valid shortid beacon: %v", err)
	}
	if !strings.HasPrefix(spec, "wbstream:") {
		t.Fatalf("assigned spec = %q", spec)
	}

	// An unknown shortid cannot even derive the selector the server would
	// match, and the server answers without a TXT record.
	if _, _, err := SendWakeProvider(ctx, "127.0.0.1:15354", "w.example.com", "wbstream", otherTestShortID); err == nil {
		t.Fatalf("unknown shortid was accepted")
	}
}

func TestAnswerKeyedPerUser(t *testing.T) {
	query := buildTXTQuery("abc.w.example.com.")
	_, qend, ok := decodeQName(query, 12)
	if !ok || qend+4 > len(query) {
		t.Fatalf("bad query: qend=%d len=%d", qend, len(query))
	}
	var captured []byte
	pc := &fakePacketConn{onWrite: func(b []byte) { captured = append([]byte(nil), b...) }}
	const nonce = "aabbccdd"
	respondTXT(pc, nilAddr{}, query, qend, testShortID, nonce, "telemost:https://telemost.yandex.ru/j/xyz", []string{"login=mts"})
	if captured == nil {
		t.Fatal("no TXT answer written")
	}
	all, err := parseTXTAnswerAll(captured)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(all) != 2 || all[1] != "login=mts" {
		t.Fatalf("all = %q", all)
	}
	if strings.Contains(all[0], "telemost:") {
		t.Fatalf("spec leaked in plaintext: %q", all[0])
	}
	spec, ok := decodeAnswerSpec(testShortID, nonce, all[0])
	if !ok || spec != "telemost:https://telemost.yandex.ru/j/xyz" {
		t.Fatalf("decode with owner shortid = %q, %v", spec, ok)
	}
	// Another user cannot authenticate/decrypt the answer.
	if _, ok := decodeAnswerSpec(otherTestShortID, nonce, all[0]); ok {
		t.Fatalf("another user decoded the answer")
	}
	// A different nonce invalidates the tag too.
	if _, ok := decodeAnswerSpec(testShortID, "deadbeef", all[0]); ok {
		t.Fatalf("answer accepted under a different nonce")
	}

	// Empty spec (login required) round-trips through the same envelope.
	captured = nil
	respondTXT(pc, nilAddr{}, query, qend, testShortID, nonce, "", []string{"login=telemost,mts"})
	all, err = parseTXTAnswerAll(captured)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if spec, ok := decodeAnswerSpec(testShortID, nonce, all[0]); !ok || spec != "" {
		t.Fatalf("empty spec = %q, %v", spec, ok)
	}
	if len(all) != 2 || all[1] != "login=telemost,mts" {
		t.Fatalf("empty-spec flags = %q", all)
	}
}

// --- test doubles -------------------------------------------------------------

// fakePacketConn captures WriteTo payloads.
type fakePacketConn struct {
	onWrite func([]byte)
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.onWrite != nil {
		c.onWrite(p)
	}
	return len(p), nil
}
func (c *fakePacketConn) Close() error                       { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                { return nilAddr{} }
func (c *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

type nilAddr struct{}

func (nilAddr) Network() string { return "udp" }
func (nilAddr) String() string  { return "0.0.0.0:0" }
