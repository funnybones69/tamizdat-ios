package vks

import (
	"testing"
	"time"
)

// TestIdleExpiredFollowsClientActivity pins the idle rule the native room
// listener uses to decide whether to leave a woken room.
//
// The rule used to be "no open accepted conns for IdleTimeout". A tunnel's
// conns are short-lived by design, so a perfectly healthy client that is
// merely between flows looked abandoned and the server released the room
// underneath it — which then made every later dial pay a fresh room join,
// and (with the phone's 3 s probe cadence) turned into a join/release loop.
// Activity on the room, not socket count, is the signal.
func TestIdleExpiredFollowsClientActivity(t *testing.T) {
	l := &dcListener{idle: 100 * time.Millisecond}

	// Never touched: the join grace starts from zero, so the room is not
	// immediately idle (the caller touches it at start).
	if l.idleExpired() {
		t.Fatal("an untouched listener must not be considered idle before its first touch")
	}

	// A disabled idle timer never expires, however quiet the room is.
	disabled := &dcListener{idle: 0}
	disabled.touch()
	if disabled.idleExpired() {
		t.Fatal("idle=0 must disable release")
	}

	// Fresh activity keeps the room.
	l.touch()
	if l.idleExpired() {
		t.Fatal("a room touched just now must not be idle")
	}

	// Activity older than the span releases it.
	l.lastActivityNanos.Store(time.Now().Add(-time.Second).UnixNano())
	if !l.idleExpired() {
		t.Fatal("a room silent for longer than its idle span must be released")
	}

	// And a new frame from the client revives it — this is the case that
	// used to be lost, because a retry HELLO does not open a conn.
	l.touch()
	if l.idleExpired() {
		t.Fatal("activity must reset the idle timer")
	}
}
