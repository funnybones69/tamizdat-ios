package vks

import (
	"testing"
	"time"
)

// TestIdleExpiredRequiresNoConnsAndNoTraffic pins the idle rule the native
// room listener uses to decide whether to leave a woken room.
//
// Two different failures forced BOTH conditions:
//
//   - An open conn means a flow is live. During a download the client only
//     ACKs, and ACKs never reach the application callback that stamps
//     lastActivity, so an activity-only rule released the room mid-transfer
//     and killed the download.
//   - Recent traffic means the client is still there between flows. A
//     tunnel's conns are short-lived by design, so a socket-count-only rule
//     released the room underneath a healthy client that was idle for a
//     moment (observed live: released 12 s before the next dial arrived).
func TestIdleExpiredRequiresNoConnsAndNoTraffic(t *testing.T) {
	newListener := func(idle time.Duration) *dcListener {
		return &dcListener{idle: idle, conns: map[string]*dcConn{}}
	}
	// A conn that is open but quiet: the download case.
	openConn := func(l *dcListener) {
		c := newDcConn(nil, dcAddr("server"), dcAddr("tag"))
		c.sid = []byte("tag1")
		l.conns["tag1"] = c
	}

	t.Run("idle=0 never releases", func(t *testing.T) {
		l := newListener(0)
		l.touch()
		if l.idleExpired() {
			t.Fatal("idle=0 must disable release")
		}
	})

	t.Run("never touched does not expire", func(t *testing.T) {
		l := newListener(100 * time.Millisecond)
		if l.idleExpired() {
			t.Fatal("an untouched listener must not be idle before its first touch")
		}
	})

	t.Run("recent activity keeps the room", func(t *testing.T) {
		l := newListener(100 * time.Millisecond)
		l.touch()
		if l.idleExpired() {
			t.Fatal("a room touched just now must not be idle")
		}
	})

	t.Run("an open conn keeps the room even when traffic went quiet", func(t *testing.T) {
		l := newListener(100 * time.Millisecond)
		openConn(l)
		// Quiet for far longer than the idle span, as during a download whose
		// only client->server traffic is KCP ACKs.
		l.lastActivityNanos.Store(time.Now().Add(-time.Hour).UnixNano())
		if l.idleExpired() {
			t.Fatal("a room with a live conn must not be released")
		}
	})

	t.Run("silence with no conns releases", func(t *testing.T) {
		l := newListener(100 * time.Millisecond)
		l.lastActivityNanos.Store(time.Now().Add(-time.Second).UnixNano())
		if !l.idleExpired() {
			t.Fatal("a room silent past its span with no conns must be released")
		}
	})

	t.Run("new traffic revives a quiet room", func(t *testing.T) {
		l := newListener(100 * time.Millisecond)
		l.lastActivityNanos.Store(time.Now().Add(-time.Second).UnixNano())
		l.touch()
		if l.idleExpired() {
			t.Fatal("activity must reset the idle timer")
		}
	})
}
