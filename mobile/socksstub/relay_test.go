package socksstub

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayUsesEightKiBBuffersAndClosesBothDirections(t *testing.T) {
	buf := getRelayBuf()
	if got := len(*buf); got != 8*1024 {
		t.Fatalf("relay buffer len=%d, want %d", got, 8*1024)
	}
	putRelayBuf(buf)

	a, aPeer := net.Pipe()
	b, bPeer := net.Pipe()
	defer aPeer.Close()
	defer bPeer.Close()
	go relay(a, b, 1)

	copyAndRead := func(t *testing.T, src net.Conn, dst net.Conn, payload string) {
		t.Helper()
		writeDone := make(chan error, 1)
		go func() {
			_, err := src.Write([]byte(payload))
			writeDone <- err
		}()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(dst, got); err != nil {
			t.Fatalf("relay read %q: %v", payload, err)
		}
		if string(got) != payload {
			t.Fatalf("relay payload=%q, want %q", got, payload)
		}
		if err := <-writeDone; err != nil {
			t.Fatalf("relay write %q: %v", payload, err)
		}
	}
	copyAndRead(t, aPeer, bPeer, "a-to-b")
	copyAndRead(t, bPeer, aPeer, "b-to-a")

	if err := aPeer.Close(); err != nil {
		t.Fatalf("close first direction: %v", err)
	}
	if err := bPeer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set close deadline: %v", err)
	}
	if _, err := bPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("relay did not close the opposite direction")
	}
}
