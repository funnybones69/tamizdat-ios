package wgturnclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestResolvePeerUDPAddrNumericBypassesDNS(t *testing.T) {
	called := false
	peer, err := resolvePeerUDPAddr(context.Background(), "203.0.113.7:443", func(context.Context, string) ([]net.IPAddr, error) {
		called = true
		return nil, errors.New("numeric peer must not use DNS")
	})
	if err != nil {
		t.Fatalf("resolve numeric peer: %v", err)
	}
	if called {
		t.Fatal("numeric peer invoked DNS resolver")
	}
	if got := peer.String(); got != "203.0.113.7:443" {
		t.Fatalf("numeric peer=%q, want 203.0.113.7:443", got)
	}
}

func TestResolvePeerUDPAddrDNSIsContextBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := resolvePeerUDPAddr(ctx, "peer.example:443", func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("resolve error=%v, want context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("context-bounded resolve took %v", elapsed)
	}
}

func TestResolvePeerUDPAddrPrefersIPv4(t *testing.T) {
	peer, err := resolvePeerUDPAddr(context.Background(), "peer.example:443", func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("198.51.100.8")}}, nil
	})
	if err != nil {
		t.Fatalf("resolve hostname: %v", err)
	}
	if got := peer.String(); got != "198.51.100.8:443" {
		t.Fatalf("resolved peer=%q, want IPv4 first", got)
	}
}
