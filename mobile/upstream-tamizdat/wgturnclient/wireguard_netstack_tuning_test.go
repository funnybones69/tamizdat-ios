package wgturnclient

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestTuneMobileTCPBufferOptions(t *testing.T) {
	s := gstack.New(gstack.Options{
		NetworkProtocols:   []gstack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []gstack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	defer s.Close()

	if err := tuneMobileTCPBufferOptions(s); err != nil {
		t.Fatalf("tuneMobileTCPBufferOptions: %v", err)
	}
	assertMobileTCPOptions(t, s)
}

func TestTuneWireGuardNetstackTCPBuffers(t *testing.T) {
	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.88.0.2")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1280,
	)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()

	if err := tuneWireGuardNetstackTCPBuffers(tnet); err != nil {
		t.Fatalf("tuneWireGuardNetstackTCPBuffers: %v", err)
	}
	s, err := wireGuardNetstackStack(tnet)
	if err != nil {
		t.Fatalf("wireGuardNetstackStack: %v", err)
	}
	assertMobileTCPOptions(t, s)
}

func assertMobileTCPOptions(t *testing.T, s *gstack.Stack) {
	t.Helper()

	var recv tcpip.TCPReceiveBufferSizeRangeOption
	if tcpipErr := s.TransportProtocolOption(tcp.ProtocolNumber, &recv); tcpipErr != nil {
		t.Fatalf("read tcp receive option: %v", tcpipErr)
	}
	if recv.Min != mobileTCPBufferMin || recv.Default != mobileTCPBufferDefault || recv.Max != mobileTCPBufferMax {
		t.Fatalf("receive option = %+v, want min=%d default=%d max=%d", recv, mobileTCPBufferMin, mobileTCPBufferDefault, mobileTCPBufferMax)
	}

	var send tcpip.TCPSendBufferSizeRangeOption
	if tcpipErr := s.TransportProtocolOption(tcp.ProtocolNumber, &send); tcpipErr != nil {
		t.Fatalf("read tcp send option: %v", tcpipErr)
	}
	if send.Min != mobileTCPBufferMin || send.Default != mobileTCPBufferDefault || send.Max != mobileTCPBufferMax {
		t.Fatalf("send option = %+v, want min=%d default=%d max=%d", send, mobileTCPBufferMin, mobileTCPBufferDefault, mobileTCPBufferMax)
	}

	var sack tcpip.TCPSACKEnabled
	if tcpipErr := s.TransportProtocolOption(tcp.ProtocolNumber, &sack); tcpipErr != nil {
		t.Fatalf("read tcp sack option: %v", tcpipErr)
	}
	if !bool(sack) {
		t.Fatalf("tcp sack disabled")
	}
}
