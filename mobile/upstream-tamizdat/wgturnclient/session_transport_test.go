package wgturnclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

func TestSessionReadTimeoutTracksLastInboundActivity(t *testing.T) {
	tests := []struct {
		name string
		last time.Duration
		now  time.Duration
		want time.Duration
	}{
		{name: "initial window", last: 0, now: 0, want: 15 * time.Second},
		{name: "heartbeat extends full window", last: 10 * time.Second, now: 15 * time.Second, want: 10 * time.Second},
		{name: "just before expiry", last: 10 * time.Second, now: 24*time.Second + 999*time.Millisecond, want: time.Millisecond},
		{name: "expires after full silence", last: 10 * time.Second, now: 25 * time.Second, want: 0},
		{name: "monotonic guard", last: 2 * time.Second, now: time.Second, want: 15 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionReadTimeoutRemaining(tc.last, tc.now); got != tc.want {
				t.Fatalf("remaining=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestSelectTurnEndpointFiltersV2ByRequestedUDPTransport(t *testing.T) {
	creds := &Credentials{
		TurnURLs: []string{"udp.example:3478", "tcp.example:3478"},
		TurnServers: []TurnServer{
			{Host: "udp.example", Port: 3478, Scheme: "turn", Transport: "udp"},
			{Host: "tcp.example", Port: 3478, Scheme: "turn", Transport: "tcp"},
		},
	}

	endpoint, err := selectTurnEndpoint(creds, 1, true)
	if err != nil {
		t.Fatalf("selectTurnEndpoint: %v", err)
	}
	if endpoint.Addr != "udp.example:3478" {
		t.Fatalf("selected addr = %q, want UDP endpoint", endpoint.Addr)
	}
	if !endpoint.UseUDP || endpoint.UseTLS || endpoint.Proto != "UDP" {
		t.Fatalf("endpoint transport = proto=%q useUDP=%t useTLS=%t, want UDP/no-TLS", endpoint.Proto, endpoint.UseUDP, endpoint.UseTLS)
	}
}

func TestSelectTurnEndpointUsesTLSForTURNSOverTCP(t *testing.T) {
	creds := &Credentials{
		TurnURLs: []string{"secure.example:5349"},
		TurnServers: []TurnServer{
			{Host: "secure.example", Port: 5349, Scheme: "turns", Transport: "tcp"},
		},
	}

	endpoint, err := selectTurnEndpoint(creds, 0, false)
	if err != nil {
		t.Fatalf("selectTurnEndpoint: %v", err)
	}
	if endpoint.Addr != "secure.example:5349" {
		t.Fatalf("selected addr = %q", endpoint.Addr)
	}
	if endpoint.UseUDP || !endpoint.UseTLS || endpoint.Proto != "TLS" {
		t.Fatalf("endpoint transport = proto=%q useUDP=%t useTLS=%t, want TLS over TCP", endpoint.Proto, endpoint.UseUDP, endpoint.UseTLS)
	}
}

func TestSelectTurnEndpointFallsBackToLegacyURLsWhenV2Absent(t *testing.T) {
	creds := &Credentials{TurnURLs: []string{"legacy-a.example:3478", "legacy-b.example:3478"}}

	endpoint, err := selectTurnEndpoint(creds, 1, false)
	if err != nil {
		t.Fatalf("selectTurnEndpoint: %v", err)
	}
	if endpoint.Addr != "legacy-b.example:3478" {
		t.Fatalf("selected addr = %q, want legacy-b.example:3478", endpoint.Addr)
	}
	if endpoint.UseUDP || endpoint.UseTLS || endpoint.Proto != "TCP" {
		t.Fatalf("endpoint transport = proto=%q useUDP=%t useTLS=%t, want TCP/no-TLS", endpoint.Proto, endpoint.UseUDP, endpoint.UseTLS)
	}
}

func TestApplyTurnStreamMemoryProfileTunesRawSocket(t *testing.T) {
	socket := &recordingTurnStreamSocket{}
	profile := sessionMemoryProfile{socketBufferSize: 24 * 1024}
	if err := applyTurnStreamMemoryProfile(socket, profile); err != nil {
		t.Fatalf("applyTurnStreamMemoryProfile: %v", err)
	}
	if !socket.noDelay || socket.readBuffer != profile.socketBufferSize || socket.writeBuffer != profile.socketBufferSize {
		t.Fatalf("socket tuning = noDelay:%t read:%d write:%d", socket.noDelay, socket.readBuffer, socket.writeBuffer)
	}
}

func TestDialTurnStreamTunesRawTCPBeforeTLSWrap(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	certificate := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	serverName := ""
	if len(certificate.DNSNames) > 0 {
		serverName = certificate.DNSNames[0]
	} else if len(certificate.IPAddresses) > 0 {
		serverName = certificate.IPAddresses[0].String()
	}
	if serverName == "" {
		t.Fatal("httptest certificate has no verifiable name")
	}
	profile := sessionMemoryProfile{socketBufferSize: 24 * 1024}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}
	conn, err := dialTurnStream(context.Background(), server.Listener.Addr().String(), true, tlsConfig, profile)
	if err != nil {
		t.Fatalf("dialTurnStream TLS: %v", err)
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		t.Fatalf("connection type=%T, want *tls.Conn", conn)
	}
	if _, ok := tlsConn.NetConn().(*net.TCPConn); !ok {
		t.Fatalf("wrapped connection type=%T, want raw *net.TCPConn", tlsConn.NetConn())
	}
}

func TestListenTURNInboundUsesBoundedBuffer(t *testing.T) {
	conn := &recordingTURNPacketConn{bufferSize: make(chan int, 1)}
	handler := &recordingTURNInboundHandler{payload: make(chan []byte, 1)}
	errCh := make(chan error, 1)
	go func() { errCh <- listenTURNInbound(conn, handler) }()

	if got := <-conn.bufferSize; got != turnInboundReadBufferSize {
		t.Fatalf("TURN inbound read buffer=%d, want %d", got, turnInboundReadBufferSize)
	}
	if got := string(<-handler.payload); got != "packet" {
		t.Fatalf("TURN inbound payload=%q, want packet", got)
	}
	if err := <-errCh; !errors.Is(err, io.EOF) {
		t.Fatalf("listenTURNInbound error=%v, want EOF", err)
	}
}

func TestListenTURNInboundRejectsOversizedSTUNConnFrameWithoutPanic(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	const payloadSize = turnInboundReadBufferSize + 1024
	frame := make([]byte, 4+payloadSize)
	binary.BigEndian.PutUint16(frame[0:2], 0x4000) // valid TURN ChannelData number
	binary.BigEndian.PutUint16(frame[2:4], payloadSize)
	writeErr := make(chan error, 1)
	go func() {
		_, err := serverSide.Write(frame)
		writeErr <- err
	}()

	handler := &recordingTURNInboundHandler{payload: make(chan []byte, 1)}
	err := listenTURNInbound(turn.NewSTUNConn(clientSide), handler)
	if !errors.Is(err, errTURNInboundFrameTooLarge) {
		t.Fatalf("oversized STUNConn frame error=%v, want %v", err, errTURNInboundFrameTooLarge)
	}
	select {
	case got := <-handler.payload:
		t.Fatalf("oversized frame reached handler: %d bytes", len(got))
	default:
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write oversized ChannelData frame: %v", err)
	}
}

func TestListenTURNInboundRejectsTruncatedUDPDatagram(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP server: %v", err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial UDP server: %v", err)
	}
	defer client.Close()

	payload := make([]byte, turnInboundReadBufferSize+1)
	if _, err := server.WriteToUDP(payload, client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write oversized UDP datagram: %v", err)
	}
	handler := &recordingTURNInboundHandler{payload: make(chan []byte, 1)}
	err = listenTURNInbound(&connectedUDPConn{client}, handler)
	if !errors.Is(err, errTURNInboundFrameTooLarge) {
		t.Fatalf("oversized UDP datagram error=%v, want %v", err, errTURNInboundFrameTooLarge)
	}
	select {
	case got := <-handler.payload:
		t.Fatalf("truncated UDP datagram reached handler: %d bytes", len(got))
	default:
	}
}

func TestListenTURNInboundSupportsRealTURNAllocate(t *testing.T) {
	const (
		realm    = "bounded-listener.test"
		username = "test-user"
		password = "test-password"
	)
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TURN server: %v", err)
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(attrs *turn.RequestAttributes) (string, []byte, bool) {
			if attrs.Username != username || attrs.Realm != realm {
				return "", nil, false
			}
			return username, turn.GenerateAuthKey(username, realm, password), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: serverConn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		LoggerFactory: &NullLoggerFactory{},
	})
	if err != nil {
		_ = serverConn.Close()
		t.Fatalf("new TURN server: %v", err)
	}
	defer server.Close()

	clientConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TURN client: %v", err)
	}
	defer clientConn.Close()
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: serverConn.LocalAddr().String(),
		TURNServerAddr: serverConn.LocalAddr().String(),
		Conn:           clientConn,
		Username:       username,
		Password:       password,
		LoggerFactory:  &NullLoggerFactory{},
	})
	if err != nil {
		t.Fatalf("new TURN client: %v", err)
	}
	defer client.Close()
	listenErr := make(chan error, 1)
	go func() { listenErr <- listenTURNInbound(clientConn, client) }()

	relay, err := client.Allocate()
	if err != nil {
		t.Fatalf("TURN Allocate through bounded listener: %v", err)
	}
	if relay.LocalAddr() == nil {
		t.Fatal("TURN Allocate returned no relay address")
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("close TURN relay: %v", err)
	}
	_ = clientConn.Close()
	select {
	case err := <-listenErr:
		if err == nil {
			t.Fatal("bounded listener stopped without close error")
		}
	case <-time.After(time.Second):
		t.Fatal("bounded listener did not stop after PacketConn close")
	}
}

func TestRunDTLSHandshakeWithThrottleReleasesSlotOnSuccessAndError(t *testing.T) {
	resetHandshakeSemForTest(t)

	if err := runDTLSHandshakeWithThrottle(context.Background(), 0, fakeDTLSHandshaker{}); err != nil {
		t.Fatalf("runDTLSHandshakeWithThrottle success: %v", err)
	}
	if got := len(handshakeSem); got != 0 {
		t.Fatalf("handshake semaphore leaked after success: len=%d", got)
	}

	boom := errors.New("boom")
	err := runDTLSHandshakeWithThrottle(context.Background(), 1, fakeDTLSHandshaker{err: boom})
	if err == nil || !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("runDTLSHandshakeWithThrottle error = %v, want boom", err)
	}
	if got := len(handshakeSem); got != 0 {
		t.Fatalf("handshake semaphore leaked after error: len=%d", got)
	}
}

func TestRunDTLSHandshakeWithThrottleTimesOutWhenFull(t *testing.T) {
	resetHandshakeSemForTest(t)
	for i := 0; i < handshakeSemCap; i++ {
		handshakeSem <- struct{}{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := runDTLSHandshakeWithThrottle(ctx, 2, fakeDTLSHandshaker{})
	if err == nil || !strings.Contains(err.Error(), "DTLS handshake throttle") {
		t.Fatalf("runDTLSHandshakeWithThrottle full semaphore error = %v", err)
	}
}

type recordingTURNPacketConn struct {
	reads      int
	bufferSize chan int
}

func (c *recordingTURNPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.reads > 0 {
		return 0, nil, io.EOF
	}
	c.reads++
	c.bufferSize <- len(p)
	return copy(p, "packet"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3478}, nil
}
func (*recordingTURNPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (*recordingTURNPacketConn) Close() error                              { return nil }
func (*recordingTURNPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (*recordingTURNPacketConn) SetDeadline(time.Time) error               { return nil }
func (*recordingTURNPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (*recordingTURNPacketConn) SetWriteDeadline(time.Time) error          { return nil }

type recordingTURNInboundHandler struct {
	payload chan []byte
}

func (h *recordingTURNInboundHandler) HandleInbound(data []byte, _ net.Addr) (bool, error) {
	h.payload <- append([]byte(nil), data...)
	return true, nil
}

type fakeDTLSHandshaker struct {
	err error
}

type recordingTurnStreamSocket struct {
	noDelay     bool
	readBuffer  int
	writeBuffer int
}

func (s *recordingTurnStreamSocket) SetNoDelay(value bool) error {
	s.noDelay = value
	return nil
}

func (s *recordingTurnStreamSocket) SetReadBuffer(value int) error {
	s.readBuffer = value
	return nil
}

func (s *recordingTurnStreamSocket) SetWriteBuffer(value int) error {
	s.writeBuffer = value
	return nil
}

func (f fakeDTLSHandshaker) HandshakeContext(context.Context) error {
	return f.err
}

func resetHandshakeSemForTest(t *testing.T) {
	t.Helper()
	old := handshakeSem
	handshakeSem = make(chan struct{}, handshakeSemCap)
	t.Cleanup(func() { handshakeSem = old })
}
