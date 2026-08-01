package wgturnclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

const (
	singleRoomWorkerSendBuf = 128
	multiRoomWorkerSendBuf  = 32
	sessionReadTimeout      = 15 * time.Second
	readBufSize             = 1600
	singleRoomSocketBufSize = 625 * 1024
	// iOS Network Extensions have a tight process + kernel memory budget.
	// Keep aggregate guards for room admission and Go queues. Per-worker TURN
	// sockets use the explicit fixed workerSocketBufferSize from cadence.go.
	multiRoomSocketBudget = 4 * 1024 * 1024
	multiRoomQueueBudget  = 512 * 1024
	minWorkerSendBuf      = 4
	// Pion Client.Listen allocates math.MaxUint16 bytes per client. Our TURN
	// channel carries DTLS records for <=2 KiB overlay frames, so a 4 KiB
	// inbound buffer preserves protocol headroom while avoiding ~6.1 MiB of
	// live heap at 100 workers.
	turnInboundReadBufferSize = 4 * 1024
	// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696.
	// Cap concurrent DTLS handshakes to 3 to stop the OK CDN TURN
	// server from rate-limiting the whole worker group when many
	// sessions race to start at the same moment (worker-group rotation
	// or app cold-start). 3 is the upstream value; matches what their
	// production client ships with.
	handshakeSemCap     = 3
	handshakeAcquireTTL = 5 * time.Second
)

var errSessionReadTimeout = errors.New("wgturn session inbound timeout")

// sessionReadTimeoutRemaining measures the timeout from the most recent
// inbound frame, not from an older absolute socket deadline. Durations are
// measured from one monotonic session origin so wall-clock adjustments cannot
// spuriously expire every worker at once.
func sessionReadTimeoutRemaining(lastInbound, now time.Duration) time.Duration {
	if now < lastInbound {
		return sessionReadTimeout
	}
	idle := now - lastInbound
	if idle >= sessionReadTimeout {
		return 0
	}
	return sessionReadTimeout - idle
}

type sessionMemoryProfile struct {
	socketBufferSize int
	workerSendBuffer int
}

// MaxBudgetedRooms returns the largest whole room pool that stays within both
// aggregate multi-room memory budgets after the minimum per-worker floors are
// applied.
func MaxBudgetedRooms(workersPerRoom int) int {
	if workersPerRoom <= 0 {
		return 0
	}
	maxWorkersBySockets := multiRoomSocketBudget / (2 * workerSocketBufferSize)
	maxWorkersByQueues := multiRoomQueueBudget / (minWorkerSendBuf * readBufSize)
	if maxWorkersByQueues < maxWorkersBySockets {
		return maxWorkersByQueues / workersPerRoom
	}
	return maxWorkersBySockets / workersPerRoom
}

func memoryProfileForWorkers(workers int, explicitRoomPool bool) sessionMemoryProfile {
	sendBuffer := singleRoomWorkerSendBuf
	if explicitRoomPool {
		sendBuffer = multiRoomQueueBudget / workers / readBufSize
		if sendBuffer > multiRoomWorkerSendBuf {
			sendBuffer = multiRoomWorkerSendBuf
		}
		if sendBuffer < minWorkerSendBuf {
			sendBuffer = minWorkerSendBuf
		}
	}
	return sessionMemoryProfile{
		socketBufferSize: workerSocketBufferSize,
		workerSendBuffer: sendBuffer,
	}
}

// handshakeSem throttles concurrent DTLS Client handshakes against
// the TURN server. Package-level so all worker groups inside one
// process share the same budget — the upstream client uses the same
// scope. iOS test/release ship a single Runner per process, so the
// distinction does not matter today, but keeping the scope identical
// to upstream avoids drift when porting future fixes.
//
// Ported from cacggghp/vk-turn-proxy (GPL-3.0), commit e8a9696
// (client/main.go:66, 1404-1409).
var handshakeSem = make(chan struct{}, handshakeSemCap)

type dtlsHandshaker interface {
	HandshakeContext(context.Context) error
}

func runDTLSHandshakeWithThrottle(sessCtx context.Context, sessionID int, conn dtlsHandshaker) error {
	// Acquire one slot from the package-level handshake throttle before
	// running the DTLS handshake. The slot is released immediately after
	// HandshakeContext returns: it must cap concurrent handshakes, not
	// long-lived relay sessions.
	acqCtx, acqCancel := context.WithTimeout(sessCtx, handshakeAcquireTTL)
	select {
	case handshakeSem <- struct{}{}:
		acqCancel()
	case <-acqCtx.Done():
		acqCancel()
		return fmt.Errorf("DTLS handshake throttle: не удалось получить слот за %s (все %d заняты)", handshakeAcquireTTL, handshakeSemCap)
	}

	hctx, hcancel := context.WithTimeout(sessCtx, 45*time.Second)
	log.Printf("[ВОРКЕР #%d] [DTLS] Рукопожатие (Handshake)...", sessionID)
	err := conn.HandshakeContext(hctx)
	hcancel()
	<-handshakeSem
	if err != nil {
		return fmt.Errorf("DTLS хендшейк: %w", err)
	}
	log.Printf("[ВОРКЕР #%d] [DTLS] Соединение установлено ✓", sessionID)
	return nil
}

// NullLoggerFactory подавляет логи pion
type NullLoggerFactory struct{}

func (n *NullLoggerFactory) NewLogger(_ string) logging.LeveledLogger { return &NullLogger{} }

type NullLogger struct{}

func (n *NullLogger) Trace(_ string)                    {}
func (n *NullLogger) Tracef(_ string, _ ...interface{}) {}
func (n *NullLogger) Debug(_ string)                    {}
func (n *NullLogger) Debugf(_ string, _ ...interface{}) {}
func (n *NullLogger) Info(_ string)                     {}
func (n *NullLogger) Infof(_ string, _ ...interface{})  {}
func (n *NullLogger) Warn(_ string)                     {}
func (n *NullLogger) Warnf(_ string, _ ...interface{})  {}
func (n *NullLogger) Error(_ string)                    {}
func (n *NullLogger) Errorf(_ string, _ ...interface{}) {}

// connectedUDPConn — обёртка для connected UDP socket → PacketConn
type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

type turnEndpoint struct {
	Addr      string
	Scheme    string
	Transport string
	Proto     string
	UseUDP    bool
	UseTLS    bool
}

func selectTurnEndpoint(creds *Credentials, sessionID int, preferUDP bool) (turnEndpoint, error) {
	if creds == nil {
		return turnEndpoint{}, fmt.Errorf("пустые TURN учетные данные")
	}
	if len(creds.TurnServers) > 0 {
		matching := make([]turnEndpoint, 0, len(creds.TurnServers))
		fallback := make([]turnEndpoint, 0, len(creds.TurnServers))
		for _, server := range creds.TurnServers {
			ep, ok := endpointFromTurnServer(server)
			if !ok {
				continue
			}
			if ep.UseUDP == preferUDP {
				matching = append(matching, ep)
			} else {
				fallback = append(fallback, ep)
			}
		}
		if len(matching) == 0 {
			matching = fallback
		}
		if len(matching) == 0 {
			return turnEndpoint{}, fmt.Errorf("нет поддерживаемых TURN endpoints")
		}
		return matching[positiveModulo(sessionID, len(matching))], nil
	}
	if len(creds.TurnURLs) == 0 {
		return turnEndpoint{}, fmt.Errorf("нет TURN URL в учетных данных")
	}
	addr := strings.TrimSpace(creds.TurnURLs[positiveModulo(sessionID, len(creds.TurnURLs))])
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return turnEndpoint{}, fmt.Errorf("разбор TURN URL %q: %w", addr, err)
	}
	proto := "TCP"
	transport := "tcp"
	if preferUDP {
		proto = "UDP"
		transport = "udp"
	}
	return turnEndpoint{
		Addr:      addr,
		Scheme:    "turn",
		Transport: transport,
		Proto:     proto,
		UseUDP:    preferUDP,
	}, nil
}

func endpointFromTurnServer(server TurnServer) (turnEndpoint, bool) {
	host := strings.TrimSpace(server.Host)
	if host == "" || server.Port <= 0 {
		return turnEndpoint{}, false
	}
	scheme := strings.ToLower(strings.TrimSpace(server.Scheme))
	if scheme == "" {
		scheme = "turn"
	}
	transport := strings.ToLower(strings.TrimSpace(server.Transport))
	if transport == "" {
		if scheme == "turns" {
			transport = "tcp"
		} else {
			transport = "udp"
		}
	}
	if transport != "udp" && transport != "tcp" {
		transport = "udp"
	}
	useTLS := scheme == "turns"
	useUDP := transport == "udp" && !useTLS
	proto := "TCP"
	if useUDP {
		proto = "UDP"
	} else if useTLS {
		proto = "TLS"
		transport = "tcp"
	}
	return turnEndpoint{
		Addr:      net.JoinHostPort(host, fmt.Sprintf("%d", server.Port)),
		Scheme:    scheme,
		Transport: transport,
		Proto:     proto,
		UseUDP:    useUDP,
		UseTLS:    useTLS,
	}, true
}

func positiveModulo(value, mod int) int {
	if mod <= 0 {
		return 0
	}
	result := value % mod
	if result < 0 {
		result += mod
	}
	return result
}

func emitEvent(onEvent EventFunc, level, format string, args ...interface{}) {
	if onEvent == nil {
		return
	}
	onEvent(level, fmt.Sprintf(format, args...))
}

type turnInboundHandler interface {
	HandleInbound([]byte, net.Addr) (bool, error)
}

var errTURNInboundFrameTooLarge = errors.New("TURN inbound frame exceeds bounded buffer")

type turnUDPMessageConn interface {
	ReadMsgUDP([]byte, []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
}

type remoteAddrConn interface {
	RemoteAddr() net.Addr
}

func readTURNInboundFrame(conn net.PacketConn, buf []byte) (int, net.Addr, error) {
	// A UDP ReadFrom silently truncates oversized datagrams. ReadMsgUDP exposes
	// MSG_TRUNC so malformed/oversized server traffic fails the worker cleanly
	// instead of feeding a partial TURN frame to Pion.
	if udpConn, ok := conn.(turnUDPMessageConn); ok {
		n, _, flags, from, err := udpConn.ReadMsgUDP(buf, nil)
		if err != nil {
			return 0, nil, err
		}
		if n < 0 || n > len(buf) || flags&syscall.MSG_TRUNC != 0 {
			return 0, nil, fmt.Errorf("%w: n=%d capacity=%d", errTURNInboundFrameTooLarge, n, len(buf))
		}
		var addr net.Addr = from
		if addr == nil {
			if connected, ok := conn.(remoteAddrConn); ok {
				addr = connected.RemoteAddr()
			}
		}
		return n, addr, nil
	}

	// Pion STUNConn may report the complete stream-frame length even when the
	// caller's buffer is smaller. Check before slicing to avoid a panic on a
	// large ChannelData frame.
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 0 || n > len(buf) {
		return 0, nil, fmt.Errorf("%w: n=%d capacity=%d", errTURNInboundFrameTooLarge, n, len(buf))
	}
	return n, from, nil
}

// listenTURNInbound is the memory-bounded equivalent of pion/turn Client.Listen.
// Pion's helper always retains a 65535-byte buffer per worker; our overlay has a
// much smaller, explicit frame ceiling. Keeping this loop local also makes the
// allocation visible to tests and prevents a dependency upgrade from silently
// restoring the per-worker 64 KiB cost.
func listenTURNInbound(conn net.PacketConn, handler turnInboundHandler) error {
	buf := make([]byte, turnInboundReadBufferSize)
	for {
		n, from, err := readTURNInboundFrame(conn, buf)
		if err != nil {
			return err
		}
		if _, err := handler.HandleInbound(buf[:n], from); err != nil {
			// Match Client.Listen semantics: an inbound parsing error stops this
			// worker's listener rather than spinning on a broken packet stream.
			return err
		}
	}
}

func sanitizeErrForEvent(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.ReplaceAll(msg, "\r", " ")
	if len(msg) > 180 {
		msg = msg[:180] + "…"
	}
	return msg
}

func classifyTURNError(err error) (stunCode int, quota bool) {
	if err == nil {
		return 0, false
	}
	lower := strings.ToLower(err.Error())
	quota = strings.Contains(lower, "quota") || strings.Contains(lower, "486")
	if strings.Contains(lower, "486") {
		stunCode = 486
	}
	return stunCode, quota
}

func ternaryEventLevel(warn bool) string {
	if warn {
		return "warn"
	}
	return "error"
}

func enqueueSessionReturn(ctx context.Context, d *Dispatcher, stats *Stats, roomID, workerID int, packet []byte, bondV2 bool) bool {
	// Raw transport attribution belongs to the DTLS read boundary. Count before
	// a possibly blocked enqueue so shutdown cannot erase an already received,
	// wire-valid DATA frame from aggregate/per-room telemetry.
	if bondV2 {
		recordBondRoomDown(stats, roomID, workerID, packet)
	}
	select {
	case d.ReturnCh <- packet:
		return true
	case <-ctx.Done():
		return false
	}
}

type turnStreamSocket interface {
	SetNoDelay(bool) error
	SetReadBuffer(int) error
	SetWriteBuffer(int) error
}

func applyTurnStreamMemoryProfile(socket turnStreamSocket, profile sessionMemoryProfile) error {
	if err := socket.SetNoDelay(true); err != nil {
		return fmt.Errorf("TCP_NODELAY: %w", err)
	}
	if err := socket.SetReadBuffer(profile.socketBufferSize); err != nil {
		return fmt.Errorf("TCP read buffer: %w", err)
	}
	if err := socket.SetWriteBuffer(profile.socketBufferSize); err != nil {
		return fmt.Errorf("TCP write buffer: %w", err)
	}
	return nil
}

// dialTurnStream tunes the raw TCP socket before any TLS wrapper hides it.
func dialTurnStream(ctx context.Context, turnAddr string, useTLS bool, tlsConfig *tls.Config, profile sessionMemoryProfile) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", turnAddr)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("unexpected TURN TCP connection type %T", raw)
	}
	if err := applyTurnStreamMemoryProfile(tcpConn, profile); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if !useTLS {
		return tcpConn, nil
	}
	if tlsConfig == nil {
		_ = raw.Close()
		return nil, fmt.Errorf("missing TURN TLS config")
	}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func RunSession(
	ctx context.Context,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	useUDP bool,
	getConfig bool,
	configCh chan<- string,
	sessionID int,
	creds *Credentials,
	deviceID, password string,
	stats *Stats,
	onEvent EventFunc,
	memoryProfile sessionMemoryProfile,
	bondV2 bool,
	bondID bondRunnerIdentity,
	roomID int,
) (bool, error) {
	configDelivered := false

	endpoint, err := selectTurnEndpoint(creds, sessionID, useUDP)
	if err != nil {
		return false, err
	}

	urlhost, urlport, err := net.SplitHostPort(endpoint.Addr)
	if err != nil {
		return false, fmt.Errorf("разбор TURN URL %q: %w", endpoint.Addr, err)
	}
	if tp.Host != "" {
		urlhost = tp.Host
	}
	if tp.Port != "" {
		urlport = tp.Port
	}
	turnAddr := net.JoinHostPort(urlhost, urlport)

	// Транспорт: UDP, TCP, или TURNS/TLS over TCP.
	var turnConn net.PacketConn
	proto := endpoint.Proto

	if endpoint.UseUDP {
		resolved, err := net.ResolveUDPAddr("udp", turnAddr)
		if err != nil {
			return false, fmt.Errorf("резолв TURN: %w", err)
		}
		c, err := net.DialUDP("udp", nil, resolved)
		if err != nil {
			return false, fmt.Errorf("подключение TURN UDP: %w", err)
		}
		defer c.Close()
		_ = c.SetReadBuffer(memoryProfile.socketBufferSize)
		_ = c.SetWriteBuffer(memoryProfile.socketBufferSize)
		turnConn = &connectedUDPConn{c}
	} else {
		var tlsConfig *tls.Config
		if endpoint.UseTLS {
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: strings.Trim(urlhost, "[]"),
			}
		}
		c, dialErr := dialTurnStream(ctx, turnAddr, endpoint.UseTLS, tlsConfig, memoryProfile)
		if dialErr != nil {
			return false, fmt.Errorf("подключение TURN %s: %w", proto, dialErr)
		}
		defer c.Close()
		turnConn = turn.NewSTUNConn(c)
	}
	log.Printf("[СЕССИЯ #%d] TURN %s (scheme=%s transport=%s proto=%s)", sessionID, turnAddr, endpoint.Scheme, endpoint.Transport, proto)
	emitEvent(onEvent, "info", "turn endpoint worker=%d scheme=%s transport=%s proto=%s preferUDP=%t addr=%s", sessionID, endpoint.Scheme, endpoint.Transport, proto, useUDP, turnAddr)
	stats.registerWorkerEndpoint(sessionID, turnAddr)
	defer stats.unregisterWorkerEndpoint(sessionID)

	// TURN Client (pion/turn/v5)
	tc, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnAddr,
		TURNServerAddr: turnAddr,
		Conn:           turnConn,
		Username:       creds.User,
		Password:       creds.Pass,
		LoggerFactory:  &NullLoggerFactory{},
	})
	if err != nil {
		return false, fmt.Errorf("TURN клиент: %w", err)
	}
	defer tc.Close()

	go func() {
		listenErr := listenTURNInbound(turnConn, tc)
		if ctx.Err() == nil && listenErr != nil {
			emitEvent(onEvent, "warn", "TURN inbound loop stopped worker=%d err=%s", sessionID, sanitizeErrForEvent(listenErr))
			// Make a bounded-reader failure terminate this worker promptly. Without
			// closing the transport, Allocate/relay reads could linger until their
			// next timeout with no inbound loop left to service transactions.
			_ = turnConn.Close()
		}
	}()

	emitEvent(onEvent, "info", "allocate start worker=%d proto=%s scheme=%s transport=%s", sessionID, proto, endpoint.Scheme, endpoint.Transport)
	relay, err := tc.Allocate()
	if err != nil {
		errStr := err.Error()
		stunCode, quota := classifyTURNError(err)
		stats.recordAllocateError(quota)
		emitEvent(onEvent, ternaryEventLevel(quota), "allocate error worker=%d quota=%t stunCode=%d err=%s", sessionID, quota, stunCode, sanitizeErrForEvent(err))
		if strings.Contains(errStr, "Quota") || strings.Contains(errStr, "486") {
			return false, fmt.Errorf("TURN квота: %w", err)
		}
		return false, fmt.Errorf("TURN Allocate: %w", err)
	}
	stats.recordAllocateOK(time.Now())
	stats.recordTURNAllocation(roomID, sessionID, creds.User)
	defer relay.Close()
	log.Printf("[СЕССИЯ #%d] Relay: %s", sessionID, relay.LocalAddr())
	emitEvent(onEvent, "info", "allocate ok worker=%d relayAddrPresent=%t", sessionID, relay.LocalAddr() != nil)

	// Pipe для DTLS ↔ TURN relay
	pipeA, pipeB := connutil.AsyncPacketPipe()

	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	// Keepalive goroutine. The loop wakes at the active cadence so a newly
	// active bond reacts promptly, but idle workers emit at most every 30s.
	var sessionWg sync.WaitGroup
	sessionWg.Add(1)
	go func() {
		defer sessionWg.Done()
		t := time.NewTicker(workerKeepaliveActiveInterval)
		defer t.Stop()
		lastKeepalive := time.Now()
		for {
			select {
			case <-sessCtx.Done():
				return
			case now := <-t.C:
				if !workerKeepaliveDue(now, lastKeepalive, stats.workerKeepaliveIntervalAt(now)) {
					continue
				}
				tc.SendBindingRequest()
				lastKeepalive = now
			}
		}
	}()

	// Relay ↔ Pipe proxy
	var relayWg sync.WaitGroup
	relayWg.Add(2)

	stopRelay := context.AfterFunc(sessCtx, func() {
		_ = relay.SetDeadline(time.Now())
		_ = pipeA.SetDeadline(time.Now())
	})
	defer stopRelay()

	// relay → pipeA
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		b := make([]byte, readBufSize)
		for {
			n, _, readErr := relay.ReadFrom(b)
			if readErr != nil {
				return
			}
			if _, writeErr := pipeA.WriteTo(b[:n], peer); writeErr != nil {
				return
			}
		}
	}()

	// pipeA → relay
	go func() {
		defer relayWg.Done()
		defer sessCancel()
		b := make([]byte, readBufSize)
		for {
			n, _, readErr := pipeA.ReadFrom(b)
			if readErr != nil {
				return
			}
			if _, writeErr := relay.WriteTo(b[:n], peer); writeErr != nil {
				return
			}
		}
	}()

	// DTLS с поддержкой Connection ID
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return false, fmt.Errorf("генерация сертификата: %w", err)
	}

	sni := tp.Sni
	if sni == "" {
		sni = "calls.okcdn.ru"
	}

	dtlsCfg := &dtls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(), // client_id support
		ServerName:            sni,
	}

	dtlsConn, err := dtls.Client(pipeB, peer, dtlsCfg)
	if err != nil {
		return false, fmt.Errorf("DTLS клиент: %w", err)
	}
	defer dtlsConn.Close()

	if err := runDTLSHandshakeWithThrottle(sessCtx, sessionID, dtlsConn); err != nil {
		return false, err
	}

	// Cancellation must interrupt Bond BIND negotiation as well as the later
	// proxy loops; otherwise shutdown can wait for the full negotiation timeout.
	stopDTLS := context.AfterFunc(sessCtx, func() {
		_ = dtlsConn.SetDeadline(time.Now())
	})
	defer stopDTLS()

	// Запрос конфига / Bond v2 BIND. Legacy raw GETCONF stays byte-for-byte
	// unchanged when bondV2=false.
	if bondV2 {
		conf, confErr := RequestBondV2Bind(dtlsConn, bondBindPayload{
			DeviceID:    deviceID,
			RunID:       bondID.RunID,
			Token:       bondID.Token,
			Room:        roomID,
			Worker:      sessionID,
			LocalPort:   localPort,
			WantConfig:  getConfig,
			Password:    password,
			LatencyLane: true,
		}, getConfig)
		if confErr != nil {
			emitEvent(onEvent, "error", "bond bind error worker=%d room=%d wantConfig=%t err=%s", sessionID, roomID, getConfig, sanitizeErrForEvent(confErr))
			return false, confErr
		}
		if conf != "" && configCh != nil {
			select {
			case configCh <- conf:
				configDelivered = true
				emitEvent(onEvent, "info", "bond config delivered worker=%d room=%d confLen=%d", sessionID, roomID, len(conf))
			default:
				configDelivered = true
				emitEvent(onEvent, "info", "bond config already-delivered worker=%d room=%d confLen=%d", sessionID, roomID, len(conf))
			}
		}
	} else if getConfig && configCh != nil {
		emitEvent(onEvent, "info", "GETCONF request worker=%d localPort=%s deviceIDLen=%d passwordLen=%d", sessionID, localPort, len(deviceID), len(password))
		conf, confErr := RequestConfig(dtlsConn, localPort, deviceID, password)
		if confErr != nil {
			errStr := confErr.Error()
			emitEvent(onEvent, "error", "GETCONF error worker=%d fatalAuth=%t err=%s", sessionID, strings.Contains(errStr, "FATAL_AUTH"), sanitizeErrForEvent(confErr))
			if strings.Contains(errStr, "FATAL_AUTH") {
				return false, confErr
			}
			log.Printf("[ВОРКЕР #%d] Ошибка конфига: %v", sessionID, confErr)
		} else if conf != "" {
			select {
			case configCh <- conf:
				configDelivered = true
				log.Printf("[ВОРКЕР #%d] Конфиг получен", sessionID)
				emitEvent(onEvent, "info", "GETCONF delivered worker=%d confLen=%d", sessionID, len(conf))
			default:
				configDelivered = true
				log.Printf("[ВОРКЕР #%d] Конфиг уже был доставлен другим воркером", sessionID)
				emitEvent(onEvent, "info", "GETCONF already-delivered worker=%d confLen=%d", sessionID, len(conf))
			}
		} else {
			log.Printf("[ВОРКЕР #%d] Сервер ещё не выдал WireGuard-конфиг, повторим позже", sessionID)
			emitEvent(onEvent, "warn", "GETCONF empty worker=%d", sessionID)
		}
	}

	// READY (Удалено! Передача трафика начинается моментально без подтверждений)
	log.Printf("[ВОРКЕР #%d] [READY] Туннель готов к работе ✓", sessionID)

	// Регистрация в диспетчере
	slot := &WorkerSlot{
		ID:     sessionID,
		RoomID: roomID,
		SendCh: make(chan []byte, memoryProfile.workerSendBuffer),
	}
	d.Register(slot)
	defer d.Unregister(slot)
	// "active" means data-plane usable: DTLS alone is not enough. Count only
	// after successful Bond BIND and dispatcher registration so invalid_bind or
	// startup handshakes never inflate the UI worker numerator.
	atomic.AddInt32(&stats.ActiveConnections, 1)
	defer atomic.AddInt32(&stats.ActiveConnections, -1)

	// Proxy DTLS ↔ Dispatcher. A separate liveness timer watches the last
	// successful inbound frame. This avoids a SetReadDeadline syscall for every
	// data packet while still making the 15-second timeout relative to actual
	// activity (the server heartbeat cadence is five seconds).
	sessionOrigin := time.Now()
	var lastInboundElapsed atomic.Int64
	lastInboundElapsed.Store(0)
	terminalErr := make(chan error, 1)
	var proxyWg sync.WaitGroup
	proxyWg.Add(3)

	// Writer: dispatcher → DTLS
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		ticker := time.NewTicker(workerKeepaliveActiveInterval)
		defer ticker.Stop()
		var lastWriteDeadline time.Time
		lastKeepalive := time.Now()
		for {
			select {
			case <-sessCtx.Done():
				return
			case now := <-ticker.C:
				if !workerKeepaliveDue(now, lastKeepalive, stats.workerKeepaliveIntervalAt(now)) {
					continue
				}
				_ = dtlsConn.SetWriteDeadline(now.Add(5 * time.Second))
				lastWriteDeadline = now
				lastKeepalive = now
				wake := []byte("WAKEUP")
				if bondV2 {
					if encoded, encErr := bondFramePayload(bondFrameKeepalive, nil); encErr == nil {
						wake = encoded
					}
				}
				if _, writeErr := dtlsConn.Write(wake); writeErr != nil {
					log.Printf("[ВОРКЕР #%d] Ошибка Writer (WAKEUP): %v", sessionID, writeErr)
					return
				}
			case pkt, ok := <-slot.SendCh:
				if !ok {
					return
				}
				now := time.Now()
				if now.Sub(lastWriteDeadline) > 5*time.Second {
					_ = dtlsConn.SetWriteDeadline(now.Add(10 * time.Second))
					lastWriteDeadline = now
				}
				if _, writeErr := dtlsConn.Write(pkt); writeErr != nil {
					log.Printf("[ВОРКЕР #%d] Ошибка Writer (Payload): %v", sessionID, writeErr)
					return
				}
			}
		}
	}()

	// Inbound liveness watchdog. When the physical path disappears, UDP writes
	// can continue to appear successful, so the missing server heartbeat is the
	// authoritative signal that this worker must return to the group retry loop.
	go func() {
		defer proxyWg.Done()
		timer := time.NewTimer(sessionReadTimeout)
		defer timer.Stop()
		for {
			select {
			case <-sessCtx.Done():
				return
			case now := <-timer.C:
				nowElapsed := now.Sub(sessionOrigin)
				observed := time.Duration(lastInboundElapsed.Load())
				remaining := sessionReadTimeoutRemaining(observed, nowElapsed)
				if remaining > 0 {
					timer.Reset(remaining)
					continue
				}
				// Re-check once after deciding to expire so a frame processed
				// concurrently with the timer gets its full 15-second window.
				latest := time.Duration(lastInboundElapsed.Load())
				if latest != observed {
					timer.Reset(sessionReadTimeoutRemaining(latest, time.Since(sessionOrigin)))
					continue
				}
				log.Printf("[ВОРКЕР #%d] Таймаут Reader — закрываем сессию для автоматического retry", sessionID)
				emitEvent(onEvent, "warn", "session inbound timeout worker=%d idle_ms=%d", sessionID, nowElapsed.Milliseconds()-observed.Milliseconds())
				select {
				case terminalErr <- errSessionReadTimeout:
				default:
				}
				sessCancel()
				return
			}
		}
	}()

	// Reader: DTLS → dispatcher
	go func() {
		defer proxyWg.Done()
		defer sessCancel()
		b := make([]byte, 2000)
		for {
			n, readErr := dtlsConn.Read(b)
			if readErr != nil {
				if sessCtx.Err() != nil {
					// Контекст был отменен (ротация/уничтожение батча)
					return
				}
				log.Printf("[ВОРКЕР #%d] Ошибка Reader: %v", sessionID, readErr)
				return
			}
			lastInboundElapsed.Store(time.Since(sessionOrigin).Nanoseconds())

			if n == 6 && string(b[:6]) == "WAKEUP" {
				continue
			}

			pkt := make([]byte, n)
			copy(pkt, b[:n])
			if !enqueueSessionReturn(sessCtx, d, stats, roomID, sessionID, pkt, bondV2) {
				return
			}
		}
	}()

	proxyWg.Wait()
	sessCancel()
	relayWg.Wait()
	sessionWg.Wait()
	_ = pipeA.Close()
	_ = pipeB.Close()
	log.Printf("[СЕССИЯ #%d] Завершена", sessionID)
	select {
	case terminal := <-terminalErr:
		return configDelivered, terminal
	default:
	}
	return configDelivered, nil
}
