// Package jazz is the SaluteJazz engine: WebSocket signaling + two
// PeerConnections (subscriber/publisher) and a "_reliable" datachannel that
// carries tunnel bytes wrapped in the Jazz DataPacket framing.
//
// Ported from the olcrtc-for-olcbox fork's internal/provider/jazz to the
// auth.Provider + engine.Session split used by the vendored olc tree.
package jazz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"

	"github.com/funnybones69/tamizdat/vks/olc/core/engine"
)

const (
	maxDataChannelMessageSize = 12288
	sendDelay                 = 2 * time.Millisecond
	dataChannelLabel          = "_reliable"
)

var (
	errNotReady  = errors.New("jazz: datachannel not ready")
	errNoSession = errors.New("jazz: no session")
)

// Session is one Jazz room participant connection.
type Session struct {
	cfg engine.Config

	ws     *websocket.Conn
	wsMu   sync.Mutex
	pcSub  *webrtc.PeerConnection
	pcPub  *webrtc.PeerConnection
	dc     *webrtc.DataChannel
	groupID string
	epoch  *epochState

	reconnectCb atomic.Value // func()
	shouldConn  atomic.Value // func() bool
	endedCb     atomic.Value // func(string)
	reconnectCh chan struct{}
	closeCh     chan struct{}
	closed      atomic.Bool
	sendQueue   chan []byte
	sessionDone chan struct{}
	wg          sync.WaitGroup
}

// New creates a Jazz engine session.
func New(ctx context.Context, cfg engine.Config) (engine.Session, error) {
	return &Session{
		cfg:         cfg,
		epoch:       newEpochState(cfg.RequireTargetedPeer),
		reconnectCh: make(chan struct{}, 1),
		closeCh:     make(chan struct{}),
		sendQueue:   make(chan []byte, 5000),
		sessionDone: make(chan struct{}),
	}, nil
}

func init() { engine.Register("jazz", New) }

var _ engine.PeerResetter = (*Session)(nil)

// Connect dials the signaling socket and establishes the datachannel.
func (s *Session) Connect(ctx context.Context) error {
	roomID := s.cfg.Extra["roomID"]
	password := s.cfg.Extra["password"]
	if roomID == "" {
		return errNoSession
	}

	settingEngine := webrtc.SettingEngine{}
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))
	wcfg := webrtc.Configuration{SDPSemantics: webrtc.SDPSemanticsUnifiedPlan, BundlePolicy: webrtc.BundlePolicyMaxBundle}

	var err error
	if s.pcSub, err = api.NewPeerConnection(wcfg); err != nil {
		return fmt.Errorf("subscriber pc: %w", err)
	}
	if s.pcPub, err = api.NewPeerConnection(wcfg); err != nil {
		return fmt.Errorf("publisher pc: %w", err)
	}
	ordered := true
	if s.dc, err = s.pcPub.CreateDataChannel(dataChannelLabel, &webrtc.DataChannelInit{Ordered: &ordered}); err != nil {
		return fmt.Errorf("datachannel: %w", err)
	}

	dcReady := make(chan struct{})
	s.setupDC(dcReady)

	if err := s.dialWS(ctx); err != nil {
		return err
	}
	if err := s.sendJoin(roomID, password); err != nil {
		return err
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.readLoop() }()

	select {
	case <-dcReady:
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.pingLoop() }()
		return nil
	case <-time.After(30 * time.Second):
		return errors.New("jazz: datachannel open timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// pingLoop sends the app-level rtc:ping keepalive every 5s (the SFU drops
// the WS after its pingTimeout=15s without one) and answers server pings.
func (s *Session) pingLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
			s.wsMu.Lock()
			if s.ws != nil {
				_ = s.ws.WriteJSON(map[string]any{
					"roomId": s.cfg.Extra["roomID"], "event": "media-in", "groupId": s.groupID,
					"requestId": uuid.New().String(),
					"payload": map[string]any{
						"method":  "rtc:ping",
						"pingReq": map[string]any{"timestamp": time.Now().UnixMilli(), "rtt": 0},
					},
				})
			}
			s.wsMu.Unlock()
		}
	}
}

// pong replies to a server-initiated rtc:ping.
func (s *Session) pong() {
	s.wsMu.Lock()
	if s.ws != nil {
		_ = s.ws.WriteJSON(map[string]any{
			"roomId": s.cfg.Extra["roomID"], "event": "media-in", "groupId": s.groupID,
			"requestId": uuid.New().String(),
			"payload": map[string]any{
				"method":  "rtc:pong",
				"pingRes": map[string]any{"timestamp": time.Now().UnixMilli(), "rtt": 0},
			},
		})
	}
	s.wsMu.Unlock()
}

func (s *Session) dialWS(ctx context.Context) error {
	d := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	ws, resp, err := d.DialContext(ctx, s.cfg.URL, nil)
	if err != nil {
		return fmt.Errorf("jazz ws dial: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	s.ws = ws
	s.ws.SetPongHandler(func(string) error {
		_ = s.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	_ = s.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	return nil
}

func (s *Session) sendJoin(roomID, password string) error {
	msg := map[string]any{
		"roomId":    roomID,
		"event":     "join",
		"requestId": uuid.New().String(),
		"payload": map[string]any{
			"password":        password,
			"participantName": s.cfg.Name,
			"supportedFeatures": map[string]any{
				"attachedRooms": true, "sessionGroups": true, "transcription": true,
			},
			"isSilent": false,
		},
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	return s.ws.WriteJSON(msg)
}

func (s *Session) setupDC(dcReady chan struct{}) {
	s.dc.OnOpen(func() {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.sendLoop() }()
		close(dcReady)
	})
	s.dc.OnClose(func() { s.queueReconnect() })
	s.dc.OnMessage(func(m webrtc.DataChannelMessage) { s.deliver(m.Data) })
	s.pcSub.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() != dataChannelLabel {
			return
		}
		dc.OnMessage(func(m webrtc.DataChannelMessage) { s.deliver(m.Data) })
	})
}

func (s *Session) handleMedia(payload map[string]any) {
	method, _ := payload["method"].(string)
	switch method {
	case "rtc:config":
		s.applyICE(payload)
	case "rtc:offer":
		s.handleSubOffer(payload)
	case "rtc:answer":
		s.handlePubAnswer(payload)
	case "rtc:ice":
		s.handleICE(payload)
	case "rtc:ping":
		s.pong()
	case "rtc:pong":
		// keepalive reply — nothing to do
	}
}
func (s *Session) deliver(data []byte) {
	payload, ok := DecodeDataPacket(data)
	if !ok {
		payload = data
	}
	body, _, ok := s.epoch.accept("", payload)
	if !ok || len(body) == 0 {
		return // not a peer-addressed frame (other clients' broadcasts etc.)
	}
	if s.cfg.OnData != nil {
		s.cfg.OnData(body)
	}
}

func (s *Session) readLoop() {
	for {
		var msg map[string]any
		if err := s.ws.ReadJSON(&msg); err != nil {
			s.queueReconnect()
			return
		}
		s.wsMu.Lock()
		_ = s.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		s.wsMu.Unlock()
		event, _ := msg["event"].(string)
		payload, _ := msg["payload"].(map[string]any)
		switch event {
		case "join-response":
			if g, ok := payload["participantGroup"].(map[string]any); ok {
				s.groupID, _ = g["groupId"].(string)
			}
		case "media-out":
			s.handleMedia(payload)
		}
	}
}


func (s *Session) applyICE(payload map[string]any) {
	cfg, _ := payload["configuration"].(map[string]any)
	servers, _ := cfg["iceServers"].([]any)
	var ice []webrtc.ICEServer
	for _, srv := range servers {
		m, _ := srv.(map[string]any)
		var urls []string
		if us, ok := m["urls"].([]any); ok {
			for _, u := range us {
				if us2, ok := u.(string); ok && us2 != "" {
					urls = append(urls, us2)
				}
			}
		}
		if len(urls) > 0 {
			ice = append(ice, webrtc.ICEServer{URLs: urls,
				Username: strOf(m["username"]), Credential: strOf(m["credential"])})
		}
	}
	if len(ice) > 0 {
		c := webrtc.Configuration{ICEServers: ice, SDPSemantics: webrtc.SDPSemanticsUnifiedPlan, BundlePolicy: webrtc.BundlePolicyMaxBundle}
		_ = s.pcSub.SetConfiguration(c)
		_ = s.pcPub.SetConfiguration(c)
	}
}

func (s *Session) handleSubOffer(payload map[string]any) {
	desc, _ := payload["description"].(map[string]any)
	sdp := strOf(desc["sdp"])
	if err := s.pcSub.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
		return
	}
	answer, err := s.pcSub.CreateAnswer(nil)
	if err != nil {
		return
	}
	if err := s.pcSub.SetLocalDescription(answer); err != nil {
		return
	}
	s.mediaIn("rtc:answer", answer.SDP)
	time.Sleep(300 * time.Millisecond)
	s.sendPubOffer()
}

func (s *Session) sendPubOffer() {
	offer, err := s.pcPub.CreateOffer(nil)
	if err != nil {
		return
	}
	if err := s.pcPub.SetLocalDescription(offer); err != nil {
		return
	}
	s.mediaIn("rtc:offer", offer.SDP)
}

func (s *Session) handlePubAnswer(payload map[string]any) {
	desc, _ := payload["description"].(map[string]any)
	_ = s.pcPub.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: strOf(desc["sdp"])})
}

func (s *Session) handleICE(payload map[string]any) {
	cands, _ := payload["rtcIceCandidates"].([]any)
	for _, c := range cands {
		m, _ := c.(map[string]any)
		init := webrtc.ICECandidateInit{Candidate: strOf(m["candidate"])}
		if mid, ok := m["sdpMid"].(string); ok {
			init.SDPMid = &mid
		}
		if idx, ok := m["sdpMLineIndex"].(float64); ok {
			v := uint16(idx) //nolint:gosec
			init.SDPMLineIndex = &v
		}
		switch strOf(m["target"]) {
		case "SUBSCRIBER":
			_ = s.pcSub.AddICECandidate(init)
		case "PUBLISHER":
			_ = s.pcPub.AddICECandidate(init)
		}
	}
}

func (s *Session) mediaIn(method, sdp string) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	_ = s.ws.WriteJSON(map[string]any{
		"roomId": s.cfg.Extra["roomID"], "event": "media-in", "groupId": s.groupID,
		"requestId": uuid.New().String(),
		"payload": map[string]any{"method": method,
			"description": map[string]any{"type": descType(method), "sdp": sdp}},
	})
}

func descType(method string) string {
	if method == "rtc:answer" {
		return "answer"
	}
	return "offer"
}

// Send queues bytes for the datachannel.
func (s *Session) Send(data []byte) error {
	if s.dc == nil || s.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return errNotReady
	}
	select {
	case s.sendQueue <- data:
		return nil
	case <-time.After(50 * time.Millisecond):
		return errNotReady
	}
}

func (s *Session) sendLoop() {
	for {
		select {
		case <-s.sessionDone:
			return
		case <-s.closeCh:
			return
		case data := <-s.sendQueue:
			if len(data) > maxDataChannelMessageSize {
				continue
			}
			if err := s.dc.Send(EncodeDataPacket(s.epoch.encodeFrame(data, s.epoch.targetFor("")))); err != nil {
				s.queueReconnect()
				return
			}
			time.Sleep(sendDelay)
		}
	}
}

// ResetPeer clears the latched peer binding so a reconnecting peer carrying a
// fresh epoch can be accepted again. The transport calls this when the upper
// layer resets the peer (control-stream failure in server accept, liveness
// reconnect); without it the latch sticks on a dead epoch and every newcomer
// stays dropped until the process restarts.
func (s *Session) ResetPeer() {
	if s.epoch != nil {
		s.epoch.reset()
	}
}

// Close terminates the session.
func (s *Session) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.closeCh)
	if s.dc != nil {
		_ = s.dc.Close()
	}
	if s.pcPub != nil {
		_ = s.pcPub.Close()
	}
	if s.pcSub != nil {
		_ = s.pcSub.Close()
	}
	if s.ws != nil {
		s.wsMu.Lock()
		_ = s.ws.Close()
		s.wsMu.Unlock()
	}
	s.ended("closed")
	return nil
}

// SetReconnectCallback registers the reconnect notifier.
func (s *Session) SetReconnectCallback(cb func()) { s.reconnectCb.Store(cb) }

// SetShouldReconnect registers the reconnect policy.
func (s *Session) SetShouldReconnect(fn func() bool) { s.shouldConn.Store(fn) }

// SetEndedCallback registers the termination notifier.
func (s *Session) SetEndedCallback(cb func(string)) { s.endedCb.Store(cb) }

// WatchConnection blocks until the session ends or ctx is cancelled.
func (s *Session) WatchConnection(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-s.closeCh:
	}
}

// CanSend reports whether the datachannel is open and the queue has room.
func (s *Session) CanSend() bool {
	return s.dc != nil && s.dc.ReadyState() == webrtc.DataChannelStateOpen && len(s.sendQueue) < 4000
}

// SubscriberCanSend reports whether the subscriber PC is connected.
func (s *Session) SubscriberCanSend() bool {
	return s.pcSub != nil && s.pcSub.ConnectionState() == webrtc.PeerConnectionStateConnected
}

// GetBufferedAmount returns the datachannel buffered bytes.
func (s *Session) GetBufferedAmount() uint64 {
	if s.dc != nil {
		return s.dc.BufferedAmount()
	}
	return 0
}

// Reconnect tears down and re-establishes the SFU connection.
func (s *Session) Reconnect(reason string) { s.queueReconnect() }

func (s *Session) queueReconnect() {
	if s.closed.Load() {
		return
	}
	if fn, ok := s.shouldConn.Load().(func() bool); ok && fn != nil && !fn() {
		return
	}
	select {
	case s.reconnectCh <- struct{}{}:
	default:
	}
	if cb, ok := s.reconnectCb.Load().(func()); ok && cb != nil {
		cb()
	}
}

func (s *Session) ended(reason string) {
	if cb, ok := s.endedCb.Load().(func(string)); ok && cb != nil {
		cb(reason)
	}
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}
