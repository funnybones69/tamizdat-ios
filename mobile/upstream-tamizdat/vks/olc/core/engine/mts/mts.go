// Package mts is the MTS Link engine: SDP-over-HTTPS signaling against the
// custom "odin" SFU, one PeerConnection, and a datachannel for tunnel bytes.
//
// Protocol (verified live by MTSReverse, 2026-09-18):
//
//	POST /rtc/room/{roomId}/join?userId&joinToken&publishToken&userName...
//	     body = SDP offer (Content-Type: application/sdp) -> SDP answer text
//	peerId = "s=<id>" line of the answer
//	POST /rtc/peer/{peerId}/update?publishToken... (renegotiation)
//	POST /rtc/peer/{peerId}/audio|video (enable)
//	GET  /rtc/room/{roomId}/ice-settings (TURN webinar/odin)
//	non-trickle ICE: full offer/answer exchange, SFU host candidates inline.
package mts

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"

	"github.com/funnybones69/tamizdat/vks/olc/core/engine"
)

const (
	dataChannelLabel          = "test" // matches the web client's channel: unordered, maxRetransmits 0
	joinTimeout               = 30 * time.Second
	maxDataChannelMessageSize = 12288
)

var (
	errNotReady  = errors.New("mts: datachannel not ready")
	errNoSession = errors.New("mts: no session")
	sdpPeerRe    = regexp.MustCompile(`(?m)^s=([^\r\n]+)`)
)

// Session is one MTS Link room participant connection.
type Session struct {
	cfg          engine.Config
	client       *http.Client
	playerClient *http.Client // shorter timeout keeps failed negotiations cycling fast
	dc           *webrtc.DataChannel
	pc           *webrtc.PeerConnection
	pcSubs       []*webrtc.PeerConnection // per-stream player connections (subscribers)
	subMu        sync.Mutex
	audioTrack   *webrtc.TrackLocalStaticRTP
	peerID       string
	roomID       string
	pubToken     string

	reconnectCb atomic.Value
	shouldConn  atomic.Value
	endedCb     atomic.Value
	closeCh     chan struct{}
	closed      atomic.Bool
	sendQueue   chan []byte
	wg          sync.WaitGroup
	epoch       *epochState // peer-addressing epochs (SFU relays frames to every participant)

	engine.VideoTrackState // local video tracks + remote-track handler (vp8channel transport)
}

// New creates an MTS engine session.
func New(ctx context.Context, cfg engine.Config) (engine.Session, error) {
	return &Session{
		cfg:          cfg,
		client:       &http.Client{Timeout: 20 * time.Second},
		playerClient: &http.Client{Timeout: 9 * time.Second},
		closeCh:      make(chan struct{}),
		sendQueue:    make(chan []byte, 5000),
		epoch:        newEpochState(cfg.RequireTargetedPeer),
	}, nil
}

func init() { engine.Register("mts", New) }

// rtcBase normalizes the rtcUrl (//sfu.mts-link.ru/event/{esid}/rtc).
func rtcBase(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "/event/"); i >= 0 {
		raw = raw[:i]
	}
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	if raw == "" {
		return "https://sfu.mts-link.ru"
	}
	return strings.TrimSuffix(raw, "/")
}

// Connect joins the room and establishes the datachannel.
func (s *Session) Connect(ctx context.Context) error {
	if s.epoch != nil {
		s.epoch.reset()
	}
	roomID := s.cfg.Extra["eventSessionID"]
	userID := s.cfg.Extra["userID"]
	pubToken := s.cfg.Extra["publishToken"]
	joinToken := s.cfg.Extra["joinToken"]
	if roomID == "" {
		return errNoSession
	}
	s.roomID, s.pubToken = roomID, pubToken
	base := rtcBase(s.cfg.URL)

	// ICE servers from ice-settings (TURN webinar/odin).
	ice := s.fetchICEServers(base, roomID)

	pcCfg := webrtc.Configuration{ICEServers: ice, SDPSemantics: webrtc.SDPSemanticsUnifiedPlan}
	api := webrtc.NewAPI()
	if os.Getenv("MTS_TRACE") == "1" {
		se := webrtc.SettingEngine{}
		lf := logging.NewDefaultLoggerFactory()
		lf.DefaultLogLevel = logging.LogLevelTrace
		se.LoggerFactory = lf
		api = webrtc.NewAPI(webrtc.WithSettingEngine(se))
	}
	var err error
	if s.pc, err = api.NewPeerConnection(pcCfg); err != nil {
		return fmt.Errorf("mts pc: %w", err)
	}
	// Attach any local video tracks (vp8channel transport) before the offer
	// so the SDP carries the video m-line, and register the remote-track
	// handler so the peer's video surfaces to the transport.
	s.RangeVideoTracks(func(track webrtc.TrackLocal, _ bool) {
		sender, addErr := s.pc.AddTrack(track)
		if addErr != nil {
			log.Printf("[mts] add video track: %v", addErr)
			return
		}
		go func() {
			buf := make([]byte, 1500)
			for {
				if _, _, rtcpErr := sender.Read(buf); rtcpErr != nil {
					return
				}
			}
		}()
		log.Printf("[mts] video track attached")
	})
	if h := s.VideoTrackHandler(); h != nil {
		s.pc.OnTrack(h)
		log.Printf("[mts] remote video handler registered")
	}
	s.pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("[mts] PC state: %v", state)
	})
	s.pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("[mts] ICE state: %v", state)
	})

	dcReady := make(chan struct{})
	// Match the web client's channel: unordered, maxRetransmits 0.
	unordered := false
	maxRetr := uint16(0)
	if s.dc, err = s.pc.CreateDataChannel(dataChannelLabel, &webrtc.DataChannelInit{Ordered: &unordered, MaxRetransmits: &maxRetr}); err != nil {
		return fmt.Errorf("mts datachannel: %w", err)
	}
	log.Printf("[mts] dc created label=%s", dataChannelLabel)
	// Watch for the SFU opening its own channel (legacy type-1 DCEP OPEN):
	// the odin SFU is the DCEP opener on some paths; pion surfaces it here.
	s.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		log.Printf("[mts] OnDataChannel: label=%q ready=%v", dc.Label(), dc.ReadyState())
		dc.OnOpen(func() {
			log.Printf("[mts] SFU-opened channel %q open — switching", dc.Label())
			if s.dc == nil || s.dc.ReadyState() != webrtc.DataChannelStateOpen {
				s.dc = dc
				s.wg.Add(1)
				go func() { defer s.wg.Done(); s.sendLoop() }()
			}
			s.wg.Add(1)
			go func() { defer s.wg.Done(); s.dcKeepalive() }()
			select {
			case <-dcReady:
			default:
				close(dcReady)
			}
		})
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			s.deliver(m.Data)
		})
	})

	// The web client joins with audio m-lines; the SFU's datachannel handling
	// appears to depend on a media-bundled offer. Add a silent opus track.
	if err := s.addSilentAudio(); err != nil {
		return fmt.Errorf("mts audio track: %w", err)
	}
	s.dc.OnOpen(func() {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.sendLoop() }()
		log.Printf("[mts] sendLoop started")
		close(dcReady)
	})
	s.dc.OnClose(func() {
		log.Printf("[mts] dc OnClose FIRED - queuing reconnect")
		s.queueReconnect()
	})
	s.dc.OnMessage(func(m webrtc.DataChannelMessage) {
		log.Printf("[mts] OnMessage: len=%d first 8=%x", len(m.Data), m.Data[:min(8, len(m.Data))])
		s.deliver(m.Data)
	})

	// ICE gathering (non-trickle: wait for all candidates).
	gatherDone := make(chan struct{})
	s.pc.OnICEGatheringStateChange(func(state webrtc.ICEGatheringState) {
		if state == webrtc.ICEGatheringStateComplete {
			select {
			case <-gatherDone:
			default:
				close(gatherDone)
			}
		}
	})

	offer, err := s.pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("mts offer: %w", err)
	}
	if err := s.pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("mts local desc: %w", err)
	}

	select {
	case <-gatherDone:
	case <-time.After(5 * time.Second): // proceed with what we have
	}

	// Join: POST the full SDP offer, read the SDP answer.
	answerSDP, err := s.join(base, roomID, userID, pubToken, joinToken, s.pc.LocalDescription().SDP)
	if err != nil {
		return err
	}
	s.peerID = peerIDFromSDP(answerSDP)
	hasApp := strings.Contains(answerSDP, "m=application")
	log.Printf("[mts] answer SDP: len=%d app_mline=%v peerID=%q publicKey=%q", len(answerSDP), hasApp, s.peerID, s.cfg.Extra["publicKey"])
	if os.Getenv("MTS_DEBUG_SDP") == "1" {
		log.Printf("[mts] ANSWER SDP:\n%s\n[mts] OFFER SDP:\n%s", answerSDP, s.pc.LocalDescription().SDP)
	}
	if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answerSDP}); err != nil {
		return fmt.Errorf("mts remote desc: %w", err)
	}

	// Activate the peer on the SFU: enable audio/video via the REST API the
	// browser calls after join (spec §2). Without this the SFU leaves the
	// session in a pre-activated state and never completes the DCEP ACK.
	if err := s.activatePeer(base); err != nil {
		log.Printf("[mts] peer activation failed (continuing): %v", err)
	}
	// Publish update: publishToken marks the peer as a send-capable participant.
	// The SFU only relays data to participants it considers publish-active.
	if pubToken := s.cfg.Extra["publishToken"]; pubToken != "" {
		if err := s.requestPublishUpdate(base); err != nil {
			log.Printf("[mts] publish update failed (continuing): %v", err)
		}
	}
	// Automatic peer discovery: the odin SFU relays a peer's media only to
	// subscribers, so without a player connection per foreign stream the
	// tunnel data (SEI in H264 video) never crosses between the peers. Poll
	// the conference list and subscribe to every NEW foreign publicKey — the
	// on-demand server usually joins before its client, so the initial join
	// often sees zero other streams and the client's stream must be picked
	// up here afterwards.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.discoverAndSubscribe(ctx, base)
	}()
	// Subscriber path: odin forwards other participants' media only through
	// per-stream player connections. Subscriptions run in the background so
	// slow SFU negotiations never block Connect's deadline; each configured
	// stream name opens one player PC feeding the track handler.
	if streams := s.streamsToSubscribe(); len(streams) > 0 {
		// Players negotiate in parallel (the SFU answers in seconds but
		// refuses some) and Connect waits for them up to a bound: the tunnel
		// handshake that follows needs both sides already reading their
		// players, so subscriptions must land before Connect returns while
		// still never stretching its deadline.
		var wg sync.WaitGroup
		for _, stream := range streams {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				if err := s.subscribePlayer(ctx, base, roomID, name); err != nil {
					log.Printf("[mts] player subscribe %s failed (continuing): %v", name, err)
				}
			}(stream)
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
			log.Printf("[mts] player subscriptions done (%d streams)", len(streams))
		case <-time.After(12 * time.Second):
			log.Printf("[mts] player subscriptions still negotiating after 12s; continuing")
		}
	}

	select {
	case <-dcReady:
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.dcKeepalive() }()
		return nil
	case <-time.After(joinTimeout):
		// Diagnostic: the odin SFU never ACKs our DCEP OPEN in this state —
		// its 6-byte frame lands as PPI=DATA on stream 0 (unparsed). Dump
		// the raw frame so we can see what the SFU is really saying.
		dumpRawStream0()
		return errors.New("mts: datachannel open timeout")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) fetchICEServers(base, roomID string) []webrtc.ICEServer {
	req, _ := http.NewRequest(http.MethodGet, base+"/rtc/room/"+roomID+"/ice-settings", nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out struct {
		IceServers []struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		} `json:"iceServers"`
	}
	if err := jsonDecode(resp.Body, &out); err != nil {
		return nil
	}
	var ice []webrtc.ICEServer
	for _, srv := range out.IceServers {
		if len(srv.URLs) > 0 {
			ice = append(ice, webrtc.ICEServer{URLs: srv.URLs, Username: srv.Username, Credential: srv.Credential})
		}
	}
	return ice
}

func (s *Session) join(base, roomID, userID, pubToken, joinToken, offerSDP string) (string, error) {
	q := url.Values{}
	q.Set("userId", userID)
	q.Set("userName", s.cfg.Name)
	if joinToken != "" {
		q.Set("joinToken", joinToken)
	}
	if pubToken != "" {
		q.Set("publishToken", pubToken)
	}
	q.Set("svcMode", "")
	q.Set("twcc", "")
	q.Set("useSimulcast", "false")
	u := base + "/rtc/room/" + roomID + "/join?" + q.Encode()
	log.Printf("[mts] join url: %s", u[:min(120, len(u))])
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(offerSDP))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/sdp")
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("mts join: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("mts join: status %d %.200s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func peerIDFromSDP(sdp string) string {
	if m := sdpPeerRe.FindStringSubmatch(sdp); len(m) > 1 {
		return m[1]
	}
	return ""
}

// streamsToSubscribe resolves which published streams to subscribe to:
// MTS_STREAM_NAME holds a comma-separated list (player names, public keys or
// switcher slot ids). Empty disables the subscriber path.
func (s *Session) streamsToSubscribe() []string {
	raw := strings.TrimSpace(os.Getenv("MTS_STREAM_NAME"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// discoverAndSubscribe polls the conference roster and opens a player
// connection for every NEW foreign public key. The odin SFU relays a
// peer's media only to explicit subscribers, so this is what makes the
// tunnel data (SEI in H264 video) actually cross between two engine peers.
// The poll handles late joiners: the on-demand server usually enters the
// room before its client, so the client's stream appears only later.
func (s *Session) discoverAndSubscribe(ctx context.Context, base string) {
	// Bind to the session lifetime, not the caller's Connect ctx: that ctx
	// is typically cancelled right after Connect returns, which silently
	// killed this loop before it ever ticked (verified live).
	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-s.closeCh:
			cancel()
		case <-sctx.Done():
		}
	}()
	own := s.cfg.Extra["publicKey"]
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	subscribed := map[string]bool{}
	for {
		select {
		case <-s.closeCh:
			return
		case <-sctx.Done():
			return
		case <-ticker.C:
		}
		keys, err := s.listConferencePublicKeys()
		if err != nil {
			log.Printf("[mts] discovery: list conferences: %v", err)
			continue
		}
		for _, key := range keys {
			if key == "" || key == own || subscribed[key] {
				continue
			}
			subscribed[key] = true
			log.Printf("[mts] discovery: subscribing to foreign stream %s", key)
			if err := s.subscribePlayer(sctx, base, s.roomID, key); err != nil {
				log.Printf("[mts] discovery: player subscribe %s failed (will not retry): %v", key, err)
			} else {
				log.Printf("[mts] discovery: player subscribed to %s", key)
			}
		}
	}
}
// session whose cookie header the auth provider passed via Extra.
func (s *Session) listConferencePublicKeys() ([]string, error) {
	esid := s.cfg.Extra["eventSessionID"]
	if esid == "" {
		return nil, errors.New("no eventSessionID")
	}
	cookieHdr := s.cfg.Extra["cookieHeader"]
	if cookieHdr == "" {
		return nil, errors.New("no cookieHeader (auth too old?)")
	}
	u := "https://my.mts-link.ru/api/eventsessions/" + url.PathEscape(esid) + "/conferences"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", cookieHdr)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("conferences list: status %d", resp.StatusCode)
	}
	var raw struct {
		Data []struct {
			PublicKey string `json:"publicKey"`
		} `json:"data"`
		Embedded []struct {
			PublicKey string `json:"publicKey"`
		} `json:"_embedded"`
	}
	keys := make([]string, 0, 8)
	// The API answers either {data:[...]} / {_embedded:[...]} or a BARE
	// array (verified live); decode both without failing on either shape.
	if err := json.Unmarshal(b, &raw); err == nil {
		for _, c := range raw.Data {
			keys = append(keys, c.PublicKey)
		}
		for _, c := range raw.Embedded {
			keys = append(keys, c.PublicKey)
		}
	}
	if len(keys) == 0 {
		var arr []struct {
			PublicKey string `json:"publicKey"`
		}
		if err := json.Unmarshal(b, &arr); err == nil {
			for _, c := range arr {
				keys = append(keys, c.PublicKey)
			}
		} else {
			return nil, fmt.Errorf("conferences decode: %w", err)
		}
	}
	return keys, nil
}

// subscribePlayer opens the odin per-stream player connection: a recvonly
// H264 PeerConnection negotiated via POST /rtc/room/{roomID}/stream/{name}/player.
// Remote video surfaces through the registered track handler.
func (s *Session) subscribePlayer(ctx context.Context, base, roomID, stream string) error {
	ice := s.fetchICEServers(base, roomID)
	api := webrtc.NewAPI()
	pc, err := api.NewPeerConnection(webrtc.Configuration{ICEServers: ice, SDPSemantics: webrtc.SDPSemanticsUnifiedPlan})
	if err != nil {
		return fmt.Errorf("player pc: %w", err)
	}
	if h := s.VideoTrackHandler(); h != nil {
		pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			log.Printf("[mts] player remote track: kind=%s codec=%s ssrc=%d stream=%s", track.Kind(), track.Codec().MimeType, track.SSRC(), track.StreamID())
			h(track, receiver)
		})
	}
	if _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		_ = pc.Close()
		return fmt.Errorf("player transceiver: %w", err)
	}

	gather := make(chan struct{})
	pc.OnICEGatheringStateChange(func(st webrtc.ICEGatheringState) {
		if st == webrtc.ICEGatheringStateComplete {
			select {
			case <-gather:
			default:
				close(gather)
			}
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("player offer: %w", err)
	}
	if err = pc.SetLocalDescription(offer); err != nil {
		_ = pc.Close()
		return fmt.Errorf("player local desc: %w", err)
	}
	select {
	case <-gather:
	case <-time.After(5 * time.Second):
	}

	q := url.Values{}
	if uid := s.cfg.Extra["userID"]; uid != "" {
		q.Set("userId", uid)
	}
	if jt := s.cfg.Extra["joinToken"]; jt != "" {
		q.Set("joinToken", jt)
	}
	q.Set("svcMode", "")
	u := base + "/rtc/room/" + roomID + "/stream/" + url.PathEscape(stream) + "/player?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(pc.LocalDescription().SDP))
	if err != nil {
		_ = pc.Close()
		return err
	}
	req.Header.Set("Content-Type", "application/sdp")
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := s.playerClient.Do(req)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("player post: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = pc.Close()
		return fmt.Errorf("player status %d: %s", resp.StatusCode, strings.TrimSpace(string(body))[:min(200, len(body))])
	}
	if err = pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(body)}); err != nil {
		_ = pc.Close()
		return fmt.Errorf("player remote desc: %w", err)
	}
	s.subMu.Lock()
	s.pcSubs = append(s.pcSubs, pc)
	s.subMu.Unlock()
	log.Printf("[mts] player subscribed: stream=%s answer=%d bytes", stream, len(body))
	return nil
}

// requestPublishUpdate posts /rtc/peer/{peerId}/update?publishToken=... so
// the SFU treats the peer as publish-active and relays its data to others.
func (s *Session) requestPublishUpdate(base string) error {
	q := url.Values{"publishToken": []string{s.cfg.Extra["publishToken"]}}
	req, err := http.NewRequest(http.MethodPost, base+"/rtc/peer/"+s.peerID+"/update?"+q.Encode(), strings.NewReader(""))
	if err != nil {
		return err
	}
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("update peer: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	_ = resp.Body.Close()
	log.Printf("[mts] peer update: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	return nil
}

// activatePeer mirrors the browser's post-join REST calls: /audio and /video
// with enabled= form, then /update for renegotiation. Errors are logged but
// non-fatal — some rooms reject guest activation and the DC may still open.
func (s *Session) activatePeer(base string) error {
	form := url.Values{"enabled": []string{"true"}}
	for _, ep := range []string{"audio", "video"} {
		req, err := http.NewRequest(http.MethodPost, base+"/rtc/peer/"+s.peerID+"/"+ep, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Referer", "https://my.mts-link.ru/")
		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("peer %s: %w", ep, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		log.Printf("[mts] peer %s: HTTP %d %s", ep, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// AddVideoTrack implements engine.VideoTrackCapable: the track is stored and
// attached to the peer connection when it exists (Connect attaches early
// registrations itself).
func (s *Session) AddVideoTrack(track webrtc.TrackLocal) error {
	s.StoreVideoTrack(track)
	if s.pc == nil {
		return nil
	}
	if _, err := s.pc.AddTrack(track); err != nil {
		return fmt.Errorf("mts video track: %w", err)
	}
	return nil
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
		case <-s.closeCh:
			return
		case data := <-s.sendQueue:
			if len(data) > maxDataChannelMessageSize {
				continue
			}
			frame := s.epoch.encodeFrame(data, s.epoch.targetFor(""))
			log.Printf("[mts] sendQueue <- %d bytes -> frame %d bytes (epoch=%d)", len(data), len(frame), s.epoch.localEpoch.Load())
			pfx := ""
			if len(frame) > 0 {
				pfx = fmt.Sprintf(" %x", frame[:min(4, len(frame))])
			}
			if err := s.dc.Send(frame); err != nil {
				log.Printf("[mts] dc.Send error: %v", err)
				s.queueReconnect()
				return
			}
			log.Printf("[mts] dc.Send ok %d bytes%s", len(frame), pfx)
		}
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
	if s.pc != nil {
		_ = s.pc.Close()
	}
	s.subMu.Lock()
	for _, pc := range s.pcSubs {
		if pc != nil {
			_ = pc.Close()
		}
	}
	s.subMu.Unlock()
	s.ended("closed")
	return nil
}

func (s *Session) SetReconnectCallback(cb func())    { s.reconnectCb.Store(cb) }
func (s *Session) SetShouldReconnect(fn func() bool) { s.shouldConn.Store(fn) }
func (s *Session) SetEndedCallback(cb func(string))  { s.endedCb.Store(cb) }

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

// SubscriberCanSend mirrors CanSend (single PC).
func (s *Session) SubscriberCanSend() bool { return s.CanSend() }

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
	if cb, ok := s.reconnectCb.Load().(func()); ok && cb != nil {
		cb()
	}
}

func (s *Session) ended(reason string) {
	if cb, ok := s.endedCb.Load().(func(string)); ok && cb != nil {
		cb(reason)
	}
}

// deliver runs the epoch filter on inbound frames. Non-epoch frames (SFU
// protocol messages, other clients' broadcasts) are dropped.
func (s *Session) deliver(data []byte) {
	if len(data) == 0 {
		return
	}
	if s.cfg.OnData != nil {
		// log first 8 bytes raw before epoch filter
		log.Printf("[mts] deliver raw: %d bytes: %x", len(data), data[:min(8, len(data))])
	}
	log.Printf("[mts] deliver ENTER: %d bytes first 12 hex: %x", len(data), data[:min(12, len(data))])
	body, _, ok := s.epoch.accept("", data)
	if !ok || len(body) == 0 {
		log.Printf("[mts] deliver dropped (epoch accept failed)")
		return
	}
	log.Printf("[mts] deliver forwarded %d bytes (epoch accepted)", len(body))
	log.Printf("[mts] deliver -> OnData %d bytes (epoch OK)", len(body))
	if s.cfg.OnData != nil {
		s.cfg.OnData(body)
	}
}

// dumpRawStream0 is a no-op placeholder: raw frame logging happens via the
// OnMessage hook above; kept as a marker for the timeout diagnostic path.
func dumpRawStream0() {}

func jsonDecode(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

// addSilentAudio attaches an opus track and starts an RTP keepalive writer:
// the odin SFU tears the session down (~30s) when no RTP flows, so we emit
// small silence packets at 20ms pacing.
func (s *Session) addSilentAudio() error {
	codec := webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1"}
	track, err := webrtc.NewTrackLocalStaticRTP(codec, "audio0", "stream0")
	if err != nil {
		return err
	}
	if _, err := s.pc.AddTrack(track); err != nil {
		return err
	}
	s.audioTrack = track
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.rtpKeepalive() }()
	return nil
}

// rtpKeepalive writes opus RTP packets carrying low-level noise. The odin
// switcher selects "active" participants by decoded audio level, so a fully
// silent track never gets slotted and its stream is not relayed to others;
// a noise floor keeps the stream perpetually active while staying quiet.
func (s *Session) rtpKeepalive() {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	var seq uint16
	var ts uint32
	var ssrc uint32 = 0x4d54534b // "MTSK"
	payload := make([]byte, 41)
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
			seq++
			ts += 960 // 20ms @ 48kHz
			// TOC 0xFC: CELT fullband 20ms. Random follow-up bytes decode to
			// noise, which gives the SFU a non-zero audio level to rank on.
			payload[0] = 0xFC
			if _, err := rand.Read(payload[1:]); err != nil {
				for i := 1; i < len(payload); i++ {
					payload[i] = byte(i * 37)
				}
			}
			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version: 2, PayloadType: 111, SequenceNumber: seq, Timestamp: ts, SSRC: ssrc,
				},
				Payload: payload,
			}
			if err := s.audioTrack.WriteRTP(pkt); err != nil {
				return
			}
		}
	}
}

// dcKeepalive sends small pings on the datachannel every 5s: the odin SFU
// closes the SCTP association after ~30s of silence even while the
// PeerConnection stays connected (verified: PC/ICE state stays "connected"
// through the teardown cycle).
func (s *Session) dcKeepalive() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	ping := []byte(`{"type":"ping","ts":0}`)
	for {
		select {
		case <-s.closeCh:
			return
		case <-t.C:
			if s.dc == nil || s.dc.ReadyState() != webrtc.DataChannelStateOpen {
				continue
			}
			ping[18] = byte(time.Now().Second()%10 + 48)
			if err := s.dc.Send(ping); err != nil {
				return
			}
		}
	}
}
