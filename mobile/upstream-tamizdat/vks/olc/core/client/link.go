package client

import (
	"context"
	"fmt"
	"time"

	"github.com/xtaci/smux"

	"github.com/funnybones69/tamizdat/vks/olc/core/handshake"
	"github.com/funnybones69/tamizdat/vks/olc/core/logger"
	"github.com/funnybones69/tamizdat/vks/olc/core/muxconn"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
	"github.com/funnybones69/tamizdat/vks/olc/core/tunnelcore"
)

const peerWaitTimeout = handshake.DefaultTimeout

func (c *Client) bringUpLink(ctx context.Context, cfg Config, cancel context.CancelFunc) error {
	// ai-generated: added this lock, held for the whole function. WatchConnection starts below,
	// before the handshake completes, so a mid-handshake reconnect can race this call: handleReconnect
	// takes reconnectMu too, and without serializing here it can install a fresh working session via
	// retryHandshake while this call is still in flight, then get overwritten when this call finally
	// reaches installPairLocked with its own, by-then-stale pair. Safe to hold: every step below is
	// bounded by handshake.DefaultTimeout/peerWaitTimeout (15s each), not unbounded.
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	linkCfg := tunnelcore.BuildTransportConfig(tunnelcore.LinkConfig{
		Provider: cfg.Provider, RoomURL: cfg.RoomURL, Engine: cfg.Engine,
		URL: cfg.URL, Token: cfg.Token, ProviderToken: cfg.ProviderToken,
		ChannelID: cfg.ChannelID, DNSServer: cfg.DNSServer,
		Options: cfg.TransportOptions, Traffic: cfg.Traffic,
	}, tunnelcore.LinkRoleConfig{
		DeviceID: c.deviceID, OnData: c.onData, OnDatagram: c.onDatagram, Resolver: cfg.Resolver,
		RequireTargetedPeer: true,
	})
	link, err := transport.New(ctx, cfg.Transport, linkCfg)
	if err != nil {
		return fmt.Errorf("failed to create link: %w", err)
	}
	c.ln = link
	link.SetEndedCallback(func(reason string) {
		logger.Infof("Client link reported conference end: %s", reason)
		cancel()
	})
	link.SetShouldReconnect(func() bool { return ctx.Err() == nil })
	link.SetReconnectCallback(func() {
		if ctx.Err() == nil {
			c.handleReconnect(ctx, cfg, cancel, reconnectProvider)
		}
	})
	if connectErr := link.Connect(ctx); connectErr != nil {
		return fmt.Errorf("failed to connect link: %w", connectErr)
	}
	// ai-generated: moved this call earlier in the function (was after the
	// handshake block below) and added this comment explaining why.
	// Start watching for reconnect requests now, not after the handshake
	// below succeeds: goolom's DataChannel can close mid-handshake (its
	// publisher-side connection is not as stable as Jitsi's), and
	// onDataChannelClose's queueReconnect() would otherwise queue a request
	// with nobody consuming it yet - a deadlock where the fix (reconnect)
	// waits on the very handshake it needs to unstick.
	c.goTracked(func() { link.WatchConnection(ctx) })
	conn := muxconn.New(link, c.keys)
	controlConn := muxconn.NewControl(link, c.keys)
	// ai-generated: write under sessMu. onData reads c.conn under sessMu.RLock from the transport's
	// delivery goroutine, live from the moment link.Connect() above succeeded; an unlocked write here
	// raced it.
	c.sessMu.Lock()
	c.conn, c.controlConn = conn, controlConn
	c.sessMu.Unlock()
	pair, err := tunnelcore.NewSessionPairWithConns(
		link, conn, controlConn, tunnelcore.ClientRole,
	)
	if err != nil {
		if pair != nil {
			_ = pair.Close()
		}
		return fmt.Errorf("create smux sessions: %w", err)
	}
	control, sessionID, peerID, err := openControlStream(ctx, pair.ControlSession, c.deviceID, c.claims)
	if err != nil {
		_ = pair.Close()
		return fmt.Errorf("handshake: %w", err)
	}
	if err := confirmPeer(link, peerID); err != nil {
		_ = pair.Close()
		return err
	}
	if waitErr := waitForPeer(ctx, link); waitErr != nil {
		_ = pair.Close()
		return waitErr
	}
	logger.Infof("session %s opened (device=%s)", sessionID, c.deviceID)
	c.sessMu.Lock()
	c.installPairLocked(pair)
	c.controlStrm = control
	c.sessionID = sessionID
	c.sessMu.Unlock()
	c.signalSessionReady()
	c.health.RecordSession(sessionID)
	c.startControlLoop(ctx, cfg, cancel, control)
	return nil
}

func waitForPeer(ctx context.Context, link transport.Transport) error {
	waiter, ok := link.(transport.PeerReadyTransport)
	if !ok {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, peerWaitTimeout)
	defer cancel()
	if err := waiter.WaitForPeer(waitCtx); err != nil {
		return fmt.Errorf("wait for peer: %w", err)
	}
	return nil
}

func confirmPeer(link transport.Transport, peerID string) error {
	if peerID == "" {
		return nil
	}
	identity, ok := link.(transport.PeerIdentity)
	if !ok {
		return fmt.Errorf("confirm peer: %w", transport.ErrPeerIdentityUnsupported)
	}
	if err := identity.ConfirmPeer(peerID); err != nil {
		return fmt.Errorf("confirm peer: %w", err)
	}
	return nil
}

func openControlStream(
	ctx context.Context,
	session *smux.Session,
	deviceID string,
	claims map[string]any,
) (*smux.Stream, string, string, error) {
	return openControlStreamTimeout(ctx, session, deviceID, claims, handshake.DefaultTimeout)
}

func openControlStreamTimeout(
	ctx context.Context,
	session *smux.Session,
	deviceID string,
	claims map[string]any,
	timeout time.Duration,
) (*smux.Stream, string, string, error) {
	// The MTS odin SFU tears the datachannel down every ~27s on BOTH peers
	// in phase, so a hello sent at channel-open lands exactly when the
	// server is reinstalling its session and is lost every time. Retrying
	// the handshake on a fresh stream a few seconds later lands inside the
	// server's live window. Providers without the teardown cycle succeed
	// on attempt 1 and never notice.
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return nil, "", "", fmt.Errorf("handshake client: %w", ctx.Err())
			case <-time.After(5 * time.Second):
			}
		}
		stream, sessionID, peerID, err := tryHandshake(ctx, session, deviceID, claims, timeout)
		if err == nil {
			return stream, sessionID, peerID, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, "", "", fmt.Errorf("handshake client: %w", ctx.Err())
		}
		logger.Infof("client: handshake attempt %d failed: %v - retrying on a new stream", attempt, err)
	}
	return nil, "", "", fmt.Errorf("handshake client (3 attempts): %w", lastErr)
}

func tryHandshake(
	ctx context.Context,
	session *smux.Session,
	deviceID string,
	claims map[string]any,
	timeout time.Duration,
) (*smux.Stream, string, string, error) {
	stream, err := session.OpenStream()
	if err != nil {
		return nil, "", "", fmt.Errorf("open control stream: %w", err)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer close(done)
	_ = stream.SetDeadline(time.Now().Add(timeout))
	sessionID, peerID, err := handshake.Client(stream, deviceID, claims)
	_ = stream.SetDeadline(time.Time{})
	if err != nil {
		_ = stream.Close()
		return nil, "", "", fmt.Errorf("handshake client: %w", err)
	}
	return stream, sessionID, peerID, nil
}

func (c *Client) handleReconnect(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	if ctx.Err() != nil {
		return
	}
	if !c.reconnectPending.CompareAndSwap(false, true) {
		// A teardown/rebuild is already running or queued. The engines that
		// call this callback do so from provider goroutines (some
		// synchronously from inside Reconnect), so blocking here would
		// deadlock the client against itself. Coalesce instead: the cycle
		// in flight tears down whatever session exists when it runs, which
		// covers this event's intent.
		return
	}
	// Run the cycle off the caller's goroutine. The engines invoke this
	// callback synchronously from their own provider paths (mts/jazz
	// queueReconnect call cb() inline), so doing the teardown - which
	// closes the datachannel and can retrigger their reconnect machinery -
	// on the caller's stack risks re-entrant deadlock.
	c.goTracked(func() {
		defer c.reconnectPending.Store(false)
		c.runReconnectCycle(ctx, cfg, cancel, reason)
		// If churn events arrived while this cycle ran, they were coalesced
		// away by the pending flag. The session state after this cycle
		// reflects the latest teardown, so no deferred re-run is needed.
	})
}

// runReconnectCycle tears the old session down and rebuilds it. reconnectMu
// serializes overlapping cycles; it is taken and released here, NOT in
// handleReconnect, so the engine callback path never blocks on it.
func (c *Client) runReconnectCycle(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	c.reconnectMu.Lock()
	c.health.RecordReconnect()
	logger.Infof("client reconnect reason=%s - tearing down smux session", reason)
	tunnelcore.ResetPeer(c.ln)
	c.sessMu.RLock()
	if c.pair != nil {
		_ = c.pair.CloseConns()
	} else {
		if c.conn != nil {
			_ = c.conn.Close()
		}
		if c.controlConn != nil {
			_ = c.controlConn.Close()
		}
	}
	c.sessMu.RUnlock()
	c.sessMu.Lock()
	oldPair := c.pair
	oldControl := c.controlStrm
	oldControlStop := c.controlStop
	oldSession := c.session
	oldControlSession := c.controlSess
	c.pair = nil
	// Clear the conns rather than installing replacements. On the liveness
	// path no smux session is built over them for up to livenessFallback, so
	// a reader-less conn would fill its inbound queue and then block the
	// transport's delivery goroutine inside Push. PushData treats nil as a
	// no-op, and tryReopenSession builds its own conns anyway.
	c.conn, c.controlConn = nil, nil
	c.session, c.controlSess = nil, nil
	c.controlStrm, c.controlStop = nil, nil
	c.sessionID = ""
	// The old session's last pong is not evidence about the next one: without
	// this reset, watchControlStaleness keeps vouching for a dead session
	// (link healthy) through the whole rebuild, which blinds the transport's
	// peer-restart corroborator exactly when it is needed. A zero time reads
	// as "no pong yet" (time.Since(zero) exceeds any threshold).
	c.controlLastPong.Store(time.Time{})
	c.sessMu.Unlock()
	// Released before the engine rebuild and retry loop: the liveness path
	// calls c.ln.Reconnect below, and the jazz/mts engines answer that by
	// synchronously invoking the reconnect callback - which re-enters
	// handleReconnect. With reconnectMu held that re-entry deadlocked the
	// whole client on its first liveness rebuild. The pending flag above
	// makes the re-entry a no-op instead.
	c.reconnectMu.Unlock()
	if oldControlStop != nil {
		oldControlStop()
	}
	closeClientPair(oldPair, oldSession, oldControlSession)
	if oldControl != nil {
		_ = oldControl.Close()
	}
	if reason == reconnectLiveness && c.ln != nil {
		c.ln.Reconnect(reconnectLiveness)
		c.scheduleLivenessFallback(ctx, cfg, cancel)
		return
	}
	c.retryHandshake(ctx, cfg, cancel, reason)
}

func closeClientPair(pair *tunnelcore.SessionPair, session, controlSession *smux.Session) {
	if pair != nil {
		_ = pair.Close()
		return
	}
	if session != nil {
		_ = session.Close()
	}
	if controlSession != nil && controlSession != session {
		_ = controlSession.Close()
	}
}

func (c *Client) scheduleLivenessFallback(ctx context.Context, cfg Config, cancel context.CancelFunc) {
	if !c.fallbackPending.CompareAndSwap(false, true) {
		return
	}
	delay := c.livenessFallback
	if delay <= 0 {
		delay = defaultLivenessFallback
	}
	c.goTracked(func() {
		defer c.fallbackPending.Store(false)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if c.sessionEstablished() {
			return
		}
		logger.Warnf("client reconnect: no provider callback within %s - re-establishing session", delay)
		if ctx.Err() == nil && !c.sessionEstablished() {
			c.retryHandshake(ctx, cfg, cancel, reconnectFallback)
		}
	})
}

func (c *Client) sessionEstablished() bool {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.session != nil && !c.session.IsClosed() && c.sessionID != ""
}

func (c *Client) retryHandshake(ctx context.Context, cfg Config, cancel context.CancelFunc, reason string) {
	const (
		initialDelay = 300 * time.Millisecond
		maxDelay     = 5 * time.Second
	)
	// Only one retry loop may run at a time: two interleaved loops take
	// turns tearing down the session the other just installed. The lock is
	// released between attempts so a fresh reconnect event can still be
	// serviced promptly instead of queueing behind this whole loop.
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	delay := initialDelay
	maxAttempts := maxHandshakeAttempts(reason)
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		// A concurrent cycle (liveness fallback, another provider event) has
		// rebuilt the session since this loop started waiting: a fresh
		// attempt here would tear that healthy session down and re-handshake
		// over it - the churn the coalescing in handleReconnect exists to
		// prevent, and the fallback path would trigger exactly this by
		// racing the provider callback it was waiting for.
		if attempt > 1 && c.sessionEstablished() {
			logger.Infof("client reconnect: session re-established by a concurrent attempt - aborting retry loop (reason=%s)", reason)
			return
		}
		logger.Infof("client reconnect attempt=%d reason=%s", attempt, reason)
		if c.tryReopenSession(ctx, cfg, cancel, attempt) {
			return
		}
		if maxAttempts > 0 && attempt >= maxAttempts {
			if cfg.ExitOnReconnectExhaustion {
				logger.Warnf("client reconnect: exhausted %d handshake attempts (reason=%s) - exiting for host failover", attempt, reason)
				cancel()
				return
			}
			logger.Warnf("client reconnect: exhausted %d handshake attempts (reason=%s) - keeping listener up", attempt, reason)
			return
		}
		c.reconnectMu.Unlock()
		select {
		case <-ctx.Done():
			c.reconnectMu.Lock()
			return
		case <-time.After(delay):
		}
		c.reconnectMu.Lock()
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
}

func maxHandshakeAttempts(reason string) int {
	switch reason {
	case reconnectProvider:
		return 5
	case reconnectFallback:
		return 3
	default:
		return 0
	}
}

func (c *Client) tryReopenSession(
	ctx context.Context,
	cfg Config,
	cancel context.CancelFunc,
	attempt int,
) bool {
	// A failed attempt may have latched the engine's peer binding onto the
	// dead session's epoch (the handshake reply path latches on the first
	// inbound frame). Without clearing it, every retry sends CLIENT_HELLO to
	// the old dead epoch and drops the restarted server's fresh frames -
	// the handshake never converges ("read welcome timeout" after a server
	// restart). ResetPeer makes the next attempt a clean slate for engines
	// that latch (jazz/mts/vp8channel/seichannel); it is a no-op elsewhere.
	if attempt > 1 {
		tunnelcore.ResetPeer(c.ln)
	}
	conn := muxconn.New(c.ln, c.keys)
	controlConn := muxconn.NewControl(c.ln, c.keys)
	c.sessMu.Lock()
	oldConn, oldControlConn := c.conn, c.controlConn
	c.conn, c.controlConn = conn, controlConn
	c.sessMu.Unlock()
	if oldConn != nil {
		_ = oldConn.Close()
	}
	if oldControlConn != nil {
		_ = oldControlConn.Close()
	}
	pair, err := tunnelcore.NewSessionPairWithConns(
		c.ln, conn, controlConn, tunnelcore.ClientRole,
	)
	if err != nil {
		logger.Warnf("smux re-init failed (attempt %d): %v", attempt, err)
		if pair != nil {
			_ = pair.Close()
		}
		return false
	}
	control, sessionID, peerID, err := openControlStreamTimeout(
		ctx, pair.ControlSession, c.deviceID, c.claims, handshake.DefaultTimeout,
	)
	if err != nil {
		logger.Warnf("handshake on reconnect failed (attempt %d): %v", attempt, err)
		_ = pair.Close()
		return false
	}
	if err := confirmPeer(c.ln, peerID); err != nil {
		logger.Warnf("peer confirmation on reconnect failed (attempt %d): %v", attempt, err)
		_ = pair.Close()
		return false
	}
	if waitErr := waitForPeer(ctx, c.ln); waitErr != nil {
		logger.Warnf("wait for peer on reconnect failed (attempt %d): %v", attempt, waitErr)
		_ = pair.Close()
		return false
	}
	logger.Infof("session %s reopened (device=%s)", sessionID, c.deviceID)
	c.sessMu.Lock()
	c.installPairLocked(pair)
	c.controlStrm = control
	c.sessionID = sessionID
	c.sessMu.Unlock()
	c.signalSessionReady()
	c.health.RecordSession(sessionID)
	c.startControlLoop(ctx, cfg, cancel, control)
	return true
}

func (c *Client) installPairLocked(pair *tunnelcore.SessionPair) {
	c.pair = pair
	c.conn = pair.DataConn
	c.controlConn = pair.ControlConn
	c.session = pair.DataSession
	c.controlSess = pair.ControlSession
}

func (c *Client) signalSessionReady() {
	c.sessMu.Lock()
	old := c.sessionReady
	c.sessionReady = make(chan struct{})
	c.sessMu.Unlock()
	close(old)
}

func (c *Client) readyChannel() chan struct{} {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.sessionReady
}

// sessionSnapshot returns the live session together with the ready channel
// that will fire when it is replaced, both read in one critical section.
func (c *Client) sessionSnapshot() (*smux.Session, string, <-chan struct{}) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.session, c.sessionID, c.sessionReady
}
