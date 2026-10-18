package vks

// credupload.go — credential upload through the tunnel.
//
// The server intercepts outbound CONNECTs to the reserved target
// `vks-creds.tamizdat.invalid:80` (any authenticated user — the family
// model has no admin distinction) and serves a tiny in-process HTTP/1.1
// handler instead of dialing out:
//
//	POST /creds/<provider>   body = the raw Cookie: header value
//
//	 telemost → one real room is created with the new cookies (the room
//	            lands in the reusable pool — the validation IS the
//	            product: a working room);
//	 mts      → one GetLoginData call (200 + rotated cookies proves the
//	            session alive).
//
// Only on success are the cookies stored (persisted, 0600) and the
// provider's login-required flag cleared. The response is JSON
// {"ok":true} or {"ok":false,"error":"..."}. Logs never carry cookie
// values.
//
// The client half is UploadProviderCredentials: plain HTTP/1.1 over a
// conn supplied by a dial function (the iOS app passes the tunnel's
// outbound dialer, so the upload rides the existing tunnel exactly like
// any other flow).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CredsUploadAuthority is the reserved CONNECT target for credential
// uploads. Reserved authority (like tamizdat-config.invalid) — never a
// real destination.
const CredsUploadAuthority = "vks-creds.tamizdat.invalid:80"

// MaxCredsUploadBytes caps one upload body (a Cookie header is a few
// hundred bytes; anything bigger is a mistake or abuse).
const MaxCredsUploadBytes = 16 * 1024

// CredsUploadHandler serves the POST /creds/<provider> endpoint. The
// tamizdat root server hands the intercepted CONNECT stream to Serve
// after answering 200 to the CONNECT.
type CredsUploadHandler struct {
	creds *CredStore
	pool  *TelemostPool
}

// NewCredsUploadHandler builds the handler over the credential store
// (and the telemost pool: a successful telemost validation adds its
// created room to the pool).
func NewCredsUploadHandler(creds *CredStore, pool *TelemostPool) *CredsUploadHandler {
	return &CredsUploadHandler{creds: creds, pool: pool}
}

// ServeHTTP implements the POST /creds/<provider> endpoint. cap 16 KiB,
// validate-before-replace, JSON reply.
func (h *CredsUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(ok bool, errStr string) {
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok, "error": errStr})
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provider := strings.Trim(strings.TrimPrefix(r.URL.Path, "/creds/"), "/")
	if !validCredProvider(provider) {
		reply(false, fmt.Sprintf("unknown provider %q (want telemost or mts)", provider))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxCredsUploadBytes+1))
	if err != nil {
		reply(false, "read body: "+err.Error())
		return
	}
	if len(body) > MaxCredsUploadBytes {
		reply(false, "body too large")
		return
	}
	cookieHeader := strings.TrimSpace(string(body))
	if cookieHeader == "" {
		reply(false, "empty cookie header")
		return
	}
	// Never log the cookie values; length only.
	log.Printf("vks creds upload: provider=%s bytes=%d from %s — validating",
		provider, len(cookieHeader), r.RemoteAddr)

	// Validate BEFORE replacing: a dead cookie set must not evict working
	// stored credentials.
	vctx, vcancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer vcancel()
	switch provider {
	case "telemost":
		roomURL, verr := createTelemostRoom(vctx, cookieHeader)
		if verr != nil {
			log.Printf("vks creds upload: telemost validation failed: %v", verr)
			h.creds.SetLoginRequired("telemost", true)
			reply(false, "telemost validation failed: "+verr.Error())
			return
		}
		// The validation room goes straight into the reusable pool.
		if h.pool != nil {
			h.pool.Add(roomURL)
		}
		log.Printf("vks creds upload: telemost validated (room created, %d chars of URI)", len(roomURL))
	case "mts":
		if _, merr := mtsGetLoginData(vctx, cookieHeader); merr != nil {
			log.Printf("vks creds upload: mts validation failed: %v", merr)
			h.creds.SetLoginRequired("mts", true)
			reply(false, "mts validation failed: "+merr.Error())
			return
		}
		log.Printf("vks creds upload: mts validated (GetLoginData 200)")
	default:
		reply(false, "unsupported provider")
		return
	}
	if err := h.creds.Replace(provider, cookieHeader); err != nil {
		reply(false, "store failed: "+err.Error())
		return
	}
	reply(true, "")
}

// CredsUploadInterceptor adapts the upload endpoint to the root
// tamizdat package's ConnInterceptor seam. The server hands over the
// stream the client opened to CredsUploadAuthority (the tamizdat CONNECT
// is already complete, like any proxied flow) and plain HTTP/1.1 is
// served on it - no TLS: the stream rides the encrypted tamizdat
// transport.
func CredsUploadInterceptor(creds *CredStore, pool *TelemostPool) func(ctx context.Context, conn net.Conn, destination, userID, userName string) {
	h := NewCredsUploadHandler(creds, pool)
	return func(ctx context.Context, conn net.Conn, destination, userID, userName string) {
		log.Printf("vks creds upload: stream open (user=%s)", userID)
		ServeCredsUpload(conn, h)
	}
}

// ServeCredsUpload runs the tiny HTTP/1.1 server on conn until the conn
// closes. It returns only after the HTTP server has closed the stream, so
// the caller may close conn afterwards without cutting off the reply.
func ServeCredsUpload(conn net.Conn, h *CredsUploadHandler) {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       15 * time.Second,
	}
	_ = srv.Serve(newOneShotListener(conn))
}

// oneShotListener adapts a single net.Conn to a net.Listener so
// http.Server.Serve can run on it. The second Accept blocks until the
// served conn is closed: Serve handles the conn on its own goroutine and
// returns as soon as Accept fails, so failing immediately would let the
// caller tear the stream down while the handler is still writing.
type oneShotListener struct {
	conn net.Conn
	used bool
	done chan struct{}
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{conn: conn, done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if !l.used {
		l.used = true
		return &closeNotifyConn{Conn: l.conn, done: l.done}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// closeNotifyConn signals oneShotListener when http.Server closes the conn.
type closeNotifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

// IsCredsUploadTarget reports whether an outbound CONNECT destination is
// the reserved credential-upload authority. The server consults this
// before its outbound registry dial (server.go).
func IsCredsUploadTarget(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(host), "."), "vks-creds.tamizdat.invalid")
}

// ---------------------------------------------------------------------------
// Client side.
// ---------------------------------------------------------------------------

// UploadProviderCredentials uploads a fresh Cookie header for the
// provider through the tunnel: it HTTP-CONNECTs to the reserved
// vks-creds.tamizdat.invalid:80 via the supplied dial function (the
// tunnel's outbound dialer — the upload rides the tunnel like any other
// flow) and POSTs the header to /creds/<provider>. The server validates
// before replacing; a validation failure returns a descriptive error
// and leaves the stored credentials untouched.
//
// dial must return a stream already connected to CredsUploadAuthority
// (the tunnel dialer performs the tamizdat-level CONNECT); plain
// HTTP/1.1 runs directly on it.
func UploadProviderCredentials(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), provider, cookieHeader string) error {
	if !validCredProvider(provider) {
		return fmt.Errorf("vks upload: unknown provider %q (want telemost or mts)", provider)
	}
	if strings.TrimSpace(cookieHeader) == "" {
		return fmt.Errorf("vks upload: empty cookie header")
	}
	if len(cookieHeader) > MaxCredsUploadBytes {
		return fmt.Errorf("vks upload: cookie header too large (%d > %d bytes)", len(cookieHeader), MaxCredsUploadBytes)
	}
	conn, err := dial(ctx, "tcp", CredsUploadAuthority)
	if err != nil {
		return fmt.Errorf("vks upload: dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	}

	body := cookieHeader
	post := "POST /creds/" + provider + " HTTP/1.1\r\n" +
		"Host: " + CredsUploadAuthority + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	if _, err := conn.Write([]byte(post)); err != nil {
		return fmt.Errorf("vks upload: write POST: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return fmt.Errorf("vks upload: read response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vks upload: status %d", resp.StatusCode)
	}
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return fmt.Errorf("vks upload: decode response: %w", err)
	}
	if !out.OK {
		if out.Error != "" {
			return fmt.Errorf("vks upload: server rejected: %s", out.Error)
		}
		return fmt.Errorf("vks upload: server rejected the credentials")
	}
	return nil
}
