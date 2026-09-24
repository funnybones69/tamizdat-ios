// Package mts is the auth provider for MTS Link (Webinar.ru rebrand) VKS
// rooms. Guests join anonymously: guestlogin issues a JWT, and creating a
// conference returns the publishToken (privateKey) that unlocks sending.
package mts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/funnybones69/tamizdat/vks/olc/core/auth"
)

const (
	apiBase = "https://my.mts-link.ru/api"
	sfuBase = "https://sfu.mts-link.ru"
)

var errAPI = errors.New("mts api error")

// Provider produces engine credentials for MTS Link. Engine() is "mts".
type Provider struct{}

// Engine reports which engine consumes mts credentials.
func (Provider) Engine() string { return "mts" }

// DefaultServiceURL returns the MTS Link service URL.
func (Provider) DefaultServiceURL() string { return "https://my.mts-link.ru" }

// Issue resolves an MTS room link to a joinable conference with publish
// rights. cfg.RoomURL accepts "https://my.mts-link.ru/j/<eventID>/<pwd>" or
// bare "<eventID>".
func (p Provider) Issue(ctx context.Context, cfg auth.Config) (auth.Credentials, error) {
	eventID := roomEventID(cfg.RoomURL)
	if eventID == "" {
		return auth.Credentials{}, auth.ErrRoomIDRequired
	}
	client := &http.Client{Jar: jar()}
	// Reuse a saved guest identity for this room so restarts rejoin as the
	// SAME participant (same cookies) instead of registering a new guest.
	saved := loadSession(eventID)
	name := cfg.Name
	if saved != nil {
		restoreCookies(client.Jar, saved.Cookies)
		if saved.Name != "" {
			name = saved.Name
		}
	}

	esid, err := activeSession(ctx, client, eventID)
	if err != nil {
		return auth.Credentials{}, err
	}
	userID, err := guestLogin(ctx, client, esid, name)
	if err != nil {
		return auth.Credentials{}, err
	}
	saveSession(eventID, &mtsSession{
		EventID: eventID,
		ESID:    esid,
		Name:    name,
		UserID:  userID,
		Cookies: dumpCookies(client.Jar),
		SavedAt: time.Now(),
	})
	// The SFU join needs the NUMERIC user id from the connections record,
	// not the hex session id (verified live: "user id not found" otherwise).
	numericUID, err := connectionsUserID(ctx, client, esid)
	if err != nil {
		return auth.Credentials{}, err
	}
	conf, err := createConference(ctx, client, esid)
	if err != nil {
		return auth.Credentials{}, err
	}
	joinToken, err := fetchJoinToken(ctx, client, esid)
	if err != nil {
		return auth.Credentials{}, err
	}
	return auth.Credentials{
		URL:   conf.RTCURL,
		Token: conf.PrivateKey,
		Extra: map[string]string{
			"eventSessionID": esid,
			"userID":         numericUID,
			"sessionID":      userID,
			"publishToken":   conf.PrivateKey,
			"joinToken":      joinToken,
			"publicKey":      conf.PublicKey,
			"participation":  conf.ParticipationID.String(),
			// Engine-side peer discovery (GET /eventsessions/{esid}/conferences)
			// needs the session cookies; pass the header form so the engine
			// can call the API directly.
			"cookieHeader": cookieHeader(client, apiBase),
		},
	}, nil
}

// roomEventID extracts the event id from an MTS room link. The last path
// segment is the API event id (verified live).
func roomEventID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "/j/"); i >= 0 {
		raw = raw[i+len("/j/"):]
	}
	raw = strings.Trim(raw, "/")
	parts := strings.Split(raw, "/")
	if len(parts) == 0 {
		return ""
	}
	id := parts[len(parts)-1]
	if i := strings.IndexAny(id, "?#"); i >= 0 {
		id = id[:i]
	}
	return id
}

func activeSession(ctx context.Context, c *http.Client, eventID string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/event/"+url.PathEscape(eventID), nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: event: %v", errAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: event: status %d", errAPI, resp.StatusCode)
	}
	// eventSessions[].id is a JSON number in the live API.
	var ev struct {
		EventSessions []struct {
			ID     json.Number `json:"id"`
			Status string      `json:"status"`
		} `json:"eventSessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil {
		return "", fmt.Errorf("%w: event decode: %v", errAPI, err)
	}
	for _, s := range ev.EventSessions {
		if s.Status == "START" || s.Status == "PUBLISHED" || s.Status == "ACTIVE" {
			return s.ID.String(), nil
		}
	}
	if len(ev.EventSessions) > 0 {
		return ev.EventSessions[0].ID.String(), nil
	}
	return "", fmt.Errorf("%w: no event sessions", errAPI)
}

type guestResp struct {
	ParticipationID json.Number `json:"participationId"`
	User            struct {
		SessionID string `json:"sessionId"`
	} `json:"user"`
}

func guestLogin(ctx context.Context, c *http.Client, esid, name string) (string, error) {
	if name == "" {
		name = "Гость"
	}
	body, _ := json.Marshal(map[string]string{"nickname": name})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/eventsessions/"+url.PathEscape(esid)+"/guestlogin", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: guestlogin: %v", errAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return "", fmt.Errorf("%w: guestlogin: status %d %s", errAPI, resp.StatusCode, string(b))
	}
	var g guestResp
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		return "", fmt.Errorf("%w: guestlogin decode: %v", errAPI, err)
	}
	if g.User.SessionID == "" {
		return "", fmt.Errorf("%w: guestlogin: empty user sessionId", errAPI)
	}
	return g.User.SessionID, nil
}

type confResp struct {
	ID              json.Number `json:"id"`
	PrivateKey      string      `json:"privateKey"`
	PublicKey       string      `json:"publicKey"`
	RTCURL          string      `json:"rtcUrl"`
	UserID          json.Number `json:"userId"`
	ParticipationID json.Number `json:"participationId"`
	Status          string      `json:"status"`
}

// fetchJoinToken gets the SFU join token: GET /eventsessions/{esid}/join-token
// (verified live — the field the web client's getJoinToken consumes).

// connectionsUserID POSTs /eventsessions/{esid}/connections and returns the
// numeric user id (the SFU join userId param).
func connectionsUserID(ctx context.Context, c *http.Client, esid string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		apiBase+"/eventsessions/"+url.PathEscape(esid)+"/connections", strings.NewReader("{}"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: connections: %v", errAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("%w: connections: status %d", errAPI, resp.StatusCode)
	}
	var out struct {
		User struct {
			ID json.Number `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("%w: connections decode: %v", errAPI, err)
	}
	if out.User.ID.String() == "" || out.User.ID.String() == "0" {
		return "", fmt.Errorf("%w: connections: empty user id", errAPI)
	}
	return out.User.ID.String(), nil
}

func fetchJoinToken(ctx context.Context, c *http.Client, esid string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		apiBase+"/eventsessions/"+url.PathEscape(esid)+"/join-token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: join-token: %v", errAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: join-token: status %d", errAPI, resp.StatusCode)
	}
	var out struct {
		Data struct {
			JoinToken string `json:"joinToken"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("%w: join-token decode: %v", errAPI, err)
	}
	if out.Data.JoinToken == "" {
		return "", fmt.Errorf("%w: join-token: empty", errAPI)
	}
	return out.Data.JoinToken, nil
}

func createConference(ctx context.Context, c *http.Client, esid string) (*confResp, error) {
	body, _ := json.Marshal(map[string]bool{"hasAudio": true, "hasVideo": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/eventsessions/"+url.PathEscape(esid)+"/conferences", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://my.mts-link.ru/")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: conferences: %v", errAPI, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 400))
		return nil, fmt.Errorf("%w: conferences: status %d %s", errAPI, resp.StatusCode, string(b))
	}
	var conf confResp
	if err := json.NewDecoder(resp.Body).Decode(&conf); err != nil {
		return nil, fmt.Errorf("%w: conferences decode: %v", errAPI, err)
	}
	if conf.PrivateKey == "" {
		return nil, fmt.Errorf("%w: conferences: empty privateKey", errAPI)
	}
	return &conf, nil
}

// mtsSession is the persisted guest identity for one room event. Reusing the
// cookies keeps the participant the same person across restarts (the roster
// keeps host/admin promotions, display name and stream state bound to it).
type mtsSession struct {
	EventID string        `json:"event_id"`
	ESID    string        `json:"esid"`
	Name    string        `json:"name"`
	UserID  string        `json:"user_id"`
	Cookies []savedCookie `json:"cookies"`
	SavedAt time.Time     `json:"saved_at"`
}

type savedCookie struct {
	Name   string    `json:"name"`
	Value  string    `json:"value"`
	Domain string    `json:"domain"`
	Path   string    `json:"path"`
	Expiry time.Time `json:"expiry,omitempty"`
}

// sessionFilePath returns where the room identity is persisted. MTS_SESSION_FILE
// overrides the default (<user cache>/tamizdat/mts-<event>.json).
func sessionFilePath(eventID string) string {
	if p := os.Getenv("MTS_SESSION_FILE"); p != "" {
		return p
	}
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "tamizdat", "mts-"+eventID+".json")
}

func loadSession(eventID string) *mtsSession {
	raw, err := os.ReadFile(sessionFilePath(eventID)) // #nosec G304 -- fixed cache path
	if err != nil {
		return nil
	}
	var sess mtsSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil
	}
	if sess.EventID != eventID {
		return nil
	}
	return &sess
}

func saveSession(eventID string, sess *mtsSession) {
	path := sessionFilePath(eventID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	raw, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

func restoreCookies(j http.CookieJar, saved []savedCookie) {
	if j == nil {
		return
	}
	u, _ := url.Parse("https://my.mts-link.ru/")
	cookies := make([]*http.Cookie, 0, len(saved))
	for _, c := range saved {
		cookies = append(cookies, &http.Cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Expires: c.Expiry,
		})
	}
	j.SetCookies(u, cookies)
}
func dumpCookies(j http.CookieJar) []savedCookie {
	if j == nil {
		return nil
	}
	u, _ := url.Parse("https://my.mts-link.ru/")
	out := []savedCookie{}
	for _, c := range j.Cookies(u) {
		out = append(out, savedCookie{Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path, Expiry: c.Expires})
	}
	return out
}

// cookieHeader renders the session cookies as a single Cookie header value
// for the given base URL, so the engine can call the API (peer discovery)
// with the same authenticated session.
func cookieHeader(c *http.Client, base string) string {
	if c == nil || c.Jar == nil {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	cookies := c.Jar.Cookies(u)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

func jar() *cookiejar.Jar {
	j, _ := cookiejar.New(nil)
	return j
}
