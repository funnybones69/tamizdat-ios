package vks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// telemost_rooms.go — server-side Telemost room creation and the reusable
// room pool.
//
// Telemost rooms persist forever (no API deletion) and admit anonymous
// guests, so a created room is a REUSABLE resource: the pool hands out an
// idle room first and only creates a new one when every pool room is
// busy. Created rooms persist to a file (-vks-telemost-pool) so restarts
// reuse them. Released rooms go back to idle — never deleted.
//
// Creation needs the Yandex account Cookie header plus a few browser
// headers (verified live, see docs/VKS_ON_DEMAND.md): X-Uid is derived
// from the Session_id cookie — the uid is the digits in "|<uid>.".

// mtsGetLoginDataBaseURL / telemostConferencesURL are unexported so tests
// can point them at httptest fakes (offline).
var (
	mtsGetLoginDataURL     = "https://gw.mts-link.ru/accountUcaas/AccountUcaas.GetLoginData"
	telemostConferencesURL = "https://cloud-api.yandex.ru/telemost_front/v2/telemost/conferences?next_gen_media_platform_allowed=true"
)

// mtsLoginHeaders is the browser-ish header set the MTS GW host expects
// (the same set createAndStartMTS uses; the refresh call needs it too).
func mtsLoginHeaders(cookieHeader string) map[string]string {
	return map[string]string{
		"Cookie":        cookieHeader,
		"Referer":       "https://my.mts-link.ru/",
		"x-platform":    "Web",
		"x-user-id":     "180602801",
		"x-device-id":   `"9e89d185-39da-438d-9f3f-d2273aac5ef7"`,
		"x-device":      "Chrome 153.0.0.0",
		"x-app-version": "3.9.206",
		"x-os":          "Windows 10.0",
		"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
	}
}

// mtsGetLoginData validates the account session and returns any Set-Cookie
// updates. A live session may return LoginData without rotating either cookie.
func mtsGetLoginData(ctx context.Context, cookieHeader string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mtsGetLoginDataURL, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range mtsLoginHeaders(cookieHeader) {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return nil, fmt.Errorf("GetLoginData: read response: %w", readErr)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GetLoginData: status %d", resp.StatusCode)
	}
	var gotAccess, gotRefresh bool
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if name, ok := setCookieName(sc); ok {
			switch name {
			case "access":
				gotAccess = true
			case "refresh":
				gotRefresh = true
			}
		}
	}
	if !gotAccess || !gotRefresh {
		var login struct {
			Type string `json:"type"`
			Value struct {
				UserID string `json:"userId"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &login); err != nil || login.Type != "LoginData" || login.Value.UserID == "" {
			return nil, fmt.Errorf("GetLoginData: 200 without authenticated LoginData or access/refresh rotation")
		}
	}
	return resp.Header.Values("Set-Cookie"), nil
}

// telemostUIDFromCookie derives the Yandex account uid from the Session_id
// cookie in a Cookie header: the uid is the digits in "|<uid>.".
func telemostUIDFromCookie(cookieHeader string) (string, bool) {
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok || k != "Session_id" {
			continue
		}
		// Current sessions have |<uid>.<signed suffix>; older exports
		// ended at |<uid>. Numeric fields before the pipe are not a UID.
		if idx := strings.Index(v, "|"); idx >= 0 {
			digits, _, _ := strings.Cut(v[idx+1:], ".")
			if isDigits(digits) {
				return digits, true
			}
		}
	}
	return "", false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// createTelemostRoom creates one Telemost conference via the account
// cookies and returns its room URL ("https://telemost.yandex.ru/j/<id>").
// A 401/403 yields ErrLoginRequired so the caller flags telemost and the
// beacon tells clients to re-upload cookies.
func createTelemostRoom(ctx context.Context, cookieHeader string) (string, error) {
	uid, ok := telemostUIDFromCookie(cookieHeader)
	if !ok {
		return "", fmt.Errorf("telemost: no Session_id uid in the cookie header")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, telemostConferencesURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookieHeader)
	req.Header.Set("X-Uid", uid)
	req.Header.Set("idempotency-key", uuid.NewString())
	req.Header.Set("Client-Instance-Id", uuid.NewString())
	req.Header.Set("X-Telemost-Client-Version", "211.2.0")
	req.Header.Set("Origin", "https://telemost.yandex.ru")
	req.Header.Set("Referer", "https://telemost.yandex.ru/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("%w: telemost create: status %d", ErrLoginRequired, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("telemost create: status %d %s", resp.StatusCode, string(body))
	}
	var out struct {
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.URI == "" {
		return "", fmt.Errorf("telemost create: no uri in the response")
	}
	return out.URI, nil
}

// ErrLoginRequired signals that the provider's stored credentials are
// dead — the caller should mark the provider login-required (beacon
// flags) instead of silently falling back.
var ErrLoginRequired = fmt.Errorf("vks: provider login required")

// ---------------------------------------------------------------------------
// The reusable Telemost room pool.
// ---------------------------------------------------------------------------

// TelemostPool tracks the reusable Telemost rooms across restarts.
// Rooms are never deleted; "idle" vs "busy" is decided by the caller
// (the WatchServer knows which rooms are live).
type TelemostPool struct {
	mu    sync.Mutex
	rooms []string // created room URLs, creation order
	path  string   // persistence file ("" = memory-only)
}

// NewTelemostPool returns a pool persisting to path ("" = memory-only)
// and loads previously created rooms from it.
func NewTelemostPool(path string) *TelemostPool {
	p := &TelemostPool{path: strings.TrimSpace(path)}
	if p.path != "" {
		if data, err := os.ReadFile(p.path); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					p.rooms = append(p.rooms, line)
				}
			}
			log.Printf("vks telemost pool: loaded %d room(s) from %s", len(p.rooms), p.path)
		}
	}
	return p
}

// Rooms returns a snapshot of every known room URL (pool rooms plus any
// armed -vks-watch telemost rooms the caller wants considered).
func (p *TelemostPool) Rooms() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.rooms...)
}

// Add appends a room URL to the pool and persists. Idempotent per URL.
func (p *TelemostPool) Add(roomURL string) {
	roomURL = strings.TrimSpace(roomURL)
	if roomURL == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.rooms {
		if r == roomURL {
			return
		}
	}
	p.rooms = append(p.rooms, roomURL)
	if p.path != "" {
		if err := writeFileAtomic0600(p.path, []byte(strings.Join(p.rooms, "\n")+"\n")); err != nil {
			log.Printf("vks telemost pool: persist: %v", err)
		}
	}
}

// Size reports the pool size.
func (p *TelemostPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.rooms)
}
