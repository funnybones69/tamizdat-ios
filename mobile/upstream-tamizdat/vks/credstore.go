package vks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// credstore.go — the mutable server-side credential store.
//
// Holds the raw Cookie header for each VKS provider whose room creation
// needs an account (telemost = Yandex session, mts = MTS Link session).
// Values load at boot from the per-provider flag files
// (-vks-yandex-cookies / -vks-mts-cookies) and may change at runtime: the
// MTS auto-refresher rotates cookies every 24 h and the in-tunnel upload
// endpoint replaces them on operator action. Every update persists back
// to the provider's file atomically (temp file + rename, mode 0600).
//
// The store also tracks a login-required flag per provider: set when a
// create/refresh call proves the cookies dead (401/403), cleared on any
// success. The beacon DNS answer carries the current set to clients so
// the iOS app can prompt for fresh cookies instead of silently timing
// out (see beacon_dns.go).
//
// File format: either the raw Cookie header text (what an operator
// pastes) or a JSON envelope {"cookie_header":...,"expires":{...}}
// written by this store after a cookie rotation. The expires map records
// the Set-Cookie lifetimes so the MTS refresher can decide staleness
// after a restart. Both forms parse on load.

// CredStore is the server-side mutable store of per-provider Cookie
// headers plus the login-required flags advertised in beacon answers.
// Safe for concurrent use.
type CredStore struct {
	mu       sync.Mutex
	cookies  map[string]string           // provider -> raw Cookie header
	paths    map[string]string           // provider -> persistence file ("" = volatile)
	expires  map[string]map[string]int64 // provider -> cookie name -> unix expiry
	loginReq map[string]bool
}

// credFileEnvelope is the persisted form of one provider's credentials.
type credFileEnvelope struct {
	CookieHeader string           `json:"cookie_header"`
	Expires      map[string]int64 `json:"expires,omitempty"`
}

// NewCredStore returns an empty store.
func NewCredStore() *CredStore {
	return &CredStore{
		cookies:  map[string]string{},
		paths:    map[string]string{},
		expires:  map[string]map[string]int64{},
		loginReq: map[string]bool{},
	}
}

func validCredProvider(provider string) bool {
	return provider == "telemost" || provider == "mts"
}

// LoadFile registers path as the provider's persistence file and loads
// the initial Cookie header from it. Call before wiring the watchers.
func (s *CredStore) LoadFile(provider, path string) error {
	if !validCredProvider(provider) {
		return fmt.Errorf("credstore: unknown provider %q (want telemost or mts)", provider)
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("credstore: empty path for %s", provider)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("credstore: read %s: %w", path, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths[provider] = path
	s.cookies[provider] = parseCredFile(data)
	if env := parseCredEnvelope(data); env != nil && len(env.Expires) > 0 {
		s.expires[provider] = env.Expires
	}
	return nil
}

// CookieHeader returns the provider's current Cookie header ("" when none).
func (s *CredStore) CookieHeader(provider string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cookies[provider]
}

// Replace swaps the provider's Cookie header, persists it, and clears the
// login-required flag. The caller validates first (the upload endpoint
// does a real provider call before replacing); this method only stores.
func (s *CredStore) Replace(provider, cookieHeader string) error {
	if !validCredProvider(provider) {
		return fmt.Errorf("credstore: unknown provider %q", provider)
	}
	cookieHeader = strings.TrimSpace(cookieHeader)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cookies[provider] = cookieHeader
	delete(s.expires, provider) // fresh header: cookie lifetimes unknown
	s.loginReq[provider] = false
	if err := s.persistLocked(provider); err != nil {
		return err
	}
	if s.paths[provider] == "" {
		log.Printf("credstore: %s credentials replaced, but no persistence file is configured (volatile until restart)", provider)
	}
	return nil
}

// MergeCookies merges Set-Cookie response values into the provider's
// stored header (each value's name=value pair replaces any same-name
// cookie, new names append), records their Expires attributes, persists,
// and clears the login-required flag. Returns the merged header.
func (s *CredStore) MergeCookies(provider string, setCookies []string) (string, error) {
	if !validCredProvider(provider) {
		return "", fmt.Errorf("credstore: unknown provider %q", provider)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	merged, expires := mergeCookieHeader(s.cookies[provider], setCookies)
	s.cookies[provider] = merged
	if len(expires) > 0 {
		if s.expires[provider] == nil {
			s.expires[provider] = map[string]int64{}
		}
		for name, unix := range expires {
			s.expires[provider][name] = unix
		}
	}
	s.loginReq[provider] = false
	if err := s.persistLocked(provider); err != nil {
		return merged, err
	}
	return merged, nil
}

// CookieExpiry reports the recorded expiry of one cookie in the
// provider's header (ok=false when unknown — e.g. loaded from a raw
// operator-supplied file that never went through a rotation).
func (s *CredStore) CookieExpiry(provider, cookieName string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unix, ok := s.expires[provider][cookieName]
	if !ok || unix == 0 {
		return time.Time{}, false
	}
	return time.Unix(unix, 0), true
}

// SetLoginRequired marks the provider as needing a fresh login (dead
// cookies). The beacon TXT answer carries the current set to clients.
func (s *CredStore) SetLoginRequired(provider string, required bool) {
	s.mu.Lock()
	s.loginReq[provider] = required
	s.mu.Unlock()
}

// LoginRequired returns the sorted providers currently flagged as
// needing a login.
func (s *CredStore) LoginRequired() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p, v := range s.loginReq {
		if v {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// persistLocked writes the provider's credentials to its file. Call with
// s.mu held.
func (s *CredStore) persistLocked(provider string) error {
	path := s.paths[provider]
	if path == "" {
		return nil
	}
	env := credFileEnvelope{CookieHeader: s.cookies[provider]}
	if s.expires[provider] != nil {
		env.Expires = s.expires[provider]
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic0600(path, append(data, '\n')); err != nil {
		return fmt.Errorf("credstore: persist %s: %w", provider, err)
	}
	return nil
}

// writeFileAtomic0600 writes data to path via a temp file in the same
// directory plus rename, ending at mode 0600. Cookie headers are
// secrets: never world-readable, never a half-written file.
func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// parseCredFile extracts the Cookie header from a credential file: either
// the JSON envelope this store writes or the raw header text.
func parseCredFile(data []byte) string {
	if env := parseCredEnvelope(data); env != nil {
		return strings.TrimSpace(env.CookieHeader)
	}
	return strings.TrimSpace(string(data))
}

func parseCredEnvelope(data []byte) *credFileEnvelope {
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "{") {
		return nil
	}
	var env credFileEnvelope
	if err := json.Unmarshal([]byte(trimmed), &env); err != nil {
		return nil
	}
	return &env
}

// ---------------------------------------------------------------------------
// Cookie header helpers (Cookie request headers and Set-Cookie values).
// ---------------------------------------------------------------------------

type cookiePair struct{ name, value string }

// parseCookiePairs splits a raw Cookie request header into name=value
// pairs, preserving order.
func parseCookiePairs(header string) []cookiePair {
	var out []cookiePair
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out = append(out, cookiePair{name: strings.TrimSpace(k), value: strings.TrimSpace(v)})
	}
	return out
}

// setCookieName extracts the cookie name from one Set-Cookie value.
func setCookieName(sc string) (string, bool) {
	first, _, _ := strings.Cut(sc, ";")
	k, _, ok := strings.Cut(strings.TrimSpace(first), "=")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(k), k != ""
}

// setCookiePairValue extracts the name=value portion (no attributes) of
// one Set-Cookie value — the part that goes into a Cookie request header.
func setCookiePairValue(sc string) string {
	first, _, _ := strings.Cut(sc, ";")
	_, v, _ := strings.Cut(strings.TrimSpace(first), "=")
	return strings.TrimSpace(v)
}

// setCookieExpires parses the Expires attribute of one Set-Cookie value.
func setCookieExpires(sc string) (time.Time, bool) {
	for _, part := range strings.Split(sc, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(k, "expires") {
			if t, err := http.ParseTime(strings.TrimSpace(v)); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

// mergeCookieHeader folds Set-Cookie response values into an existing
// Cookie request header (same-name cookies are replaced — rotation —
// new names append) and returns the recorded cookie expiries.
func mergeCookieHeader(existing string, setCookies []string) (string, map[string]int64) {
	pairs := parseCookiePairs(existing)
	expires := map[string]int64{}
	for _, sc := range setCookies {
		name, ok := setCookieName(sc)
		if !ok || name == "" {
			continue
		}
		value := setCookiePairValue(sc)
		replaced := false
		for i := range pairs {
			if pairs[i].name == name {
				pairs[i].value = value
				replaced = true
				break
			}
		}
		if !replaced {
			pairs = append(pairs, cookiePair{name: name, value: value})
		}
		if t, ok := setCookieExpires(sc); ok {
			expires[name] = t.Unix()
		}
	}
	var sb strings.Builder
	for i, p := range pairs {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(p.name)
		sb.WriteString("=")
		sb.WriteString(p.value)
	}
	return sb.String(), expires
}

// ---------------------------------------------------------------------------
// MTS cookie auto-refresh (every 24 h + startup staleness check).
// ---------------------------------------------------------------------------

// StartMTSRefresher runs the MTS cookie auto-rotation: one
// AccountUcaas.GetLoginData call every 24 h (a 200 rotates BOTH the
// access (~4 d) and refresh (~31 d) cookies), plus an immediate call at
// startup when the stored access cookie is missing or expired. A failing
// call (non-200, or the response lacks either cookie) marks mts
// login-required so beacons tell clients to re-upload credentials.
func StartMTSRefresher(ctx context.Context, store *CredStore) {
	go func() {
		if mtsAccessStale(store) {
			refreshMTSCookies(ctx, store)
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshMTSCookies(ctx, store)
			}
		}
	}()
}

// mtsAccessStale reports whether the stored MTS access cookie is missing
// or expired (an unknown expiry — raw operator file, never rotated in
// this store — also counts: verify once at startup rather than trusting
// an unknown age).
func mtsAccessStale(store *CredStore) bool {
	header := store.CookieHeader("mts")
	if header == "" {
		return true
	}
	exp, ok := store.CookieExpiry("mts", "access")
	return !ok || !exp.After(time.Now())
}

// refreshMTSCookies performs one GetLoginData rotation and merges the
// returned Set-Cookie values into the store (persisted). Failure marks
// mts login-required.
func refreshMTSCookies(ctx context.Context, store *CredStore) {
	header := store.CookieHeader("mts")
	if header == "" {
		store.SetLoginRequired("mts", true)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	setCookies, err := mtsGetLoginData(cctx, header)
	if err != nil {
		log.Printf("vks mts refresh: %v — marking login required", err)
		store.SetLoginRequired("mts", true)
		return
	}
	if _, err := store.MergeCookies("mts", setCookies); err != nil {
		log.Printf("vks mts refresh: cookies merged but not persisted: %v", err)
	}
	log.Printf("vks mts refresh: cookies rotated (%d set-cookie values merged)", len(setCookies))
}
