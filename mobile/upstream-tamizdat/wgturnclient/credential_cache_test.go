package wgturnclient

import (
	"context"
	"sync"
	"testing"
	"time"
)

func testGenerationCreds(user, pass string) *Credentials {
	return &Credentials{
		User: user, Pass: pass, Lifetime: 600,
		TurnURLs: []string{"turn.example.invalid:3478"},
	}
}

func TestCredentialsForAttemptUsesLatestPublishedGeneration(t *testing.T) {
	r := &Runner{
		cfg:       Config{WorkersPerRoom: 12, VKHashes: []string{"room"}},
		roomCreds: make(map[string]roomCredentialCacheEntry),
	}
	fallback := testGenerationCreds("old-user", "old-pass")
	latest := testGenerationCreds("new-user", "new-pass")
	r.updateRoomCreds("room", latest)
	got := r.credentialsForAttempt("room", fallback)
	if got == nil || got.User != latest.User || got.Pass != latest.Pass {
		t.Fatalf("attempt credentials=%#v want latest generation", got)
	}
}

func TestInvalidateCredentialsCannotDeleteNewerGeneration(t *testing.T) {
	r := &Runner{
		cfg:       Config{WorkersPerRoom: 12, VKHashes: []string{"room"}},
		roomCreds: make(map[string]roomCredentialCacheEntry),
	}
	stale := testGenerationCreds("same-user", "old-pass")
	fresh := testGenerationCreds("same-user", "new-pass")
	r.updateRoomCreds("room", fresh)
	r.invalidateCredentials("room", stale)
	if got := r.currentRoomCreds("room"); got == nil || got.Pass != fresh.Pass {
		t.Fatalf("stale invalidation removed fresh generation: %#v", got)
	}
	r.invalidateCredentials("room", fresh)
	if got := r.currentRoomCreds("room"); got != nil {
		t.Fatalf("matching generation survived invalidation: %#v", got)
	}
}

func TestForcedCredentialRefreshIsPerRoomAndOnePerMinute(t *testing.T) {
	r := &Runner{}
	now := time.Unix(10, 0)
	if !r.reserveForcedCredentialRefresh("room-a", now) {
		t.Fatal("first room-a refresh rejected")
	}
	if r.reserveForcedCredentialRefresh("room-a", now.Add(59*time.Second)) {
		t.Fatal("second room-a refresh inside one minute accepted")
	}
	if !r.reserveForcedCredentialRefresh("room-b", now.Add(time.Second)) {
		t.Fatal("sibling room was rate limited by room-a")
	}
	if !r.reserveForcedCredentialRefresh("room-a", now.Add(time.Minute)) {
		t.Fatal("room-a refresh remained limited after one minute")
	}
}

func TestGenerationRefreshObservesExternalIOSCredentialPush(t *testing.T) {
	stale := testGenerationCreds("stale-user", "stale-pass")
	r := &Runner{
		cfg:           Config{WorkersPerRoom: 12, VKHashes: []string{"room"}},
		roomCreds:     make(map[string]roomCredentialCacheEntry),
		roomAuthLocks: make(map[string]*sync.Mutex),
		forcedCredsAt: make(map[string]time.Time),
	}
	r.updateRoomCreds("room", stale)
	if _, err := r.refreshCredentialsForGeneration(context.Background(), &TurnParams{}, "room", stale, NewStats()); err == nil {
		t.Fatal("missing external generation unexpectedly refreshed")
	}
	fresh := testGenerationCreds("fresh-user", "fresh-pass")
	r.updateRoomCreds("room", fresh)
	got, err := r.refreshCredentialsForGeneration(context.Background(), &TurnParams{}, "room", stale, NewStats())
	if err != nil {
		t.Fatal(err)
	}
	if got.User != fresh.User || got.Pass != fresh.Pass {
		t.Fatalf("refresh=%#v want externally pushed generation", got)
	}
}
