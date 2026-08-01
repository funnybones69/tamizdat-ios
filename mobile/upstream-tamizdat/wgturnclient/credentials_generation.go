package wgturnclient

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const forcedCredentialRefreshInterval = 60 * time.Second

func (r *Runner) reserveForcedCredentialRefresh(hash string, now time.Time) bool {
	key := strings.TrimSpace(hash)
	r.forcedCredsMu.Lock()
	defer r.forcedCredsMu.Unlock()
	if r.forcedCredsAt == nil {
		r.forcedCredsAt = make(map[string]time.Time)
	}
	if last := r.forcedCredsAt[key]; !last.IsZero() && now.Sub(last) < forcedCredentialRefreshInterval {
		return false
	}
	r.forcedCredsAt[key] = now
	return true
}

// refreshCredentialsForGeneration reuses a fresh sibling generation when one
// exists. Otherwise it invalidates exactly the rejected generation and allows
// at most one forced provider attempt per room per minute. On iOS the provider
// is the external Swift refresher, so a missing generation remains retryable.
func (r *Runner) refreshCredentialsForGeneration(ctx context.Context, tp *TurnParams, hash string, previous *Credentials, stats *Stats) (*Credentials, error) {
	authLock := r.credentialLock(hash)
	authLock.Lock()
	defer authLock.Unlock()

	var cached *Credentials
	if r.cfg.WorkersPerRoom > 0 {
		cached = r.currentRoomCreds(hash)
	} else {
		cached = r.currentPreloadedCreds()
	}
	if cached != nil && !sameCredentialGeneration(cached, previous) {
		return cached, nil
	}
	r.invalidateCredentials(hash, previous)
	if !r.reserveForcedCredentialRefresh(hash, time.Now()) {
		return nil, fmt.Errorf("forced credential refresh is temporarily rate limited")
	}
	return r.getCredsWithFallback(ctx, tp, hash, stats)
}
