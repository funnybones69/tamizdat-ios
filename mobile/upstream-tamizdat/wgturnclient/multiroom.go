package wgturnclient

import (
	"fmt"
	"time"
)

type workerGroupPlan struct {
	hashIndex   int
	roomID      int
	workerCount int
}

type roomCredentialCacheEntry struct {
	creds      *Credentials
	expiresAt  time.Time
	validUntil time.Time
}

func buildWorkerGroupPlans(totalWorkers, roomCount, workersPerRoom int) []workerGroupPlan {
	var plans []workerGroupPlan
	if workersPerRoom > 0 {
		if roomCount < 1 {
			return nil
		}
		// One allocation per lifecycle group makes every explicit-room
		// replacement kill-one-add-one instead of replacing 12 workers at once.
		for room := 0; room < roomCount; room++ {
			for worker := 0; worker < workersPerRoom; worker++ {
				plans = append(plans, workerGroupPlan{hashIndex: room, roomID: room, workerCount: multiRoomGroupSize})
			}
		}
		return plans
	}

	remaining := totalWorkers
	for remaining > 0 {
		count := remaining
		if count > workersPerGroup {
			count = workersPerGroup
		}
		// Legacy/preloaded single-room mode keeps the iOS 12+partial batching
		// and belongs to one logical room even before a hash is synthesized.
		plans = append(plans, workerGroupPlan{hashIndex: 0, roomID: 0, workerCount: count})
		remaining -= count
	}
	return plans
}

func cloneCredentials(creds *Credentials) *Credentials {
	if creds == nil {
		return nil
	}
	dup := *creds
	dup.TurnURLs = append([]string(nil), creds.TurnURLs...)
	dup.TurnServers = append([]TurnServer(nil), creds.TurnServers...)
	return &dup
}

func credentialReuseDuration(creds *Credentials) time.Duration {
	lifetime := 600
	if creds != nil && creds.Lifetime > 0 {
		lifetime = creds.Lifetime
	}
	safety := rotationSafetySeconds
	if lifetime <= 240 {
		safety = 30
	}
	if lifetime <= 60 {
		safety = 5
	}
	seconds := lifetime - safety
	if seconds < 5 {
		seconds = 5
	}
	return time.Duration(seconds) * time.Second
}

func (r *Runner) currentRoomCreds(hash string) *Credentials {
	r.roomCredsMu.Lock()
	defer r.roomCredsMu.Unlock()
	entry, ok := r.roomCreds[hash]
	if !ok || entry.creds == nil {
		return nil
	}
	if !entry.expiresAt.IsZero() && !time.Now().Before(entry.expiresAt) {
		delete(r.roomCreds, hash)
		return nil
	}
	dup := cloneCredentials(entry.creds)
	if !entry.validUntil.IsZero() {
		remaining := int(time.Until(entry.validUntil).Seconds())
		if remaining <= 0 {
			delete(r.roomCreds, hash)
			return nil
		}
		dup.Lifetime = remaining
	}
	return dup
}

func (r *Runner) updateRoomCreds(hash string, creds *Credentials) {
	if hash == "" || creds == nil {
		return
	}
	now := time.Now()
	lifetime := creds.Lifetime
	if lifetime <= 0 {
		lifetime = 600
	}
	r.roomCredsMu.Lock()
	r.roomCreds[hash] = roomCredentialCacheEntry{
		creds:      cloneCredentials(creds),
		expiresAt:  now.Add(credentialReuseDuration(creds)),
		validUntil: now.Add(time.Duration(lifetime) * time.Second),
	}
	r.roomCredsMu.Unlock()
}

// UpdatePreloadedCredsByHash atomically replaces the complete iOS room bundle.
// Missing rooms remain a hard error so a live runner cannot silently degrade.
func (r *Runner) UpdatePreloadedCredsByHash(creds map[string]*Credentials) error {
	if r.cfg.WorkersPerRoom <= 0 {
		return fmt.Errorf("runner is not in multi-room mode")
	}
	if len(creds) != len(r.cfg.VKHashes) {
		return fmt.Errorf("credential bundle room count mismatch")
	}
	for _, hash := range r.cfg.VKHashes {
		if creds[hash] == nil {
			return fmt.Errorf("credential bundle missing configured room")
		}
	}
	for hash, snapshot := range creds {
		r.updateRoomCreds(hash, snapshot)
	}
	r.credsRevision.Add(1)
	r.signalCredentialsUpdated()
	r.eventf("info", "multi-room credentials updated rooms=%d", len(creds))
	return nil
}

// credentialsForAttempt reads the latest published generation before every
// retry so sibling groups and Swift credential pushes are observed promptly.
func (r *Runner) credentialsForAttempt(hash string, fallback *Credentials) *Credentials {
	if r.cfg.WorkersPerRoom > 0 {
		if current := r.currentRoomCreds(hash); current != nil {
			return current
		}
	} else if current := r.currentPreloadedCreds(); current != nil {
		return current
	}
	return fallback
}

func sameCredentialGeneration(a, b *Credentials) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.User == b.User && a.Pass == b.Pass
}

// invalidateCredentials removes only the generation that received TURN 486.
// A stale sibling can never erase a newer generation already pushed by Swift.
func (r *Runner) invalidateCredentials(hash string, stale *Credentials) {
	if r.cfg.WorkersPerRoom > 0 {
		r.roomCredsMu.Lock()
		defer r.roomCredsMu.Unlock()
		entry, ok := r.roomCreds[hash]
		if !ok || entry.creds == nil || !sameCredentialGeneration(entry.creds, stale) {
			return
		}
		delete(r.roomCreds, hash)
		return
	}

	r.preloadedCredsMu.Lock()
	defer r.preloadedCredsMu.Unlock()
	current := r.preloadedCreds.Load()
	if current == nil || !sameCredentialGeneration(current, stale) {
		return
	}
	r.preloadedCreds.Store(nil)
}
