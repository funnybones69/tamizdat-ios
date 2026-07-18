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
	creds     *Credentials
	expiresAt time.Time
}

func buildWorkerGroupPlans(totalWorkers, roomCount, workersPerRoom int) []workerGroupPlan {
	if workersPerRoom <= 0 {
		var plans []workerGroupPlan
		remaining := totalWorkers
		for remaining > 0 {
			count := remaining
			if count > workersPerGroup {
				count = workersPerGroup
			}
			// Legacy/preloaded single-room mode has no explicit VKHashes list.
			// Every partial group belongs to the same logical room so runner
			// startup can cascade 12+8 and never index an empty room slice.
			plans = append(plans, workerGroupPlan{hashIndex: 0, roomID: 0, workerCount: count})
			remaining -= count
		}
		return plans
	}
	var plans []workerGroupPlan
	for room := 0; room < roomCount; room++ {
		remaining := workersPerRoom
		for remaining > 0 {
			count := remaining
			if count > workersPerGroup {
				count = workersPerGroup
			}
			plans = append(plans, workerGroupPlan{hashIndex: room, roomID: room, workerCount: count})
			remaining -= count
		}
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

func (r *Runner) currentRoomCreds(hash string) *Credentials {
	r.roomCredsMu.Lock()
	defer r.roomCredsMu.Unlock()
	entry, ok := r.roomCreds[hash]
	if !ok || entry.creds == nil {
		return nil
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(r.roomCreds, hash)
		return nil
	}
	return cloneCredentials(entry.creds)
}

func (r *Runner) updateRoomCreds(hash string, creds *Credentials) {
	if hash == "" || creds == nil {
		return
	}
	expiresAt := time.Time{}
	if creds.Lifetime > 0 {
		expiresAt = time.Now().Add(time.Duration(creds.Lifetime) * time.Second)
	}
	r.roomCredsMu.Lock()
	r.roomCreds[hash] = roomCredentialCacheEntry{creds: cloneCredentials(creds), expiresAt: expiresAt}
	r.roomCredsMu.Unlock()
}

// UpdatePreloadedCredsByHash atomically replaces the per-room snapshots used
// by future rotations. Missing rooms are rejected by the gomobile bridge before
// this method is called, so a live runner never silently degrades to fewer rooms.
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
	r.eventf("info", "multi-room credentials updated rooms=%d", len(creds))
	return nil
}
