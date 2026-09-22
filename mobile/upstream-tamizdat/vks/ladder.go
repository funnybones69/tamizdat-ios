package vks

import (
	"context"
	"log"
	"time"
)

// RunLadder runs the VKS client over an ordered list of room specs, failing
// over to the next when the active room link dies. This is the fallback
// ladder across providers (telemost → wbstream → jazz → …). All specs share
// the same local SOCKS listener address and tamizdat identity; the listener
// is rebound on each failover (brief blip while a provider switch happens).
//
// retryDelay: pause between a dead profile and the next attempt.
// maxCycles: 0 = loop the ladder forever.
func RunLadder(ctx context.Context, specs []ClientConfig, retryDelay time.Duration, maxCycles int) error {
	if len(specs) == 0 {
		return nil
	}
	if retryDelay <= 0 {
		retryDelay = 2 * time.Second
	}
	for cycle := 1; ; cycle++ {
		for i, cfg := range specs {
			if ctx.Err() != nil {
				return nil
			}
			// On-demand: emit the wake beacon so the server joins this room
			// just in time, then give it a short head start to enter before
			// the client knocks (a guest cannot create the room alone).
			if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
				rk := RoomWakeKey(cfg.KeyHex, cfg.Provider, cfg.RoomURL)
				if err := SendWake(ctx, cfg.WakeDNSServer, cfg.WakeZone, rk); err != nil {
					log.Printf("vks ladder: wake beacon for %s failed: %v", cfg.Provider, err)
				} else {
					log.Printf("vks ladder: wake beacon sent for %s (room %s)", cfg.Provider, cfg.RoomURL)
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(3 * time.Second):
				}
			}
			log.Printf("vks ladder: cycle=%d profile=%d/%d provider=%s room=%s", cycle, i+1, len(specs), cfg.Provider, cfg.RoomURL)
			err := RunClient(ctx, cfg, func() {
				log.Printf("vks ladder: profile %s up (socks %s)", cfg.Provider, cfg.ListenAddr)
			})
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("vks ladder: profile %s ended: %v — failing over", cfg.Provider, err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(retryDelay):
			}
		}
		if maxCycles > 0 && cycle >= maxCycles {
			return nil
		}
	}
}

// ParseSpecs splits a comma-separated provider:room list into configs.
// A comma inside a room URL is not supported (rooms are comma-separated).
func ParseSpecs(list string) ([]Config, error) {
	var out []Config
	for _, spec := range splitSpecs(list) {
		cfg, err := ParseSpec(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, nil
}

func splitSpecs(list string) []string {
	var out []string
	start := 0
	for i := range len(list) {
		if list[i] != ',' {
			continue
		}
		// a comma starts a new spec only if followed by a known provider prefix
		rest := list[i+1:]
		if hasProviderPrefix(rest) {
			out = append(out, list[start:i])
			start = i + 1
		}
	}
	out = append(out, list[start:])
	return out
}

func hasProviderPrefix(s string) bool {
	for _, p := range []string{"telemost:", "wbstream:", "jitsi:", "jazz:", "mts:"} {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}
