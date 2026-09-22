package vks

import (
	"context"
	"log"
	"math/rand"
	"strings"
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
		// Random provider order per cycle: the user's flow — the client
		// picks a random enabled provider, beacons it, and the server
		// answers with an assigned room (TXT). Failover walks the rest.
		order := shuffledSpecs(specs)
		for i, cfg := range order {
			if ctx.Err() != nil {
				return nil
			}
			// On-demand: ask the server for a room on this provider. The
			// server creates a fresh one (WB/Jazz) or assigns an armed one,
			// answering in-band with the room spec; the client connects to
			// the ASSIGNED room instead of its statically configured one.
			if cfg.WakeDNSServer != "" && cfg.WakeZone != "" {
				spec, err := SendWakeProvider(ctx, cfg.WakeDNSServer, cfg.WakeZone, cfg.KeyHex, cfg.Provider)
				if err != nil {
					log.Printf("vks ladder: provider beacon for %s failed: %v", cfg.Provider, err)
					// Fall back to the static room beacon.
					rk := RoomWakeKey(cfg.KeyHex, cfg.Provider, cfg.RoomURL)
					_ = SendWake(ctx, cfg.WakeDNSServer, cfg.WakeZone, rk)
				} else {
					log.Printf("vks ladder: server assigned room %q (provider %s)", spec, cfg.Provider)
					if p, r, ok := splitProviderRoom(spec); ok {
						cfg.Provider, cfg.RoomURL = p, r
					}
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(3 * time.Second):
				}
			}
			log.Printf("vks ladder: cycle=%d profile=%d/%d provider=%s room=%s", cycle, i+1, len(order), cfg.Provider, cfg.RoomURL)
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

// shuffledSpecs returns the specs in a random order (a copy).
func shuffledSpecs(specs []ClientConfig) []ClientConfig {
	out := make([]ClientConfig, len(specs))
	copy(out, specs)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// splitProviderRoom splits an assigned-room spec "provider:roomURL" into
// its parts. Returns ok=false on malformed specs.
func splitProviderRoom(spec string) (string, string, bool) {
	i := strings.Index(spec, ":")
	if i <= 0 || i+1 >= len(spec) {
		return "", "", false
	}
	return spec[:i], spec[i+1:], true
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
