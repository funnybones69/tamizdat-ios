// Package vks carries Tamizdat client traffic through third-party Russian
// video-conferencing (ВКС) rooms — Yandex Telemost, WB Stream, SaluteJazz,
// MTS Link, Jitsi — so clients behind whitelist-only networks reach the
// Tamizdat server while looking like ordinary call participants.
//
// Integration uses the vendored olcRTC stack (internal/vks/olc, WTFPL):
// its engines (goolom/livekit/jitsi + custom jazz/mts) and vp8channel KCP
// transport carry the olcrtc wire (epoch handshake + XChaCha20 + smux).
// Tamizdat identity/auth/routing/accounting plug in at the seam:
//   - server: AuthHook validates the tamizdat shortID from handshake claims
//     via the panel user registry; DialHook routes each CONNECT through the
//     tamizdat outbound registry; OnTraffic feeds per-user accounting.
//   - client: runs the vendored SOCKS5 client with the shortID in claims.
package vks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport/seichannel"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport/vp8channel"
)

// Config describes one VKS room endpoint shared by the server wrapper and the
// client wrapper.
type Config struct {
	// Provider selects the VKS service: telemost, wbstream, jitsi, jazz, mts.
	Provider string
	// RoomURL is the provider room identifier (Telemost room URL, WB room id,
	// Jazz room link, Jitsi host/room, MTS room link).
	RoomURL string
	// ProviderToken is an optional account token for providers whose room
	// creation or publish rights need an account (WB Stream). Empty = guest.
	ProviderToken string
	// Transport selects the in-room carrier: vp8channel (default, fastest,
	// proven) or datachannel.
	Transport string
	// KeyHex is the shared olcRTC wire key (64 hex chars), preventing random
	// room participants from consuming the server. Tamizdat shortID auth
	// still applies on top.
	KeyHex string
	// Name is the display name shown in the room. Empty = generated.
	Name string
	// DNSServer optionally overrides DNS resolution for provider endpoints.
	DNSServer string
}

// transportName picks the in-room carrier. vp8channel (video-frame muling) is
// the fast proven default for SFU providers; jazz uses its native datachannel
// (its SFU carries a "_reliable" datachannel and the engine has no video
// track publishing yet).
func (c Config) transportName() string {
	if c.Transport != "" {
		return c.Transport
	}
	if c.Provider == "jazz" {
		return "datachannel"
	}
	if c.Provider == "mts" {
		// odin accepts only H264 for video, so the SEI channel (H264) is the
		// carrier the SFU will happily forward.
		return "seichannel"
	}
	return "vp8channel"
}

// transportOptions returns the matching per-transport Options (nil for
// datachannel, which needs none).
func (c Config) transportOptions() transport.Options {
	switch c.transportName() {
	case "vp8channel":
		return vp8channel.Options{FPS: 30, BatchSize: 64}
	case "seichannel":
		opts := seichannel.Options{FPS: 30, BatchSize: 64}
		if n, ok := envInt("VKS_SEI_FPS"); ok {
			opts.FPS = n
		}
		if n, ok := envInt("VKS_SEI_BATCH"); ok {
			opts.BatchSize = n
		}
		if n, ok := envInt("VKS_SEI_FRAG"); ok {
			opts.FragmentSize = n
		}
		if n, ok := envInt("VKS_SEI_ACK"); ok {
			opts.AckTimeoutMS = n
		}
		return opts
	default:
		return nil
	}
}

// ParseSpec parses "provider:roomURL" or "provider://roomURL" shorthand.
// The room part may itself contain "://" (e.g. a full telemost URL).
func ParseSpec(spec string) (Config, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Config{}, fmt.Errorf("empty vks spec")
	}
	idx := strings.Index(spec, ":")
	if idx <= 0 {
		return Config{}, fmt.Errorf("vks spec %q: want provider:room", spec)
	}
	cfg := Config{Provider: strings.ToLower(strings.TrimSpace(spec[:idx]))}
	room := strings.TrimSpace(spec[idx+1:])
	room = strings.TrimPrefix(room, "//")
	if room == "" {
		return Config{}, fmt.Errorf("vks spec %q: empty room", spec)
	}
	cfg.RoomURL = room
	return cfg, nil
}

// envInt reads an integer override from the environment; the packing sweep
// uses these so transport parameters can be retuned without a rebuild.
func envInt(name string) (int, bool) {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n, true
		}
	}
	return 0, false
}
