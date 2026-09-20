package vks

import (
	"context"
	"fmt"

	olcclient "github.com/funnybones69/tamizdat/vks/olc/core/client"
	"github.com/funnybones69/tamizdat/vks/olc/core/app/session"
)

// ClientConfig extends Config with the tamizdat user identity and the local
// SOCKS5 listener address.
type ClientConfig struct {
	Config
	// ShortIDHex is the tamizdat master_shortid presented in the handshake
	// claims (the room itself is shared/anonymous; the user is authenticated
	// inside the encrypted olcRTC wire).
	ShortIDHex string
	// ListenAddr is the local SOCKS5 bind, e.g. 127.0.0.1:11080.
	ListenAddr string
	// DeviceIDPath optionally persists a stable olcRTC device id.
	DeviceIDPath string
}

// RunClient joins the room as a client participant and serves SOCKS5 on
// ListenAddr. Blocking until ctx is cancelled or the link dies.
func RunClient(ctx context.Context, cfg ClientConfig, onReady func()) error {
	if cfg.ShortIDHex == "" {
		return fmt.Errorf("vks: shortid required")
	}
	session.RegisterDefaults()
	return olcclient.RunWithReady(ctx, olcclient.Config{
		Transport:                  cfg.transportName(),
		Provider:                   cfg.Provider,
		RoomURL:                    cfg.RoomURL,
		KeyHex:                     cfg.KeyHex,
		LocalAddr:                  cfg.ListenAddr,
		DNSServer:                  cfg.DNSServer,
		ProviderToken:              cfg.ProviderToken,
		TransportOptions:           cfg.transportOptions(),
		DeviceIDPath:               cfg.DeviceIDPath,
		Claims:                     map[string]any{"shortid": cfg.ShortIDHex},
		ExitOnReconnectExhaustion:  true,
	}, onReady)
}
