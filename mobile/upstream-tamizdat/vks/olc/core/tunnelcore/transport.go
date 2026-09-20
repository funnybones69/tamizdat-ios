package tunnelcore

import (
	"net"
	"os"
	"strings"

	"github.com/funnybones69/tamizdat/vks/olc/core/names"
	"github.com/funnybones69/tamizdat/vks/olc/core/transport"
)

// LinkConfig contains transport fields shared by server and client roles.
type LinkConfig struct {
	Provider      string
	RoomURL       string
	Engine        string
	URL           string
	Token         string
	ProviderToken string
	ChannelID     string
	DNSServer     string
	Options       transport.Options
	Traffic       transport.TrafficConfig
}

// LinkRoleConfig contains transport fields that differ by tunnel role.
type LinkRoleConfig struct {
	DeviceID            string
	OnData              func([]byte)
	OnPeerData          func(string, []byte)
	Resolver            *net.Resolver
	ProxyAddr           string
	ProxyPort           int
	RequireTargetedPeer bool
}

// BuildTransportConfig combines shared link settings with role-specific callbacks.
func BuildTransportConfig(base LinkConfig, role LinkRoleConfig) transport.Config {
	return transport.Config{
		Provider:            base.Provider,
		RoomURL:             base.RoomURL,
		Engine:              base.Engine,
		URL:                 base.URL,
		Token:               base.Token,
		ProviderToken:       base.ProviderToken,
		ChannelID:           base.ChannelID,
		DeviceID:            role.DeviceID,
		Name:                participantName(),
		OnData:              role.OnData,
		OnPeerData:          role.OnPeerData,
		DNSServer:           base.DNSServer,
		Resolver:            Resolver(role.Resolver, base.DNSServer),
		ProxyAddr:           role.ProxyAddr,
		ProxyPort:           role.ProxyPort,
		RequireTargetedPeer: role.RequireTargetedPeer,
		Options:             base.Options,
		Traffic:             base.Traffic,
	}
}

// participantName returns the display name for this participant. VKS_NAME
// overrides the random pool (used to keep one stable identity while a room
// owner grants roles); otherwise a realistic random name is generated.
func participantName() string {
	if n := strings.TrimSpace(os.Getenv("VKS_NAME")); n != "" {
		return n
	}
	return names.Generate()
}
