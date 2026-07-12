package socksstub

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/funnybones69/tamizdat/wgturnclient"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func TestStopVKTurnUpstreamClearsStaleNetstackWhenNotRunning(t *testing.T) {
	vkturnMu.Lock()
	vkturnRunner = nil
	vkturnCancel = nil
	vkturnAttachStop = nil
	vkturnRunning.Store(false)
	vkturnNet.Store(&netstack.Net{})
	vkturnWGConfig.Store(nil)
	vkturnStats.Store(nil)
	vkturnErr.Store(nil)
	vkturnMu.Unlock()

	StopVKTurnUpstream()

	if got := VKTurnNetstack(); got != nil {
		t.Fatalf("VKTurnNetstack() after StopVKTurnUpstream with running=false = %p, want nil", got)
	}
}

func TestShouldUseUDPIgnoresTurnsEndpoints(t *testing.T) {
	creds := &wgturnclient.Credentials{
		TurnServers: []wgturnclient.TurnServer{
			{Host: "secure.example", Port: 5349, Scheme: "turns", Transport: "udp"},
		},
	}
	if shouldUseUDP(creds) {
		t.Fatal("shouldUseUDP returned true for turns endpoint; TURNS must use TLS/TCP in this client")
	}
}

func TestNormalizeVKTurnWorkers(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, 24},
		{-1, 24},
		{1, 12},
		{12, 12},
		{13, 12},
		{24, 24},
		{36, 36},
		{73, 72},
	}
	for _, tc := range cases {
		if got := normalizeVKTurnWorkers(tc.in); got != tc.want {
			t.Fatalf("normalizeVKTurnWorkers(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseVKTurnRoomCredsJSONRejectsPartialDuplicateAndStaleBundles(t *testing.T) {
	fresh := time.Now().Unix()
	room := func(hash string, acquired int64) string {
		return fmt.Sprintf(`{"hash":%q,"credentials":{"username":"user","password":"pass","turn_servers":["relay.example:3478"],"lifetime_sec":3600,"acquired_at_unix":%d}}`, hash, acquired)
	}
	valid := `{"rooms":[` + room("a", fresh) + `,` + room("b", fresh) + `,` + room("c", fresh) + `,` + room("d", fresh) + `]}`
	hashes, creds, err := parseVKTurnRoomCredsJSON(valid)
	if err != nil {
		t.Fatalf("valid bundle: %v", err)
	}
	if len(hashes) != 4 || len(creds) != 4 {
		t.Fatalf("valid bundle sizes hashes=%d creds=%d", len(hashes), len(creds))
	}

	duplicate := `{"rooms":[` + room("a", fresh) + `,` + room("a", fresh) + `]}`
	if _, _, err := parseVKTurnRoomCredsJSON(duplicate); err == nil {
		t.Fatal("expected duplicate room rejection")
	}
	stale := `{"rooms":[` + room("a", fresh-4000) + `]}`
	if _, _, err := parseVKTurnRoomCredsJSON(stale); err == nil {
		t.Fatal("expected stale credentials rejection")
	}
}

func TestParseVKTurnCredsJSONNormalizesV2SchemeAndTransport(t *testing.T) {
	creds, err := parseVKTurnCredsJSON(`{
		"username":"user",
		"password":"pass",
		"turn_servers_v2":[
			{"host":"udp.example","port":3478,"scheme":"TURN","transport":"UDP"},
			{"host":"secure.example","port":5349,"scheme":"TURNS","transport":"UDP"}
		],
		"lifetime_sec":600
	}`)
	if err != nil {
		t.Fatalf("parseVKTurnCredsJSON: %v", err)
	}
	if len(creds.TurnServers) != 2 {
		t.Fatalf("TurnServers len = %d", len(creds.TurnServers))
	}
	if creds.TurnServers[0].Scheme != "turn" || creds.TurnServers[0].Transport != "udp" {
		t.Fatalf("first server = %+v, want turn/udp", creds.TurnServers[0])
	}
	if creds.TurnServers[1].Scheme != "turns" || creds.TurnServers[1].Transport != "tcp" {
		t.Fatalf("second server = %+v, want turns/tcp", creds.TurnServers[1])
	}
	if strings.Contains(creds.TurnURLs[0], "turn:") || strings.Contains(creds.TurnURLs[1], "turns:") {
		t.Fatalf("TurnURLs should remain legacy host:port values, got %#v", creds.TurnURLs)
	}
}
