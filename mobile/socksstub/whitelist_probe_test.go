package socksstub

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

func TestNormalizeWhitelistProbeHostsSplitsCommaSemicolonAndDedupes(t *testing.T) {
	got := normalizeWhitelistProbeHosts([]string{" google.com, cloudflare.com ", "google.com;example.org\n"})
	want := []string{"google.com", "cloudflare.com", "example.org"}
	if len(got) != len(want) {
		t.Fatalf("len=%d got=%v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestWhitelistProbeClassifiesAllowlistOnlyWhenDomesticPassesAndForeignAllFail(t *testing.T) {
	cfg := whitelistProbeCycleRequest{
		Foreign:   []string{"google.com", "cloudflare.com"},
		Domestic:  []string{"ya.ru", "ozon.ru", "gosuslugi.ru"},
		TimeoutMs: 1000,
		Port:      443,
	}
	probe := func(_ context.Context, host, dialIP string, port, _ int) whitelistProbeTargetResult {
		pass := host == "ya.ru" || host == "ozon.ru" || host == "gosuslugi.ru"
		return whitelistProbeTargetResult{Host: host, Port: port, TCPOK: pass, TLSOK: pass, Pass: pass, ErrorClass: map[bool]string{true: "ok", false: "timeout"}[pass]}
	}
	res := runWhitelistProbeCycle(cfg, probe)
	if res.Classification != "allowlist" {
		t.Fatalf("classification=%q summary=%q res=%+v", res.Classification, res.Summary, res)
	}
	if res.DomesticPass != 3 || res.ForeignPass != 0 {
		t.Fatalf("unexpected pass counts: domestic=%d foreign=%d", res.DomesticPass, res.ForeignPass)
	}
}

func TestWhitelistProbeClassifiesAllowlistWithSingleForeignControl(t *testing.T) {
	cfg := whitelistProbeCycleRequest{
		Foreign:  []string{"google.com"},
		Domestic: []string{"ya.ru"},
		Port:     443,
	}
	probe := func(_ context.Context, host, dialIP string, port, _ int) whitelistProbeTargetResult {
		pass := host == "ya.ru"
		return whitelistProbeTargetResult{Host: host, Port: port, TCPOK: pass, TLSOK: pass, Pass: pass, ErrorClass: map[bool]string{true: "ok", false: "timeout"}[pass]}
	}
	res := runWhitelistProbeCycle(cfg, probe)
	if res.Classification != "allowlist" {
		t.Fatalf("classification=%q summary=%q res=%+v", res.Classification, res.Summary, res)
	}
	if res.DomesticPass != 1 || res.ForeignPass != 0 {
		t.Fatalf("unexpected pass counts: domestic=%d foreign=%d", res.DomesticPass, res.ForeignPass)
	}
}

func TestWhitelistProbePinnedIPPassedToProbe(t *testing.T) {
	cfg := whitelistProbeCycleRequest{
		Foreign:   []string{"google.com"},
		Domestic:  []string{"ya.ru"},
		Port:      443,
		PinnedIPs: map[string]string{"google.com": "93.184.216.34"},
	}
	var mu sync.Mutex
	received := map[string]string{}
	probe := func(_ context.Context, host, dialIP string, port, _ int) whitelistProbeTargetResult {
		mu.Lock()
		received[host] = dialIP
		mu.Unlock()
		return whitelistProbeTargetResult{Host: host, Port: port}
	}
	_ = runWhitelistProbeCycle(cfg, probe)

	mu.Lock()
	defer mu.Unlock()
	if got := received["google.com"]; got != "93.184.216.34" {
		t.Fatalf("google.com dialIP=%q want %q", got, "93.184.216.34")
	}
	if got := received["ya.ru"]; got != "" {
		t.Fatalf("ya.ru dialIP=%q want empty", got)
	}
}

func TestWhitelistProbeClassifiesPartialWhenSomeForeignPass(t *testing.T) {
	cfg := whitelistProbeCycleRequest{Foreign: []string{"google.com", "cloudflare.com"}, Domestic: []string{"ya.ru", "ozon.ru", "gosuslugi.ru"}, Port: 443}
	probe := func(_ context.Context, host, dialIP string, port, _ int) whitelistProbeTargetResult {
		pass := host != "cloudflare.com"
		return whitelistProbeTargetResult{Host: host, Port: port, TCPOK: pass, TLSOK: pass, Pass: pass}
	}
	res := runWhitelistProbeCycle(cfg, probe)
	if res.Classification != "partial" {
		t.Fatalf("classification=%q want partial", res.Classification)
	}
}

func TestWhitelistProbeJSONIncludesRemoteAddress(t *testing.T) {
	res := whitelistProbeCycleResult{
		OK:             true,
		Classification: "normal",
		Targets: []whitelistProbeTargetResult{{
			Group:         "foreign",
			Host:          "example.com",
			Port:          443,
			TCPOK:         true,
			TLSOK:         true,
			Pass:          true,
			RemoteAddress: "192.0.2.10:443",
		}},
	}
	out := marshalWhitelistProbeResult(res)
	var decoded whitelistProbeCycleResult
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("bad json: %v out=%s", err, out)
	}
	if len(decoded.Targets) != 1 || decoded.Targets[0].RemoteAddress != "192.0.2.10:443" {
		t.Fatalf("remote address missing: %+v", decoded.Targets)
	}
}

func TestWhitelistProbeNetworkMatchesIPv4OnlyTunnel(t *testing.T) {
	if whitelistProbeNetwork != "tcp4" {
		t.Fatalf("network=%q want tcp4", whitelistProbeNetwork)
	}
}

func TestRunWhitelistProbeCycleJSONDefaultsAndMarshals(t *testing.T) {
	out := RunWhitelistProbeCycleJSON(`{"timeout_ms":1,"foreign":["203.0.113.1","198.51.100.1"],"domestic":["192.0.2.1"]}`)
	var res whitelistProbeCycleResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("bad json: %v out=%s", err, out)
	}
	if !res.OK {
		t.Fatalf("expected ok result, got %+v", res)
	}
	if res.Classification == "" {
		t.Fatalf("missing classification: %+v", res)
	}
}
