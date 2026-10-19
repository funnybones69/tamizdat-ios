package tamizdat

import "testing"

// TestSingleTransportConfigStaysSingle pins the pool sizing the native room
// client depends on.
//
// The native client rides one media room and wants exactly one TLS+H2
// transport over it. But applyDefaults() raises MinTransports to 2 for the
// H2 security defaults, and the MaxTransports < MinTransports clamp then
// drags MaxTransports to 2 as well. The pool reports
//
//	tamizdat: pool at MaxTransports cap: cap=2
//
// whenever both transport slots are busy — and UDP flows (DNS, QUIC, APNs)
// are classified realtime, needing the spare slot, so they failed outright
// while TCP kept working. A live log carried that line 176 times in a few
// minutes.
//
// A caller that disables the security defaults and asks for one transport
// must get one.
func TestSingleTransportConfigStaysSingle(t *testing.T) {
	cfg := ClientConfig{
		ServerAddr:             "vks-dc:443",
		ServerName:             "ya.ru",
		MinTransports:          1,
		MaxTransports:          1,
		DisableDefaultSecurity: true,
		TCPFragmentation:       true,
		RecordFragmentation:    true,
		CoverTrafficEnabled:    false,
	}
	cfg.applyDefaults()
	if cfg.MinTransports != 1 || cfg.MaxTransports != 1 {
		t.Fatalf("pool sizing = %d..%d, want 1..1: a second transport makes the "+
			"pool report a cap and realtime (UDP) flows fail",
			cfg.MinTransports, cfg.MaxTransports)
	}

	// The security-defaults path still sizes the pool to 2 as before, so the
	// normal H2 client is unaffected.
	def := ClientConfig{ServerAddr: "host:443", ServerName: "ya.ru"}
	def.applyDefaults()
	if def.MaxTransports < 2 {
		t.Fatalf("default config MaxTransports = %d, want >= 2", def.MaxTransports)
	}
}
