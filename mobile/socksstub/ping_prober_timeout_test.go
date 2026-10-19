package socksstub

import (
	"testing"
	"time"
)

// TestProbeTimeoutsFollowCarrier pins the probe budget per carrier.
//
// The ping prober's first probe used to run with a flat 5 s budget. That is
// enough for the H2 endpoint it was written for, but a whitelist carrier has
// to join a media room, publish its track and wait for the server's
// discovery answer before a single byte can move - measured at ~13 s on a
// live Telemost room. The shield therefore painted red on a tunnel that was
// about to come up, and the operator saw "Нет связи" with traffic already
// flowing. Whitelist carriers get a budget that covers the join; Main keeps
// the original numbers so H2 behaviour does not change.
func TestProbeTimeoutsFollowCarrier(t *testing.T) {
	prev := CurrentUpstreamMode()
	t.Cleanup(func() { SetUpstreamMode(prev) })

	SetUpstreamMode("main")
	steady, first := probeTimeouts()
	if steady != pingProbeTimeout || first != pingProbeTimeoutFirst {
		t.Fatalf("main: got steady=%s first=%s, want %s/%s",
			steady, first, pingProbeTimeout, pingProbeTimeoutFirst)
	}

	SetUpstreamMode("vks")
	steady, first = probeTimeouts()
	if steady != pingProbeTimeoutVKS || first != pingProbeTimeoutVKSFirst {
		t.Fatalf("vks: got steady=%s first=%s, want %s/%s",
			steady, first, pingProbeTimeoutVKS, pingProbeTimeoutVKSFirst)
	}
	// The whole point: the first probe must outlast a cold room join.
	const coldJoin = 13 * time.Second
	if first < coldJoin {
		t.Fatalf("vks first-probe budget %s is shorter than a measured cold join (%s)", first, coldJoin)
	}
	if steady >= first {
		t.Fatalf("steady budget %s should be below the first-probe budget %s", steady, first)
	}
}
