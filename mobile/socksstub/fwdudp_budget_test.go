package socksstub

import "testing"

func TestFwdUDPGlobalEntryBudget(t *testing.T) {
	if got := len(fwdUDPGlobalSlots); got != 0 {
		t.Fatalf("global FWD_UDP budget is dirty before test: %d", got)
	}
	t.Cleanup(func() {
		for len(fwdUDPGlobalSlots) > 0 {
			releaseFwdUDPGlobalEntry()
		}
	})
	for i := 0; i < fwdUDPGlobalMaxEntries; i++ {
		if !tryAcquireFwdUDPGlobalEntry() {
			t.Fatalf("slot %d rejected before cap %d", i, fwdUDPGlobalMaxEntries)
		}
	}
	if tryAcquireFwdUDPGlobalEntry() {
		t.Fatalf("entry above global cap %d was accepted", fwdUDPGlobalMaxEntries)
	}
	for i := 0; i < fwdUDPGlobalMaxEntries; i++ {
		releaseFwdUDPGlobalEntry()
	}
	if got := len(fwdUDPGlobalSlots); got != 0 {
		t.Fatalf("global FWD_UDP budget leaked %d slots", got)
	}
}
