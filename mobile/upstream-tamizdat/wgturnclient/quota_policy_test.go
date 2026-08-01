package wgturnclient

import (
	"testing"
	"time"
)

func TestNextQuotaRetryDelay(t *testing.T) {
	for _, tc := range []struct {
		current time.Duration
		want    time.Duration
	}{
		{0, 5 * time.Second},
		{5 * time.Second, 10 * time.Second},
		{10 * time.Second, 20 * time.Second},
		{30 * time.Second, 60 * time.Second},
		{60 * time.Second, 60 * time.Second},
		{2 * time.Minute, 60 * time.Second},
	} {
		if got := nextQuotaRetryDelay(tc.current); got != tc.want {
			t.Fatalf("nextQuotaRetryDelay(%v)=%v want=%v", tc.current, got, tc.want)
		}
	}
}

func TestRotationSleepDurationUsesRollingOffsetsAndFloor(t *testing.T) {
	for _, tc := range []struct {
		lifetime int
		groupID  int
		want     time.Duration
	}{
		{600, 1, 470 * time.Second},
		{600, 2, 460 * time.Second},
		{600, 99, 420 * time.Second},
		{180, 1, 140 * time.Second},
		{30, 1, rotationMinimumInterval},
		{0, 1, (defaultCycleSecs-rotationSafetySeconds)*time.Second - rotationOffsetStep},
	} {
		if got := rotationSleepDuration(tc.lifetime, tc.groupID); got != tc.want {
			t.Fatalf("rotationSleepDuration(%d,%d)=%v want=%v", tc.lifetime, tc.groupID, got, tc.want)
		}
	}
	if got := rotationOffset(999); got != rotationOffsetCap {
		t.Fatalf("rotation offset cap=%v want=%v", got, rotationOffsetCap)
	}
}
