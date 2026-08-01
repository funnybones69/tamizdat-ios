package wgturnclient

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func testRoomCreds(label string) *Credentials {
	return &Credentials{
		User:     "user-" + label,
		Pass:     "pass-" + label,
		TurnURLs: []string{"relay.example:3478"},
		Lifetime: 3600,
	}
}

func TestLegacySingleRoomPlannerTwenty(t *testing.T) {
	plans := buildWorkerGroupPlans(20, 0, 0)
	if len(plans) != 2 {
		t.Fatalf("plans=%d, want 2", len(plans))
	}
	if plans[0].hashIndex != 0 || plans[0].workerCount != 12 || plans[1].hashIndex != 0 || plans[1].workerCount != 8 {
		t.Fatalf("legacy plans=%+v, want one room planned as 12+8", plans)
	}
}

func TestNewLegacySingleRoomPreservesTwentyWorkers(t *testing.T) {
	runner, err := New(Config{
		PeerAddr:       "127.0.0.1:443",
		Workers:        20,
		UseUDP:         true,
		PreloadedCreds: testRoomCreds("legacy"),
	})
	if err != nil {
		t.Fatalf("New legacy single-room: %v", err)
	}
	if runner.cfg.Workers != 20 {
		t.Fatalf("effective workers=%d, want 20", runner.cfg.Workers)
	}
	plans := buildWorkerGroupPlans(runner.cfg.Workers, len(runner.cfg.VKHashes), runner.cfg.WorkersPerRoom)
	if len(plans) != 2 || plans[0].workerCount != 12 || plans[1].workerCount != 8 {
		t.Fatalf("effective plans=%+v, want 12+8", plans)
	}
}

func TestSessionMemoryProfileFixedSocketBuffersAndQueueBudgets(t *testing.T) {
	single := memoryProfileForWorkers(20, false)
	if single.socketBufferSize != workerSocketBufferSize || single.workerSendBuffer != singleRoomWorkerSendBuf {
		t.Fatalf("single-room profile=%+v, want fixed %d/%d", single, workerSocketBufferSize, singleRoomWorkerSendBuf)
	}

	oneExplicitRoom := memoryProfileForWorkers(20, true)
	if oneExplicitRoom.socketBufferSize != workerSocketBufferSize {
		t.Fatalf("explicit-room socket=%d, want fixed %d", oneExplicitRoom.socketBufferSize, workerSocketBufferSize)
	}
	if got := 20 * oneExplicitRoom.socketBufferSize * 2; got > multiRoomSocketBudget {
		t.Fatalf("one explicit room requested socket memory=%d, budget=%d", got, multiRoomSocketBudget)
	}
	if got := 20 * oneExplicitRoom.workerSendBuffer * readBufSize; got > multiRoomQueueBudget {
		t.Fatalf("one explicit room queued payload memory=%d, budget=%d", got, multiRoomQueueBudget)
	}

	multi := memoryProfileForWorkers(80, true)
	if multi.socketBufferSize != workerSocketBufferSize || multi.workerSendBuffer != multiRoomQueueBudget/80/readBufSize {
		t.Fatalf("multi-room profile=%+v, want fixed socket + budget-derived queue", multi)
	}
	if got := 80 * multi.workerSendBuffer * readBufSize; got > multiRoomQueueBudget {
		t.Fatalf("multi-room queued payload memory=%d, budget=%d", got, multiRoomQueueBudget)
	}

	twoRooms := memoryProfileForWorkers(40, true)
	if got := 40 * twoRooms.socketBufferSize * 2; got > multiRoomSocketBudget {
		t.Fatalf("two-room requested socket memory=%d, budget=%d", got, multiRoomSocketBudget)
	}
	if got := 40 * twoRooms.workerSendBuffer * readBufSize; got > multiRoomQueueBudget {
		t.Fatalf("two-room queued payload memory=%d, budget=%d", got, multiRoomQueueBudget)
	}

	// Beyond-admission worker counts keep the fixed socket size; the socket
	// budget is enforced by MaxBudgetedRooms admission, not by shrinking.
	scaled := memoryProfileForWorkers(160, true)
	if scaled.socketBufferSize != workerSocketBufferSize {
		t.Fatalf("scaled socket=%d, want fixed %d", scaled.socketBufferSize, workerSocketBufferSize)
	}
	if scaled.workerSendBuffer != minWorkerSendBuf {
		t.Fatalf("scaled queue=%d, want floor %d", scaled.workerSendBuffer, minWorkerSendBuf)
	}
	if got := 160 * scaled.workerSendBuffer * readBufSize; got <= multiRoomQueueBudget {
		t.Fatalf("scaled queue memory=%d unexpectedly fits four-room budget=%d", got, multiRoomQueueBudget)
	}
}

func TestMaxBudgetedRoomsHonorsPerWorkerFloors(t *testing.T) {
	if got := MaxBudgetedRooms(20); got != 6 {
		t.Fatalf("MaxBudgetedRooms(20)=%d, want 6", got)
	}
	maxWorkers := MaxBudgetedRooms(20) * 20
	maxProfile := memoryProfileForWorkers(maxWorkers, true)
	if got := maxWorkers * maxProfile.socketBufferSize * 2; got > multiRoomSocketBudget {
		t.Fatalf("max-room socket request=%d, budget=%d", got, multiRoomSocketBudget)
	}
	if got := maxWorkers * maxProfile.workerSendBuffer * readBufSize; got > multiRoomQueueBudget {
		t.Fatalf("max-room queue=%d, budget=%d", got, multiRoomQueueBudget)
	}
	maxPlusOneWorkers := (MaxBudgetedRooms(20) + 1) * 20
	maxPlusOneProfile := memoryProfileForWorkers(maxPlusOneWorkers, true)
	if got := maxPlusOneWorkers * maxPlusOneProfile.workerSendBuffer * readBufSize; got <= multiRoomQueueBudget {
		t.Fatalf("max+1 queue=%d unexpectedly fits budget=%d", got, multiRoomQueueBudget)
	}
}

func TestMultiRoomPlannerUsesOneWorkerRollingGroups(t *testing.T) {
	plans := buildWorkerGroupPlans(80, 4, 20)
	if len(plans) != 80 {
		t.Fatalf("plans=%d, want 80", len(plans))
	}
	for room := 0; room < 4; room++ {
		for worker := 0; worker < 20; worker++ {
			plan := plans[room*20+worker]
			if plan.hashIndex != room || plan.roomID != room || plan.workerCount != 1 {
				t.Fatalf("room %d worker %d plan=%+v, want single-worker room plan", room, worker, plan)
			}
		}
	}
}

func TestNewRequiresCompleteDistinctMultiRoomCredentials(t *testing.T) {
	hashes := []string{"room-a", "room-b", "room-c", "room-d"}
	creds := map[string]*Credentials{}
	for _, hash := range hashes {
		creds[hash] = testRoomCreds(hash)
	}
	runner, err := New(Config{
		PeerAddr:             "127.0.0.1:443",
		UseUDP:               true,
		WorkersPerRoom:       20,
		VKHashes:             hashes,
		PreloadedCredsByHash: creds,
	})
	if err != nil {
		t.Fatalf("New 4x20: %v", err)
	}
	if runner.cfg.Workers != 80 {
		t.Fatalf("workers=%d, want 80", runner.cfg.Workers)
	}

	delete(creds, "room-d")
	if _, err := New(Config{PeerAddr: "127.0.0.1:443", UseUDP: true, WorkersPerRoom: 20, VKHashes: hashes, PreloadedCredsByHash: creds}); err == nil {
		t.Fatal("expected incomplete credential map rejection")
	}
	if _, err := New(Config{PeerAddr: "127.0.0.1:443", UseUDP: true, WorkersPerRoom: 21, VKHashes: []string{"room-a"}, PreloadedCredsByHash: map[string]*Credentials{"room-a": testRoomCreds("a")}}); err == nil {
		t.Fatal("expected workers-per-room cap rejection")
	}
}

func TestNewSupportsRoomsBeyondLegacyFour(t *testing.T) {
	hashes := []string{"room-a", "room-b", "room-c", "room-d", "room-e", "room-f"}
	creds := make(map[string]*Credentials, len(hashes))
	for _, hash := range hashes {
		creds[hash] = testRoomCreds(hash)
	}
	runner, err := New(Config{
		PeerAddr: "127.0.0.1:443", UseUDP: true, BondV2: true,
		WorkersPerRoom: 20, VKHashes: hashes, PreloadedCredsByHash: creds,
	})
	if err != nil {
		t.Fatalf("New 6x20: %v", err)
	}
	if runner.cfg.Workers != 120 {
		t.Fatalf("workers=%d, want 120", runner.cfg.Workers)
	}
	tooMany := append(append([]string(nil), hashes...), "room-g")
	tooManyCreds := make(map[string]*Credentials, len(tooMany))
	for _, hash := range tooMany {
		tooManyCreds[hash] = testRoomCreds(hash)
	}
	if _, err := New(Config{
		PeerAddr: "127.0.0.1:443", UseUDP: true, BondV2: true,
		WorkersPerRoom: 12, VKHashes: tooMany, PreloadedCredsByHash: tooManyCreds,
	}); err == nil || !strings.Contains(err.Error(), "at most 6 rooms") {
		t.Fatalf("seven-room error=%v, want six-room cap", err)
	}
}

func TestConfigBrokerRetriesThenDeliversOnce(t *testing.T) {
	broker := &configBroker{ch: make(chan string, 1)}
	if !broker.claim() {
		t.Fatal("first claim failed")
	}
	if broker.claim() {
		t.Fatal("concurrent second claim succeeded")
	}
	broker.complete(false)
	if !broker.claim() {
		t.Fatal("claim after failed delivery did not retry")
	}
	broker.complete(true)
	if broker.claim() {
		t.Fatal("claim after successful delivery succeeded")
	}
}

func TestConfigBrokerRearmsExactlyOneClaimantAfterBondLoss(t *testing.T) {
	broker := &configBroker{ch: make(chan string, 1)}
	if !broker.claim() {
		t.Fatal("initial claim failed")
	}
	broker.complete(true)
	if !broker.rearmAfterBondLoss() {
		t.Fatal("completed broker did not rearm")
	}
	if broker.rearmAfterBondLoss() {
		t.Fatal("second rearm succeeded without another delivery")
	}
	if !broker.claim() {
		t.Fatal("rearmed broker did not elect a claimant")
	}
	if broker.claim() {
		t.Fatal("rearmed broker elected more than one claimant")
	}
	broker.complete(true)
}

func TestBondConfigRearmOnlyForFullTimeoutOrMissingBond(t *testing.T) {
	if shouldRearmBondConfig(true, false, errSessionReadTimeout, 1) {
		t.Fatal("partial worker timeout rearmed the shared bond")
	}
	if !shouldRearmBondConfig(true, false, errSessionReadTimeout, 0) {
		t.Fatal("full worker timeout did not rearm the shared bond")
	}
	if !shouldRearmBondConfig(true, false, bondNegotiationError{Reason: "bind wait timeout"}, 3) {
		t.Fatal("missing server bond did not rearm claimant")
	}
	if shouldRearmBondConfig(true, true, bondNegotiationError{Reason: "bind wait timeout"}, 0) {
		t.Fatal("current claimant tried to rearm itself")
	}
	if shouldRearmBondConfig(false, false, errSessionReadTimeout, 0) {
		t.Fatal("legacy mode rearmed Bond v2 claimant")
	}
}

func TestTURNQuotaErrorsRemainRetryableWithBoundedStagger(t *testing.T) {
	errText := "TURN allocate: Allocate error response (error 486: Allocation Quota Reached)"
	if !isTURNQuotaError(errText) {
		t.Fatalf("486 error was not classified as retryable quota: %q", errText)
	}
	if !isTURNQuotaError("TURN квота исчерпана") {
		t.Fatal("localized TURN quota error was not classified as retryable")
	}
	if isTURNQuotaError(errors.New("connection refused").Error()) {
		t.Fatal("non-quota error was classified as TURN quota")
	}

	first := quotaRetryDelay(1, 1)
	if first < 10*time.Second || first >= 20*time.Second {
		t.Fatalf("first quota retry=%v, want [10s,20s)", first)
	}
	steady := quotaRetryDelay(20, 1)
	if steady < 60*time.Second || steady >= 70*time.Second {
		t.Fatalf("steady quota retry=%v, want [60s,70s)", steady)
	}
	if other := quotaRetryDelay(20, 2); other == steady {
		t.Fatalf("worker retry staggering collapsed: worker1=%v worker2=%v", steady, other)
	}
}

func TestQuotaRetryCredentialRevisionGate(t *testing.T) {
	tests := []struct {
		name     string
		captured uint64
		current  uint64
		want     bool
	}{
		{name: "unchanged", captured: 7, current: 7, want: false},
		{name: "older", captured: 7, current: 6, want: false},
		{name: "advanced", captured: 7, current: 8, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := credentialsRevisionAdvanced(tc.captured, tc.current); got != tc.want {
				t.Fatalf("credentialsRevisionAdvanced(%d, %d)=%t want=%t", tc.captured, tc.current, got, tc.want)
			}
		})
	}
}

func TestQuotaRetryWakesImmediatelyOnCredentialUpdate(t *testing.T) {
	runner := &Runner{credsChanged: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan bool, 1)
	started := time.Now()
	go func() {
		done <- runner.waitForQuotaRetry(ctx, 0, 10*time.Second)
	}()

	time.Sleep(10 * time.Millisecond)
	runner.credsRevision.Add(1)
	runner.signalCredentialsUpdated()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("quota retry treated credential wake as cancellation")
		}
		if elapsed := time.Since(started); elapsed >= time.Second {
			t.Fatalf("credential update did not interrupt quota backoff: %v", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("quota retry remained asleep after credential update")
	}
}

func TestQuotaRetryObservesUpdateBeforeSignalCapture(t *testing.T) {
	runner := &Runner{credsChanged: make(chan struct{})}
	runner.credsRevision.Store(2)
	started := time.Now()
	if !runner.waitForQuotaRetry(context.Background(), 1, time.Second) {
		t.Fatal("advanced revision was not accepted")
	}
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("advanced revision waited for timer: %v", elapsed)
	}
}

func TestCredentialPushesAdvanceRevision(t *testing.T) {
	legacy := &Runner{}
	legacy.UpdatePreloadedCreds(testRoomCreds("legacy-refresh"))
	if got := legacy.credsRevision.Load(); got != 1 {
		t.Fatalf("legacy credentials revision=%d want=1", got)
	}

	multi := &Runner{
		cfg:       Config{WorkersPerRoom: 20, VKHashes: []string{"room-a", "room-b"}},
		roomCreds: make(map[string]roomCredentialCacheEntry),
	}
	multi.updateRoomCreds("room-a", testRoomCreds("old-a"))
	multi.updateRoomCreds("room-b", testRoomCreds("old-b"))
	if err := multi.UpdatePreloadedCredsByHash(map[string]*Credentials{
		"room-a": testRoomCreds("room-a-refresh"),
		"room-b": testRoomCreds("room-b-refresh"),
	}); err != nil {
		t.Fatal(err)
	}
	if got := multi.credsRevision.Load(); got != 1 {
		t.Fatalf("multi-room credentials revision=%d want=1", got)
	}
	creds, revision, err := multi.getCredsWithRevision(context.Background(), &TurnParams{}, "room-b", NewStats())
	if err != nil {
		t.Fatal(err)
	}
	if revision != 1 || creds.User != "user-room-b-refresh" {
		t.Fatalf("room-b refresh revision=%d user=%q", revision, creds.User)
	}
}

func TestDispatcherDropsStaleWorkerCountNotifications(t *testing.T) {
	d := &Dispatcher{}
	var mu sync.Mutex
	var got []int
	d.onWorkerCount = func(count int) {
		mu.Lock()
		got = append(got, count)
		mu.Unlock()
	}
	d.notifyWorkerCount(2, 2)
	d.notifyWorkerCount(1, 1)
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("notifications=%v want=[2]", got)
	}
}
