package socksstub

import (
	"context"
	"encoding/json"
	"errors"
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
	vkturnRunDone = nil
	vkturnDraining = nil
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

func TestStopVKTurnUpstreamWaitsForWorkerDrain(t *testing.T) {
	done := make(chan struct{})
	runner := &wgturnclient.Runner{}
	vkturnMu.Lock()
	vkturnRunner = runner
	vkturnTelemetryOwner = runner
	vkturnCancel = nil
	vkturnRunDone = done
	vkturnDraining = nil
	vkturnAttachStop = nil
	vkturnRunning.Store(true)
	vkturnNet.Store(&netstack.Net{})
	vkturnTelemetry.Store(nil)
	vkturnStats.Store(nil)
	beforeGeneration := vkturnGeneration.Load()
	vkturnMu.Unlock()
	defer func() {
		vkturnMu.Lock()
		vkturnRunner = nil
		vkturnTelemetryOwner = nil
		vkturnCancel = nil
		vkturnRunDone = nil
		vkturnDraining = nil
		vkturnRunning.Store(false)
		vkturnTelemetry.Store(nil)
		vkturnStats.Store(nil)
		vkturnMu.Unlock()
	}()

	go func() {
		time.Sleep(75 * time.Millisecond)
		final := wgturnclient.StatsSnapshot{ActiveConnections: 0, BondFramesDown: 7, RoomDownBytes: make([]int64, 3)}
		final.RoomDownBytes[2] = 707
		storeVKTurnTelemetryIfCurrent(runner, final)
		finishVKTurnRunner(runner, done, nil)
	}()
	started := time.Now()
	StopVKTurnUpstream()
	if elapsed := time.Since(started); elapsed < 60*time.Millisecond {
		t.Fatalf("StopVKTurnUpstream returned before worker drain: %v", elapsed)
	}
	if vkturnGeneration.Load() <= beforeGeneration {
		t.Fatal("StopVKTurnUpstream did not invalidate the runner generation")
	}
	if TURNUpstreamRunning() || VKTurnNetstack() != nil {
		t.Fatal("StopVKTurnUpstream left runtime state active")
	}
	var got struct {
		Running   bool `json:"running"`
		Telemetry struct {
			BondFramesDown int64    `json:"bond_frames_down"`
			RoomDownBytes  [4]int64 `json:"room_down_bytes"`
		} `json:"telemetry"`
	}
	if err := json.Unmarshal([]byte(TURNUpstreamStatsJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Running || got.Telemetry.BondFramesDown != 7 || got.Telemetry.RoomDownBytes[2] != 707 {
		t.Fatalf("final stop telemetry=%+v", got)
	}
}

func TestStopVKTurnUpstreamAsyncReturnsBeforeWorkerDrain(t *testing.T) {
	done := make(chan struct{})
	runner := &wgturnclient.Runner{}
	vkturnMu.Lock()
	vkturnRunner = runner
	vkturnTelemetryOwner = runner
	vkturnCancel = nil
	vkturnRunDone = done
	vkturnDraining = nil
	vkturnAttachStop = nil
	vkturnRunning.Store(true)
	vkturnTelemetry.Store(nil)
	vkturnStats.Store(nil)
	vkturnMu.Unlock()
	defer func() {
		vkturnMu.Lock()
		vkturnRunner = nil
		vkturnTelemetryOwner = nil
		vkturnCancel = nil
		vkturnRunDone = nil
		vkturnDraining = nil
		vkturnRunning.Store(false)
		vkturnTelemetry.Store(nil)
		vkturnStats.Store(nil)
		vkturnMu.Unlock()
	}()

	started := time.Now()
	StopVKTurnUpstreamAsync()
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("StopVKTurnUpstreamAsync blocked stopTunnel for %v", elapsed)
	}
	if !TURNUpstreamDraining() {
		t.Fatal("async stop did not gate replacement start while workers drain")
	}
	final := wgturnclient.StatsSnapshot{BondFramesDown: 9, RoomDownBytes: make([]int64, 2)}
	final.RoomDownBytes[1] = 909
	storeVKTurnTelemetryIfCurrent(runner, final)
	var got struct {
		Running   bool `json:"running"`
		Telemetry struct {
			RoomDownBytes [4]int64 `json:"room_down_bytes"`
		} `json:"telemetry"`
	}
	if err := json.Unmarshal([]byte(TURNUpstreamStatsJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Running || got.Telemetry.RoomDownBytes[1] != 909 {
		t.Fatalf("async final telemetry=%+v", got)
	}
	finishVKTurnRunner(runner, done, nil)
	time.Sleep(100 * time.Millisecond)
	if !TURNUpstreamDraining() {
		t.Fatal("async stop cleared gate before TURN allocation release grace elapsed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for TURNUpstreamDraining() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if TURNUpstreamDraining() {
		t.Fatal("async stop did not clear drain gate after completion")
	}
}

func TestStopVKTurnUpstreamSyncIsSingleflightPerDrain(t *testing.T) {
	done := make(chan struct{})
	runner := &wgturnclient.Runner{}
	vkturnMu.Lock()
	vkturnRunner = runner
	vkturnTelemetryOwner = runner
	vkturnCancel = nil
	vkturnRunDone = done
	vkturnDraining = nil
	vkturnRunning.Store(true)
	vkturnStats.Store(nil)
	vkturnErr.Store(nil)
	vkturnMu.Unlock()
	defer func() {
		vkturnMu.Lock()
		vkturnRunner = nil
		vkturnTelemetryOwner = nil
		vkturnCancel = nil
		vkturnRunDone = nil
		vkturnDraining = nil
		vkturnRunning.Store(false)
		vkturnStats.Store(nil)
		vkturnErr.Store(nil)
		vkturnMu.Unlock()
	}()

	firstDone := make(chan struct{})
	go func() {
		StopVKTurnUpstream()
		close(firstDone)
	}()
	deadline := time.Now().Add(time.Second)
	for !TURNUpstreamDraining() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !TURNUpstreamDraining() {
		t.Fatal("first sync stop did not claim drain")
	}
	started := time.Now()
	StopVKTurnUpstream()
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("second sync stop waited on an already-owned drain: %v", elapsed)
	}
	finishVKTurnRunner(runner, done, nil)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first sync stop did not finish after owner cleanup")
	}
}

func TestFinishVKTurnRunnerPreservesErrorForTimedOutDrain(t *testing.T) {
	done := make(chan struct{})
	runner := &wgturnclient.Runner{}
	vkturnMu.Lock()
	vkturnRunner = runner
	vkturnTelemetryOwner = runner
	vkturnCancel = nil
	vkturnRunDone = done
	vkturnDraining = done // models a sync stop that already timed out
	vkturnRunning.Store(false)
	vkturnStats.Store(nil)
	vkturnErr.Store(nil)
	vkturnMu.Unlock()
	defer func() {
		vkturnMu.Lock()
		vkturnRunner = nil
		vkturnTelemetryOwner = nil
		vkturnCancel = nil
		vkturnRunDone = nil
		vkturnDraining = nil
		vkturnRunning.Store(false)
		vkturnStats.Store(nil)
		vkturnErr.Store(nil)
		vkturnMu.Unlock()
	}()

	finishVKTurnRunner(runner, done, fmt.Errorf("drain failure"))
	select {
	case <-done:
	default:
		t.Fatal("runDone was not closed after owner cleanup completed")
	}
	var got struct {
		Running bool   `json:"running"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal([]byte(TURNUpstreamStatsJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Running || got.Error != "drain failure" {
		t.Fatalf("timed-out drain final state=%+v", got)
	}
	vkturnMu.Lock()
	remaining := vkturnRunner
	vkturnMu.Unlock()
	if remaining != nil {
		t.Fatal("owner cleanup did not clear the finished runner")
	}
}

func TestStartVKTurnUpstreamReturnsAlreadyRunningSentinel(t *testing.T) {
	vkturnMu.Lock()
	vkturnRunning.Store(true)
	vkturnErr.Store(nil)
	vkturnStats.Store(nil)
	vkturnMu.Unlock()

	got := StartVKTurnUpstream(`{"username":"user","password":"pass","turn_servers":["relay.example:3478"],"lifetime_sec":3600}`, "127.0.0.1:443", "password", "device", 9000, 20)
	if got != "already running" {
		t.Fatalf("StartVKTurnUpstream while active = %q, want already running", got)
	}

	vkturnMu.Lock()
	vkturnRunning.Store(false)
	vkturnStats.Store(nil)
	vkturnMu.Unlock()
}

func TestStartVKTurnUpstreamBlocksWhilePreviousRunnerDrains(t *testing.T) {
	draining := make(chan struct{})
	vkturnMu.Lock()
	vkturnRunner = nil
	vkturnRunDone = nil
	vkturnDraining = draining
	vkturnRunning.Store(false)
	vkturnMu.Unlock()

	got := StartVKTurnUpstream(`{"username":"user","password":"pass","turn_servers":["relay.example:3478"],"lifetime_sec":3600}`, "127.0.0.1:443", "password", "device", 9000, 20)
	if got != "previous runner still draining" {
		t.Fatalf("StartVKTurnUpstream during drain = %q, want drain blocker", got)
	}

	close(draining)
	vkturnMu.Lock()
	vkturnDraining = nil
	vkturnMu.Unlock()
}

func TestStartVKTurnUpstreamHonorsAllocationReleaseBarrier(t *testing.T) {
	vkturnMu.Lock()
	vkturnRunner = nil
	vkturnDraining = nil
	vkturnRunning.Store(false)
	vkturnRestartNotBefore.Store(time.Now().Add(75 * time.Millisecond).UnixNano())
	vkturnMu.Unlock()

	started := time.Now()
	got := StartVKTurnUpstream(`{"username":"user","password":"pass","turn_servers":["relay.example:3478"],"lifetime_sec":3600}`, "invalid-peer", "password", "device", 9000, 20)
	if elapsed := time.Since(started); elapsed < 60*time.Millisecond {
		t.Fatalf("StartVKTurnUpstream skipped allocation release barrier: %v", elapsed)
	}
	if got != "" {
		t.Fatalf("expected async runner start after release barrier, got %q", got)
	}
	StopVKTurnUpstream()
	vkturnRestartNotBefore.Store(0)
}

func TestStaleRunnerCannotOverwriteCurrentErrorState(t *testing.T) {
	current := &wgturnclient.Runner{}
	stale := &wgturnclient.Runner{}
	vkturnMu.Lock()
	vkturnRunner = current
	vkturnRunning.Store(true)
	vkturnErr.Store(nil)
	vkturnStats.Store(nil)
	vkturnMu.Unlock()

	if storeVKTurnErrorIfCurrent(stale, "stale timeout") {
		t.Fatal("stale runner unexpectedly stored an error")
	}
	if got := vkturnErr.Load(); got != nil {
		t.Fatalf("stale runner poisoned current error state: %q", *got)
	}
	if !storeVKTurnErrorIfCurrent(current, "current timeout") {
		t.Fatal("current runner failed to store its error")
	}

	vkturnMu.Lock()
	vkturnRunner = nil
	vkturnRunning.Store(false)
	vkturnErr.Store(nil)
	vkturnStats.Store(nil)
	vkturnMu.Unlock()
}

func TestVKTurnStatsJSONExportsCurrentRunnerTelemetry(t *testing.T) {
	current := &wgturnclient.Runner{}
	stale := &wgturnclient.Runner{}
	vkturnMu.Lock()
	vkturnRunner = current
	vkturnTelemetryOwner = current
	vkturnRunning.Store(true)
	vkturnErr.Store(nil)
	vkturnStats.Store(nil)
	vkturnTelemetry.Store(nil)
	vkturnMu.Unlock()
	defer func() {
		vkturnMu.Lock()
		vkturnRunner = nil
		vkturnTelemetryOwner = nil
		vkturnRunning.Store(false)
		vkturnStats.Store(nil)
		vkturnTelemetry.Store(nil)
		vkturnMu.Unlock()
	}()

	vkturnExpectedWorkers.Store(120)
	snapshot := wgturnclient.StatsSnapshot{
		ActiveConnections: 80,
		BondFramesUp:      12,
		BondFramesDown:    13,
		RoomUpBytes:       make([]int64, 6),
		RoomDownBytes:     make([]int64, 6),
	}
	snapshot.RoomUpBytes[3] = 404
	snapshot.RoomDownBytes[3] = 505
	storeVKTurnTelemetryIfCurrent(current, snapshot)
	staleSnapshot := snapshot
	staleSnapshot.RoomDownBytes[3] = 999
	storeVKTurnTelemetryIfCurrent(stale, staleSnapshot)
	storeVKTurnWorkerCountIfCurrent(current, 44)
	storeVKTurnWorkerCountIfCurrent(stale, 99)

	var got struct {
		Active     int   `json:"active"`
		Expected   int64 `json:"expected"`
		Running    bool  `json:"running"`
		QuotaStorm bool  `json:"quota_storm"`
		Telemetry  struct {
			BondFramesUp  int64   `json:"bond_frames_up"`
			RoomUpBytes   []int64 `json:"room_up_bytes"`
			RoomDownBytes []int64 `json:"room_down_bytes"`
		} `json:"telemetry"`
	}
	if err := json.Unmarshal([]byte(TURNUpstreamStatsJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Running || got.Active != 44 || got.Expected != 120 || got.Telemetry.BondFramesUp != 12 || got.Telemetry.RoomUpBytes[3] != 404 || got.Telemetry.RoomDownBytes[3] != 505 {
		t.Fatalf("telemetry JSON=%+v", got)
	}

	stormSnapshot := snapshot
	stormSnapshot.ActiveConnections = 0
	stormSnapshot.QuotaStorm = true
	storeVKTurnTelemetryIfCurrent(current, stormSnapshot)
	if err := json.Unmarshal([]byte(TURNUpstreamStatsJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if !got.QuotaStorm {
		t.Fatalf("quota_storm missing from stats JSON: %+v", got)
	}
	storeVKTurnWorkerCountIfCurrent(current, 1)
	if err := json.Unmarshal([]byte(TURNUpstreamStatsJSON()), &got); err != nil {
		t.Fatal(err)
	}
	if got.QuotaStorm {
		t.Fatalf("quota_storm remained active after worker recovery: %+v", got)
	}
}

func TestVKTurnRequiredFailsClosedWithoutNetstack(t *testing.T) {
	vkturnNet.Store(nil)
	SetVKTurnRequired(true)
	defer SetVKTurnRequired(false)

	if _, err := dialUpstream(context.Background(), "127.0.0.1:9"); !errors.Is(err, errVKTurnRequiredNotReady) {
		t.Fatalf("TCP error=%v, want fail-closed sentinel", err)
	}
	if _, err := dialUpstreamUDP(context.Background(), "127.0.0.1:9"); !errors.Is(err, errVKTurnRequiredNotReady) {
		t.Fatalf("UDP error=%v, want fail-closed sentinel", err)
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
		{13, 13},
		{20, 20},
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
	valid := `{"rooms":[` + room("a", fresh) + `,` + room("b", fresh) + `]}`
	hashes, creds, err := parseVKTurnRoomCredsJSON(valid)
	if err != nil {
		t.Fatalf("valid bundle: %v", err)
	}
	if len(hashes) != 2 || len(creds) != 2 {
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

func TestParseVKTurnRoomCredsJSONEnforcesIOSResourceRoomLimit(t *testing.T) {
	fresh := time.Now().Unix()
	room := func(index int) string {
		return fmt.Sprintf(`{"hash":"room-%d","credentials":{"username":"user","password":"pass","turn_servers":["relay.example:3478"],"lifetime_sec":3600,"acquired_at_unix":%d}}`, index, fresh)
	}
	bundle := func(count int) string {
		rooms := make([]string, count)
		for i := range rooms {
			rooms[i] = room(i)
		}
		return `{"rooms":[` + strings.Join(rooms, ",") + `]}`
	}

	if VKTurnMaxRooms() != 3 {
		t.Fatalf("VKTurnMaxRooms()=%d, want 3", VKTurnMaxRooms())
	}
	if hashes, _, err := parseVKTurnRoomCredsJSON(bundle(VKTurnMaxRooms())); err != nil || len(hashes) != VKTurnMaxRooms() {
		t.Fatalf("max-room bundle rejected: hashes=%d err=%v", len(hashes), err)
	}
	if _, _, err := parseVKTurnRoomCredsJSON(bundle(VKTurnMaxRooms() + 1)); err == nil || !strings.Contains(err.Error(), "memory-safe maximum 3") {
		t.Fatalf("max+1 bundle error = %v, want iOS room-limit rejection", err)
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

func TestWaitForVKTurnConfigContinuesAfterDiagnosticTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	configCh := make(chan string, 1)
	runDone := make(chan struct{})
	timeoutSeen := make(chan struct{}, 1)

	type waitResult struct {
		conf   string
		result vkturnAttachWaitResult
	}
	resultCh := make(chan waitResult, 1)
	go func() {
		conf, result := waitForVKTurnConfig(ctx, runDone, configCh, 10*time.Millisecond, func() {
			select {
			case timeoutSeen <- struct{}{}:
			default:
			}
		})
		resultCh <- waitResult{conf: conf, result: result}
	}()

	select {
	case <-timeoutSeen:
	case <-time.After(time.Second):
		t.Fatal("diagnostic timeout did not fire")
	}
	select {
	case result := <-resultCh:
		t.Fatalf("wait ended at diagnostic timeout: %+v", result)
	default:
	}

	configCh <- "config-ready"
	select {
	case result := <-resultCh:
		if result.result != vkturnAttachConfigReady || result.conf == "" {
			t.Fatalf("result=%+v, want later config delivery", result)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not accept config after timeout")
	}
}
