package wgturnclient

import "testing"

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

func TestSessionMemoryProfilePreservesSingleRoomAndBoundsMultiRoom(t *testing.T) {
	single := memoryProfileForWorkers(20)
	if single.socketBufferSize != 625*1024 || single.workerSendBuffer != 128 {
		t.Fatalf("single-room profile=%+v, want legacy 625KiB/128", single)
	}

	multi := memoryProfileForWorkers(80)
	if multi.socketBufferSize != 128*1024 || multi.workerSendBuffer != 32 {
		t.Fatalf("multi-room profile=%+v, want 128KiB/32", multi)
	}
	if got := 80 * multi.socketBufferSize * 2; got > 20*1024*1024 {
		t.Fatalf("multi-room requested socket memory=%d, want <=20MiB", got)
	}
}

func TestMultiRoomPlannerFourByTwenty(t *testing.T) {
	plans := buildWorkerGroupPlans(80, 4, 20)
	if len(plans) != 8 {
		t.Fatalf("plans=%d, want 8", len(plans))
	}
	for room := 0; room < 4; room++ {
		first, second := plans[room*2], plans[room*2+1]
		if first.hashIndex != room || first.workerCount != 12 || second.hashIndex != room || second.workerCount != 8 {
			t.Fatalf("room %d plans=%+v %+v, want 12+8", room, first, second)
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
