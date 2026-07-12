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
