package daemon

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func mkKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestAuditLog_AppendAndVerify(t *testing.T) {
	key := mkKey(t)
	log, err := NewAuditLog(key, 32)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := log.Append(Event{Action: ActionLandingView, ShareID: "abc", RemoteIP: "10.0.0.1", Outcome: "success"}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	events := log.Drain(0)
	if len(events) != 5 {
		t.Fatalf("expected 5, got %d", len(events))
	}

	// Chain verifies from the genesis seed.
	ok, bad := Verify(key, events, Seed(key))
	if !ok {
		t.Fatalf("chain broken at event %d", bad)
	}
	// Sequence numbers are monotonic.
	for i, e := range events {
		if e.Seq != uint64(i) {
			t.Errorf("event %d has Seq=%d, want %d", i, e.Seq, i)
		}
	}
}

func TestAuditLog_TamperDetected(t *testing.T) {
	key := mkKey(t)
	log, _ := NewAuditLog(key, 16)
	_, _ = log.Append(Event{Action: ActionDownloadOK, ShareID: "x"})
	_, _ = log.Append(Event{Action: ActionDownloadOK, ShareID: "y"})

	ev := log.Drain(0)
	ev[0].ShareID = "tampered" // attacker rewrites the first event
	ok, bad := Verify(key, ev, Seed(key))
	if ok || bad != 0 {
		t.Fatalf("expected break at event 0, got ok=%v bad=%d", ok, bad)
	}
}

func TestAuditLog_WrongKeyFailsVerify(t *testing.T) {
	key := mkKey(t)
	log, _ := NewAuditLog(key, 16)
	_, _ = log.Append(Event{Action: ActionLandingView})

	ev := log.Drain(0)
	other := mkKey(t)
	if ok, _ := Verify(other, ev, Seed(other)); ok {
		t.Fatalf("verify with wrong key should fail")
	}
}

func TestAuditLog_AckThroughDrops(t *testing.T) {
	log, _ := NewAuditLog(mkKey(t), 16)
	for i := 0; i < 4; i++ {
		_, _ = log.Append(Event{Action: ActionLandingView})
	}
	log.AckThrough(1) // drop seq 0 and 1
	ev := log.Drain(0)
	if len(ev) != 2 {
		t.Fatalf("expected 2 after ack, got %d", len(ev))
	}
	if ev[0].Seq != 2 || ev[1].Seq != 3 {
		t.Fatalf("post-ack seqs wrong: %d %d", ev[0].Seq, ev[1].Seq)
	}
}

func TestAuditLog_CapOverflowDropsOldest(t *testing.T) {
	log, _ := NewAuditLog(mkKey(t), 3)
	for i := 0; i < 5; i++ {
		_, _ = log.Append(Event{Action: ActionDownloadOK})
	}
	ev := log.Drain(0)
	if len(ev) != 3 {
		t.Fatalf("expected cap=3 retained, got %d", len(ev))
	}
	// Oldest retained event should be seq 2 (0 and 1 dropped).
	if ev[0].Seq != 2 {
		t.Fatalf("expected oldest seq=2, got %d", ev[0].Seq)
	}
}

func TestNewAuditLog_RejectsShortKey(t *testing.T) {
	_, err := NewAuditLog(bytes.Repeat([]byte{1}, 16), 10)
	if err == nil {
		t.Fatalf("expected short-key rejection")
	}
}
