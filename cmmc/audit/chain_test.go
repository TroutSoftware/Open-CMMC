package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

var chainKey = []byte("0123456789abcdef0123456789abcdef")

// sinkCopy collects Emit'd events and returns copies. Used to inspect
// the MAC fields stamped by HMACChainEmitter.
type sinkCopy struct{ got []Event }

func (s *sinkCopy) Emit(_ context.Context, e *Event) { s.got = append(s.got, *e) }

func emitSeries(t *testing.T, n int) ([]Event, *HMACChainEmitter) {
	t.Helper()
	sink := &sinkCopy{}
	chain := NewHMACChainEmitter(sink, chainKey)
	for i := 0; i < n; i++ {
		ev := New("user.create", OutcomeSuccess)
		ev.Ts = time.Unix(int64(1700000000+i), 0).UTC()
		ev.UserID = "alice"
		ev.Resource = "/api/users"
		ev.Status = 201
		chain.Emit(context.Background(), ev)
	}
	return sink.got, chain
}

func TestHMACChain_FirstEventHasEmptyPrev(t *testing.T) {
	got, _ := emitSeries(t, 1)
	if got[0].PrevMAC != "" {
		t.Errorf("genesis PrevMAC should be empty; got %q", got[0].PrevMAC)
	}
	if got[0].MAC == "" {
		t.Error("MAC must be populated")
	}
}

func TestHMACChain_EachPrevEqualsPriorMAC(t *testing.T) {
	got, _ := emitSeries(t, 5)
	for i := 1; i < len(got); i++ {
		if got[i].PrevMAC != got[i-1].MAC {
			t.Errorf("event %d prev_mac=%q != prior mac=%q", i, got[i].PrevMAC, got[i-1].MAC)
		}
	}
}

func TestHMACChain_Tip(t *testing.T) {
	got, chain := emitSeries(t, 3)
	if chain.Tip() != got[len(got)-1].MAC {
		t.Errorf("Tip()=%q, want last MAC %q", chain.Tip(), got[len(got)-1].MAC)
	}
}

func TestVerifyChain_IntactSequenceReturnsMinusOne(t *testing.T) {
	got, _ := emitSeries(t, 5)
	if idx := VerifyChain(got, chainKey, ""); idx != -1 {
		t.Errorf("intact chain reported break at %d", idx)
	}
}

func TestVerifyChain_DetectsFieldMutation(t *testing.T) {
	got, _ := emitSeries(t, 5)
	got[2].Resource = "/api/evil"
	idx := VerifyChain(got, chainKey, "")
	if idx != 2 {
		t.Errorf("expected break at 2, got %d", idx)
	}
}

func TestVerifyChain_DetectsInsertion(t *testing.T) {
	got, _ := emitSeries(t, 4)
	fake := New("user.delete", OutcomeSuccess)
	fake.PrevMAC = got[1].MAC
	fake.MAC = "fake-fake-fake-fake"
	spliced := append([]Event{}, got[:2]...)
	spliced = append(spliced, *fake)
	spliced = append(spliced, got[2:]...)
	idx := VerifyChain(spliced, chainKey, "")
	// First break should be at the fake event (index 2) — its MAC is
	// wrong for its claimed prev.
	if idx != 2 {
		t.Errorf("expected break at inserted index 2, got %d", idx)
	}
}

func TestVerifyChain_DetectsDeletion(t *testing.T) {
	got, _ := emitSeries(t, 5)
	// Drop the middle event. Event 2's prev_mac now references the
	// MAC of a now-absent predecessor — first break at index 2.
	shrunk := append([]Event{}, got[:2]...)
	shrunk = append(shrunk, got[3:]...)
	idx := VerifyChain(shrunk, chainKey, "")
	if idx != 2 {
		t.Errorf("expected break at 2 after deletion, got %d", idx)
	}
}

func TestVerifyChain_DetectsReorder(t *testing.T) {
	got, _ := emitSeries(t, 5)
	got[1], got[2] = got[2], got[1]
	idx := VerifyChain(got, chainKey, "")
	if idx == -1 {
		t.Error("reorder should have been detected")
	}
}

func TestVerifyChain_WrongKeyDetectsAllBreaks(t *testing.T) {
	got, _ := emitSeries(t, 3)
	wrongKey := []byte("wrongwrongwrongwrongwrongwrongwr")
	if idx := VerifyChain(got, wrongKey, ""); idx != 0 {
		t.Errorf("wrong key should break at 0; got %d", idx)
	}
}

func TestHMACChain_JSONRoundTrip(t *testing.T) {
	// End-to-end: emit, re-parse from JSON, verify chain intact.
	buf := &bytes.Buffer{}
	json := NewJSONEmitter(buf)
	chain := NewHMACChainEmitter(json, chainKey)
	for i := 0; i < 3; i++ {
		ev := New("x", OutcomeSuccess)
		ev.Ts = time.Unix(int64(1700000000+i), 0).UTC()
		chain.Emit(context.Background(), ev)
	}
	// Parse lines back.
	var events []Event
	dec := decodeLines(t, buf)
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("decode: %v", err)
		}
		events = append(events, ev)
	}
	if idx := VerifyChain(events, chainKey, ""); idx != -1 {
		t.Errorf("JSON round-trip broke chain at %d", idx)
	}
}

// decodeLines adapts the newline-delimited JSON stream to a json.Decoder
// that only returns single objects.
type lineDecoder struct{ d *json.Decoder }

func (l *lineDecoder) More() bool                   { return l.d.More() }
func (l *lineDecoder) Decode(v interface{}) error   { return l.d.Decode(v) }
func decodeLines(_ *testing.T, r *bytes.Buffer) *lineDecoder {
	return &lineDecoder{d: json.NewDecoder(r)}
}
