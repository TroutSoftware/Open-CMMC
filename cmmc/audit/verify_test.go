package audit

import (
	"context"
	"testing"
	"time"
)

// emitN sends N distinct events through the chain → ring pipeline
// so tests operate on realistic state. Returns the chain tip after
// emission (== events[N-1].MAC).
func emitN(t *testing.T, ring *RingBufferEmitter, chain *HMACChainEmitter, n int) string {
	t.Helper()
	for i := 0; i < n; i++ {
		ev := &Event{
			Ts:      time.Now().UTC().Add(time.Duration(i) * time.Millisecond),
			EventID: "ev-" + string(rune('a'+i)),
			Action:  "file.upload",
			Outcome: "success",
		}
		chain.Emit(context.Background(), ev)
		ring.Emit(context.Background(), ev)
	}
	return chain.Tip()
}

func TestVerifyRingBuffer_Empty(t *testing.T) {
	ring := NewRingBufferEmitter(10)
	r := VerifyRingBuffer(ring, "", []byte("k"))
	if !r.Intact || r.FirstBreakIndex != -1 || r.Length != 0 {
		t.Errorf("empty ring not reported intact: %+v", r)
	}
}

func TestVerifyRingBuffer_IntactChain_NoGenesis(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	tip := emitN(t, ring, chain, 5)

	r := VerifyRingBuffer(ring, "", key)
	if !r.Intact {
		t.Errorf("intact chain reported as broken at %d", r.FirstBreakIndex)
	}
	if r.Length != 5 {
		t.Errorf("Length = %d, want 5", r.Length)
	}
	if r.ChainTip != tip {
		t.Errorf("ChainTip = %q, want %q", r.ChainTip, tip)
	}
	if r.Wrapped {
		t.Error("5 events in cap-10 ring should not report wrapped")
	}
}

func TestVerifyRingBuffer_WrappedRing_ReportsWrapped(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(3)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	emitN(t, ring, chain, 10) // evicts 7

	r := VerifyRingBuffer(ring, "", key)
	if !r.Wrapped {
		t.Error("wrapped ring not reported wrapped")
	}
	if r.Length != 3 {
		t.Errorf("Length = %d, want 3", r.Length)
	}
	// With no expectedGenesis, verifier trusts events[0].PrevMAC
	// and confirms internal consistency.
	if !r.Intact {
		t.Errorf("wrapped but internally-consistent chain reported broken at %d", r.FirstBreakIndex)
	}
}

func TestVerifyRingBuffer_TamperedMAC_DetectedAtIndex(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	emitN(t, ring, chain, 5)

	// Mutate the MAC of event[2] directly in the ring's backing
	// array (simulates a bolt-level tamper). The ring doesn't
	// expose its buffer so use Snapshot + reflect-style access via
	// Emit(replacement) is not possible — instead, replicate the
	// tamper by re-emitting a tampered event to a fresh ring.
	// Simpler: copy the Snapshot and mutate it, then verify.
	events := ring.Snapshot()
	events[2].MAC = "tampered===="
	breakIdx := VerifyChain(events, key, "")
	if breakIdx != 2 {
		t.Errorf("tamper at index 2 reported at %d", breakIdx)
	}
}

func TestVerifyRingBuffer_ExpectedGenesisMismatch_BreaksAtZero(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	emitN(t, ring, chain, 3)

	r := VerifyRingBuffer(ring, "bogus-genesis", key)
	if r.FirstBreakIndex != 0 {
		t.Errorf("genesis mismatch should break at index 0, got %d", r.FirstBreakIndex)
	}
	if r.Intact {
		t.Error("intact reported true despite genesis mismatch")
	}
}

func TestVerifyRingBuffer_NilRing_Graceful(t *testing.T) {
	r := VerifyRingBuffer(nil, "", []byte("k"))
	if !r.Intact || r.FirstBreakIndex != -1 {
		t.Errorf("nil ring not handled: %+v", r)
	}
}

// NopEmitter swallows events — used as the inner sink when we only
// care about the chain emitter's stamping side effect.
type NopEmitter struct{}

func (NopEmitter) Emit(_ context.Context, _ *Event) {}

// TestVerifyRingBuffer_WrongKey_BreaksAtZero — operator configured
// the wrong key at verify time. Every MAC comparison fails, so
// FirstBreakIndex == 0.
func TestVerifyRingBuffer_WrongKey_BreaksAtZero(t *testing.T) {
	sealKey := []byte("0123456789abcdef0123456789abcdef")
	wrongKey := []byte("ffffffffffffffffffffffffffffffff")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, sealKey)
	emitN(t, ring, chain, 3)

	r := VerifyRingBuffer(ring, "", wrongKey)
	if r.Intact {
		t.Error("wrong key should not verify as intact")
	}
	if r.FirstBreakIndex != 0 {
		t.Errorf("wrong key should break at 0, got %d", r.FirstBreakIndex)
	}
}

// TestVerifyRingBuffer_GenesisSupplied_TamperedIndex0_Detected —
// the whole point of accepting expected_genesis. With a correct
// SIEM-saved tip, a tamper at events[0] is caught.
func TestVerifyRingBuffer_GenesisSupplied_TamperedIndex0_Detected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	emitN(t, ring, chain, 5)

	// Tamper events[0].PrevMAC directly (Snapshot returns a copy,
	// so exercise the verification function on the copy that would
	// come out of a live Snapshot — genesis must be the correct one
	// for the sealed event).
	events := ring.Snapshot()
	expectedGenesis := events[0].PrevMAC // what SIEM saved
	events[0].PrevMAC = "attacker-rewrite"
	events[0].MAC = "attacker-resign"
	breakIdx := VerifyChain(events, key, expectedGenesis)
	if breakIdx != 0 {
		t.Errorf("tamper at events[0] with supplied genesis should break at 0, got %d", breakIdx)
	}
}

// TestVerifyRingBuffer_NilRing_Shape — pins the nil-ring response
// shape (zero length, empty tip, intact, no genesis).
func TestVerifyRingBuffer_NilRing_Shape(t *testing.T) {
	r := VerifyRingBuffer(nil, "", nil)
	if r.Length != 0 || r.Capacity != 0 || r.ChainTip != "" {
		t.Errorf("nil-ring fields not zeroed: %+v", r)
	}
	if !r.Intact || r.FirstBreakIndex != -1 {
		t.Error("nil ring must report intact")
	}
}

// TestVerifyRingBuffer_KeyMissing_Signal — when the verifier key
// is nil/short, KeyMissing must be true so operators don't misread
// the resulting FirstBreakIndex=0 as actual tampering.
func TestVerifyRingBuffer_KeyMissing_Signal(t *testing.T) {
	sealKey := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, sealKey)
	emitN(t, ring, chain, 3)

	r := VerifyRingBuffer(ring, "", nil)
	if !r.KeyMissing {
		t.Error("KeyMissing should be true for nil verify key")
	}
	r = VerifyRingBuffer(ring, "", []byte("too-short"))
	if !r.KeyMissing {
		t.Error("KeyMissing should be true for <32-byte key")
	}
}

// TestVerifyRingBuffer_GenesisProvided_Flag — pins the
// reviewer-flagged signal that tells callers whether they got the
// strong (genesis-anchored) or weak (internal-only) check.
func TestVerifyRingBuffer_GenesisProvided_Flag(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(10)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	emitN(t, ring, chain, 2)

	r := VerifyRingBuffer(ring, "", key)
	if r.GenesisProvided {
		t.Error("empty genesis should set GenesisProvided=false")
	}
	r = VerifyRingBuffer(ring, "some-tip", key)
	if !r.GenesisProvided {
		t.Error("supplied genesis should set GenesisProvided=true")
	}
}

// TestVerifyRingBuffer_ConcurrentEmit — the docstring promises
// Snapshot/VerifyRingBuffer is safe to call concurrently with Emit.
// Run with -race.
func TestVerifyRingBuffer_ConcurrentEmit(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ring := NewRingBufferEmitter(100)
	chain := NewHMACChainEmitter(NopEmitter{}, key)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 500; i++ {
			_ = VerifyRingBuffer(ring, "", key)
		}
	}()
	for i := 0; i < 500; i++ {
		ev := &Event{Action: "file.upload", Outcome: "success"}
		chain.Emit(context.Background(), ev)
		ring.Emit(context.Background(), ev)
	}
	<-done
}

// TestDeriveChainKey_Threshold — the ≥32 byte gate.
func TestDeriveChainKey_Threshold(t *testing.T) {
	if DeriveChainKey(nil) != nil {
		t.Error("nil key must return nil")
	}
	if DeriveChainKey([]byte("short")) != nil {
		t.Error("<32 byte key must return nil")
	}
	good := []byte("0123456789abcdef0123456789abcdef")
	out := DeriveChainKey(good)
	if len(out) != 32 {
		t.Errorf("good key round-trip len=%d", len(out))
	}
}
