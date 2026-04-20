package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var _ = time.Second // keep import stable across edits

// --- Event schema --------------------------------------------------------

func TestNew_SetsTimestampIDAndActionOutcome(t *testing.T) {
	before := time.Now().UTC()
	ev := New(ActionAuthLoginOK, OutcomeSuccess)
	after := time.Now().UTC()

	if ev.Ts.Before(before) || ev.Ts.After(after) {
		t.Errorf("timestamp %v outside [%v, %v]", ev.Ts, before, after)
	}
	if ev.EventID == "" {
		t.Error("EventID empty")
	}
	if ev.Action != ActionAuthLoginOK {
		t.Errorf("action=%q", ev.Action)
	}
	if ev.Outcome != OutcomeSuccess {
		t.Errorf("outcome=%q", ev.Outcome)
	}
}

// RFC3339Nano and base64url(16 bytes) regex — if the shape drifts the
// SIEM side breaks silently, so pin it here.
var base64URLID = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

func TestNew_EventIDShape(t *testing.T) {
	ev := New("x", "y")
	if !base64URLID.MatchString(ev.EventID) {
		t.Errorf("EventID %q does not match base64url(16 bytes)", ev.EventID)
	}
}

func TestNew_EventIDs_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		ev := New("x", "y")
		if _, dup := seen[ev.EventID]; dup {
			t.Fatalf("collision iter %d", i)
		}
		seen[ev.EventID] = struct{}{}
	}
}

func TestEvent_JSONMarshal_OmitsEmpty(t *testing.T) {
	ev := New(ActionAuthLoginOK, OutcomeSuccess)
	ev.UserID = "alice"
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	// Required fields present
	for _, key := range []string{`"ts":`, `"event_id":`, `"action":`, `"outcome":`, `"user_id":"alice"`} {
		if !strings.Contains(s, key) {
			t.Errorf("missing %q in %s", key, s)
		}
	}
	// Optional fields empty → omitted
	for _, key := range []string{`"username":`, `"client_ip":`, `"latency_ms":`, `"extra":`} {
		if strings.Contains(s, key) {
			t.Errorf("unexpected %q in %s", key, s)
		}
	}
}

// --- JSONEmitter ---------------------------------------------------------

func TestJSONEmitter_OneLinePerEvent(t *testing.T) {
	buf := &bytes.Buffer{}
	em := NewJSONEmitter(buf)
	em.Emit(context.Background(), New("a", OutcomeSuccess))
	em.Emit(context.Background(), New("b", OutcomeFailure))
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), buf.String())
	}
	for i, line := range lines {
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestJSONEmitter_ConcurrentEmit(t *testing.T) {
	buf := &bytes.Buffer{}
	em := NewJSONEmitter(buf)
	var wg sync.WaitGroup
	const N = 100
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			em.Emit(context.Background(), New("concurrent", OutcomeSuccess))
		}()
	}
	wg.Wait()
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte{'\n'})
	if len(lines) != N {
		t.Errorf("got %d lines, want %d (race may have corrupted output)", len(lines), N)
	}
}

// --- MemoryEmitter -------------------------------------------------------

func TestMemoryEmitter_CapturesAndCopies(t *testing.T) {
	em := NewMemoryEmitter()
	ev := New("a", OutcomeSuccess)
	em.Emit(context.Background(), ev)
	// Mutate the original after emission — the stored copy must not change.
	ev.Action = "mutated"
	got := em.Events()
	if len(got) != 1 {
		t.Fatalf("got %d events", len(got))
	}
	if got[0].Action != "a" {
		t.Errorf("Emit should copy; got %q", got[0].Action)
	}
}

func TestMemoryEmitter_Reset(t *testing.T) {
	em := NewMemoryEmitter()
	em.Emit(context.Background(), New("a", "b"))
	em.Reset()
	if len(em.Events()) != 0 {
		t.Fatal("Reset did not clear")
	}
}

// --- Package default ----------------------------------------------------

func TestDefault_SwapAndEmit(t *testing.T) {
	orig := Default()
	defer SetDefault(orig)

	mem := NewMemoryEmitter()
	SetDefault(mem)
	Emit(context.Background(), New(ActionAuthLoginOK, OutcomeSuccess))
	got := mem.Events()
	if len(got) != 1 || got[0].Action != ActionAuthLoginOK {
		t.Errorf("default emit did not route to the swapped emitter: %v", got)
	}
}

// --- Correlation middleware ---------------------------------------------

func TestCorrelationMiddleware_GeneratesID(t *testing.T) {
	var capturedID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedID = CorrelationIDFromContext(r.Context())
	})
	mw := CorrelationMiddleware(next)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	mw.ServeHTTP(w, r)
	if capturedID == "" {
		t.Fatal("no correlation id on context")
	}
	if got := w.Header().Get(HeaderCorrelationID); got != capturedID {
		t.Errorf("response header %q != ctx id %q", got, capturedID)
	}
	if !base64URLID.MatchString(capturedID) {
		t.Errorf("generated id shape wrong: %q", capturedID)
	}
}

func TestCorrelationMiddleware_PropagatesInboundID(t *testing.T) {
	const inbound = "inbound-correlation-value-1234"
	var capturedID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedID = CorrelationIDFromContext(r.Context())
	})
	mw := CorrelationMiddleware(next)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(HeaderCorrelationID, inbound)
	mw.ServeHTTP(w, r)
	if capturedID != inbound {
		t.Errorf("inbound id not propagated: got %q want %q", capturedID, inbound)
	}
	if got := w.Header().Get(HeaderCorrelationID); got != inbound {
		t.Errorf("response header %q != inbound %q", got, inbound)
	}
}

// --- RingBufferEmitter ---------------------------------------------------

func TestRingBuffer_StoresUnderCapacity(t *testing.T) {
	r := NewRingBufferEmitter(5)
	for i := 0; i < 3; i++ {
		r.Emit(context.Background(), New("a", OutcomeSuccess))
	}
	if got := r.Len(); got != 3 {
		t.Errorf("Len=%d, want 3", got)
	}
	if got := len(r.Snapshot()); got != 3 {
		t.Errorf("Snapshot len=%d, want 3", got)
	}
}

func TestRingBuffer_EvictsOldestWhenFull(t *testing.T) {
	r := NewRingBufferEmitter(3)
	// Emit 5 events; only the last 3 survive in chronological order.
	for i := 0; i < 5; i++ {
		ev := New("a", OutcomeSuccess)
		ev.Reason = string(rune('A' + i)) // A, B, C, D, E
		r.Emit(context.Background(), ev)
	}
	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("Snapshot len=%d, want 3", len(snap))
	}
	want := []string{"C", "D", "E"}
	for i, ev := range snap {
		if ev.Reason != want[i] {
			t.Errorf("snap[%d].Reason=%q, want %q", i, ev.Reason, want[i])
		}
	}
}

func TestRingBuffer_CapacityZero_CoercedToOne(t *testing.T) {
	r := NewRingBufferEmitter(0)
	if r.Capacity() != 1 {
		t.Errorf("cap=%d, want 1", r.Capacity())
	}
	r.Emit(context.Background(), New("a", OutcomeSuccess))
	if r.Len() != 1 {
		t.Errorf("len=%d, want 1", r.Len())
	}
}

func TestRingBuffer_ConcurrentEmitAndSnapshot(t *testing.T) {
	r := NewRingBufferEmitter(32)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					r.Emit(context.Background(), New("c", OutcomeSuccess))
				}
			}
		}()
	}
	// Read snapshots from another goroutine while writes race.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = r.Snapshot()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	// Length must be at most capacity.
	if r.Len() > r.Capacity() {
		t.Errorf("len=%d > capacity=%d", r.Len(), r.Capacity())
	}
}

// --- MultiEmitter --------------------------------------------------------

func TestMulti_FansToAll(t *testing.T) {
	a := NewMemoryEmitter()
	b := NewMemoryEmitter()
	m := Multi(a, b)
	m.Emit(context.Background(), New("x", OutcomeSuccess))
	if len(a.Events()) != 1 || len(b.Events()) != 1 {
		t.Errorf("fan-out broken: a=%d b=%d", len(a.Events()), len(b.Events()))
	}
}

func TestMulti_NilSinksSkipped(t *testing.T) {
	a := NewMemoryEmitter()
	m := Multi(nil, a, nil)
	m.Emit(context.Background(), New("x", OutcomeSuccess))
	if len(a.Events()) != 1 {
		t.Fatalf("non-nil sink should still receive; got %d", len(a.Events()))
	}
}

// TestActionConstants_CoverAllExpectedEvents pins the set of action
// constants so a future refactor cannot silently drop one (SIEM
// dashboards often pivot on exact action names; a rename there would
// break downstream filters without this test tripping).
func TestActionConstants_CoverAllExpectedEvents(t *testing.T) {
	want := []string{
		// auth
		ActionAuthLoginOK, ActionAuthLoginFail, ActionAuthLogout, ActionAuthzPrivReject,
		// user
		ActionUserCreate, ActionUserUpdate, ActionUserDelete, ActionUserList, ActionUserRead,
		// share
		ActionShareCreate, ActionShareDelete, ActionShareList, ActionShareRead,
		// settings
		ActionSettingsUpdate, ActionSettingsRead,
		// file
		ActionFileUpload, ActionFileDownload, ActionFileDelete,
		ActionFileRead, ActionFileRename, ActionFileModify,
		ActionFilePreview, ActionFileSubtitle, ActionFileSearch,
		ActionFilePublicDL, ActionFilePublicRead,
		// admin reads
		ActionAdminUsageRead, ActionAdminCommandsRead,
	}
	seen := map[string]struct{}{}
	for _, a := range want {
		if a == "" {
			t.Error("action constant is empty string")
		}
		if _, dup := seen[a]; dup {
			t.Errorf("duplicate action constant %q", a)
		}
		seen[a] = struct{}{}
	}
}

func TestCorrelationIDFromContext_EmptyWhenAbsent(t *testing.T) {
	if got := CorrelationIDFromContext(context.Background()); got != "" {
		t.Errorf("empty context should return \"\"; got %q", got)
	}
}
