package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
)

// Emitter is the audit-event sink. Implementations MUST be safe for
// concurrent Emit calls from request-handler goroutines.
type Emitter interface {
	Emit(ctx context.Context, e *Event)
}

// JSONEmitter writes one JSON-encoded Event per line to an io.Writer.
// The default production target is os.Stdout — filebrowser's stdout
// is expected to be captured by journald, which in turn feeds the
// rsyslog-ossl forwarder that ships to the customer SIEM.
type JSONEmitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewJSONEmitter wraps an io.Writer. The writer must be safe for
// concurrent use if callers emit from multiple goroutines — the
// emitter's own mutex serializes encoder access but cannot serialize
// underlying writes across separate emitters sharing a writer.
func NewJSONEmitter(w io.Writer) *JSONEmitter {
	return &JSONEmitter{enc: json.NewEncoder(w)}
}

// Emit marshals the event as JSON-per-line. ctx is accepted for
// interface compatibility with future context-aware emitters (e.g.,
// a future rsyslog-direct or SIEM-HTTP emitter that needs cancellation);
// the JSONEmitter ignores it today.
func (e *JSONEmitter) Emit(_ context.Context, ev *Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// We deliberately drop encoder errors. An audit stream that
	// fails to write is a tamper-detection event for the SIEM, but
	// this thread cannot reasonably recover — the caller is in the
	// middle of a user request. The rsyslog watchdog (architecture.md
	// §7) detects gaps out-of-band.
	_ = e.enc.Encode(ev)
}

// defaultEmitter is the package-wide sink. Unless overridden via
// SetDefault, events go to stdout.
var (
	defaultMu      sync.RWMutex
	defaultEmitter Emitter = NewJSONEmitter(os.Stdout)
)

// SetDefault replaces the package default. Tests call this with an in-
// memory emitter; cmd/root.go may call this at boot to wire stdout to
// a separate file descriptor (e.g., /var/log/cmmc-filebrowser/audit).
func SetDefault(e Emitter) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultEmitter = e
}

// Default returns the current package emitter.
func Default() Emitter {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultEmitter
}

// Emit is the package-level convenience — callers typically use
// audit.Emit(ctx, event) instead of plumbing Emitter through config.
func Emit(ctx context.Context, ev *Event) {
	Default().Emit(ctx, ev)
}

// MemoryEmitter collects events in memory for testing. Not safe
// for production — unbounded memory growth.
type MemoryEmitter struct {
	mu     sync.Mutex
	events []Event
}

// NewMemoryEmitter returns an in-memory Emitter with a pre-allocated
// slice. Intended for tests only.
func NewMemoryEmitter() *MemoryEmitter {
	return &MemoryEmitter{events: make([]Event, 0, 8)}
}

// Emit stores the event. Makes a copy so later mutations by callers do
// not affect the stored record.
func (m *MemoryEmitter) Emit(_ context.Context, ev *Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, *ev)
}

// Events returns a snapshot copy of the collected events.
func (m *MemoryEmitter) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out
}

// Reset clears the collected events.
func (m *MemoryEmitter) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = m.events[:0]
}
