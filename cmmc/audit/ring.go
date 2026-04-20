package audit

import (
	"context"
	"sync"
)

// RingBufferEmitter keeps the most-recent N events in memory so an
// admin UI / API can surface them without hitting the SIEM. Bounded
// by design — when full, newest event evicts the oldest.
//
// NOT a replacement for the durable SIEM pipeline. The ring buffer is
// a local convenience for operators debugging the deployment. The
// canonical audit record still flows via JSONEmitter → journald →
// rsyslog-ossl → customer SIEM.
type RingBufferEmitter struct {
	mu     sync.Mutex
	buf    []Event
	head   int // next write index
	length int // number of valid entries (≤ cap(buf))
}

// NewRingBufferEmitter returns a ring buffer of fixed capacity.
// A capacity ≤ 0 is coerced to 1 so the emitter is always usable.
func NewRingBufferEmitter(capacity int) *RingBufferEmitter {
	if capacity <= 0 {
		capacity = 1
	}
	return &RingBufferEmitter{buf: make([]Event, capacity)}
}

// Emit records the event, evicting the oldest when the buffer is full.
func (r *RingBufferEmitter) Emit(_ context.Context, e *Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head] = *e
	r.head = (r.head + 1) % len(r.buf)
	if r.length < len(r.buf) {
		r.length++
	}
}

// Snapshot returns the events in chronological order (oldest first).
// Safe to call concurrently with Emit — returns a copy.
func (r *RingBufferEmitter) Snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, r.length)
	if r.length < len(r.buf) {
		// Not wrapped yet — events are at indices [0, length).
		copy(out, r.buf[:r.length])
		return out
	}
	// Wrapped. Oldest is at head; newest is at head-1 (mod cap).
	n := copy(out, r.buf[r.head:])
	copy(out[n:], r.buf[:r.head])
	return out
}

// Len returns the number of events currently held.
func (r *RingBufferEmitter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.length
}

// Capacity returns the fixed buffer size.
func (r *RingBufferEmitter) Capacity() int { return len(r.buf) }
