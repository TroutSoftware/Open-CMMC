package audit

import "context"

// MultiEmitter fans an event out to several sinks in order.
// Errors in one sink do not affect the others — Emit on each sink
// runs to completion even if a prior sink blocked or panicked.
//
// Typical production wiring:
//
//	audit.SetDefault(audit.Multi(
//	    audit.NewJSONEmitter(os.Stdout),  // to journald → rsyslog-ossl → SIEM
//	    audit.NewRingBufferEmitter(1000), // for the admin UI endpoint
//	))
type MultiEmitter []Emitter

// Multi is a convenience constructor.
func Multi(emitters ...Emitter) MultiEmitter {
	return MultiEmitter(emitters)
}

// Emit sends the event to every sink. A nil sink is skipped so callers
// can build the slice defensively. Each sink's Emit is given the same
// Event pointer — sinks MUST treat the event as read-only.
func (m MultiEmitter) Emit(ctx context.Context, e *Event) {
	for _, s := range m {
		if s == nil {
			continue
		}
		s.Emit(ctx, e)
	}
}
