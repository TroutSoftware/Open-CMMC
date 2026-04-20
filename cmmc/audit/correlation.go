package audit

import (
	"context"
	"net/http"
)

// HeaderCorrelationID is the HTTP header used to carry correlation IDs
// across service boundaries. Matches the convention used by most
// cloud observability stacks; customers already running tracing can
// forward their existing header without translation.
const HeaderCorrelationID = "X-Correlation-Id"

// correlationIDKey is an unexported type used as a context-value key.
// The unexported type is the Go convention for context keys — it makes
// accidental collisions impossible.
type correlationIDKey struct{}

// WithCorrelationID returns a child context carrying the given id.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey{}, id)
}

// CorrelationIDFromContext returns the correlation id stored on ctx,
// or an empty string when absent. Handlers use this to stamp events.
func CorrelationIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey{}).(string); ok {
		return id
	}
	return ""
}

// CorrelationMiddleware returns an http.Handler middleware that:
//   - reads the incoming X-Correlation-Id header when present,
//   - generates a fresh id when absent,
//   - stores it on the request context for handlers to read via
//     CorrelationIDFromContext,
//   - echoes it in the response header so clients (and fronting
//     proxies / SIEM ingest) can join log streams across tiers.
//
// CMMC 3.3.5: correlate audit record review across components.
func CorrelationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderCorrelationID)
		if id == "" {
			id = newRandomID()
		}
		w.Header().Set(HeaderCorrelationID, id)
		next.ServeHTTP(w, r.WithContext(WithCorrelationID(r.Context(), id)))
	})
}
