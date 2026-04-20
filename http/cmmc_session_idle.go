package fbhttp

import (
	"context"
	"net/http"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/cmmc/auth/session"
)

// jtiContextKey is the request-context key where withUser stashes
// the authenticated session's jti. Handlers (oidcLogoutHandler) read
// it via jtiFromContext instead of re-parsing the JWT.
type jtiContextKey struct{}

// mfaAtContextKey — same pattern for the cmmc_mfa_at claim. Needed
// because /api/renew mints a new JWT and must carry MFA evidence
// forward; without this, withFreshMFA on the next privileged
// request (PUT /marking, user create, etc.) sees a zero MFAAt and
// 401s even though the user just finished an MFA'd login.
type mfaAtContextKey struct{}

// withJTI returns a derived context carrying the given jti.
func withJTI(ctx context.Context, jti string) context.Context {
	if jti == "" {
		return ctx
	}
	return context.WithValue(ctx, jtiContextKey{}, jti)
}

// jtiFromContext returns the jti stashed by withUser, or "" if
// none is present (non-authenticated path or the handler bypassed
// withUser).
func jtiFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(jtiContextKey{}).(string); ok {
		return v
	}
	return ""
}

// withMFAAt returns a derived context carrying the given unix-second
// MFA timestamp. Zero values are dropped (no MFA evidence on this
// session → context unchanged).
func withMFAAt(ctx context.Context, mfaAt int64) context.Context {
	if mfaAt == 0 {
		return ctx
	}
	return context.WithValue(ctx, mfaAtContextKey{}, mfaAt)
}

// mfaAtFromContext returns the cmmc_mfa_at unix-seconds stashed by
// withUser, or 0 if absent.
func mfaAtFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(mfaAtContextKey{}).(int64); ok {
		return v
	}
	return 0
}

// sessionIdleTracker holds the CMMC 3.10.2 / 3.1.11 idle-session
// state. cmd/root.go calls SetSessionIdleTracker once at boot if
// the operator enabled the feature; nil means "feature off" and
// withUser short-circuits the idle check.
var sessionIdleTracker *session.IdleTracker

// SetSessionIdleTracker wires the tracker from boot. Passing nil
// explicitly disables idle-timeout enforcement across the process.
func SetSessionIdleTracker(t *session.IdleTracker) { sessionIdleTracker = t }

// emitSessionIdleLock records the lockout as a chain-stamped audit
// event so a SIEM correlation rule can differentiate idle-timeout
// from other 401 causes. Mirrors the shape the other cmmc-
// enforcement emitters use.
func emitSessionIdleLock(r *http.Request, username, jti string) {
	ev := audit.New(audit.ActionSessionIdleLock, audit.OutcomeReject)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	ev.Username = username
	ev.Status = http.StatusUnauthorized
	ev.Reason = "session idle past threshold [jti=" + jti + "]"
	audit.Emit(r.Context(), ev)
}
