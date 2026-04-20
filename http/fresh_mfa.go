package fbhttp

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	session "github.com/filebrowser/filebrowser/v2/cmmc/auth/session"
)

// freshMFAParser is allocated once so withFreshMFA does not rebuild
// the parser on every privileged request.
var freshMFAParser = jwt.NewParser(
	jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	jwt.WithExpirationRequired(),
)

// withFreshMFA gates a privileged handler on the OIDC-issued session
// JWT carrying a cmmc_mfa_at claim newer than the freshness threshold.
// Other AuthMethods (json/proxy/hook/none) pass through because they
// do not emit the MFA claim.
//
// Fail-closed: missing token, invalid signature, expired token, missing
// cmmc_mfa_at, or stale cmmc_mfa_at all produce 401. Satisfies
// CMMC 3.1.15 (authorize remote priv commands) and 3.5.3 (MFA for
// priv network access) when applied to admin + destructive routes.
//
// Threshold defaults to session.DefaultFreshMFAThreshold. Override via
// the freshMFAThreshold package-level variable (set at boot from the
// FB_OIDC_MFA_FRESH_SECONDS env variable in cmd/root.go).
func withFreshMFA(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if d.settings.AuthMethod != fbAuth.MethodOIDCAuth {
			return fn(w, r, d)
		}
		rawTok, err := (&extractor{}).ExtractToken(r)
		if err != nil || rawTok == "" {
			emitPrivRejectEvent(r, "", "", "no session token")
			return http.StatusUnauthorized, nil
		}
		var c session.Claims
		tok, err := freshMFAParser.ParseWithClaims(rawTok, &c, func(_ *jwt.Token) (interface{}, error) {
			return sessionSigningKey(d.settings), nil
		})
		if err != nil || !tok.Valid {
			emitPrivRejectEvent(r, "", "", "invalid session token")
			return http.StatusUnauthorized, nil
		}
		if !session.IsFreshMFA(&c, getFreshMFAThreshold()) {
			reason := "stale MFA"
			if c.MFAAt == 0 {
				reason = "MFA claim missing (re-login required after deploy / never MFA'd)"
			}
			emitPrivRejectEvent(r, userIDString(c.User.ID), c.User.Username, reason)
			return http.StatusUnauthorized, nil
		}
		return fn(w, r, d)
	}
}

// emitPrivRejectEvent stamps an authz.priv.reject audit event with the
// caller identity (if known) and the specific reason. Called only from
// withFreshMFA reject branches — the response body stays a uniform
// "401 Unauthorized" so reject details do not leak to the caller, but
// the operator sees them in audit records.
func emitPrivRejectEvent(r *http.Request, userID, username, reason string) {
	ev := audit.New(audit.ActionAuthzPrivReject, audit.OutcomeReject)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	ev.UserID = userID
	ev.Username = username
	ev.Resource = r.URL.Path
	ev.Status = http.StatusUnauthorized
	ev.Reason = reason
	audit.Emit(r.Context(), ev)
}

// freshMFAThresholdNS holds the current threshold in nanoseconds for
// atomic read/write from request-handling goroutines vs the boot-time
// configurator. Default set in init(); override via SetFreshMFAThreshold.
var freshMFAThresholdNS atomic.Int64

func init() { freshMFAThresholdNS.Store(int64(session.DefaultFreshMFAThreshold)) }

func getFreshMFAThreshold() time.Duration {
	return time.Duration(freshMFAThresholdNS.Load())
}

// SetFreshMFAThreshold overrides the max cmmc_mfa_at age. Expected to
// be called once from cmd/root.go with FB_OIDC_MFA_FRESH_SECONDS, but
// stored atomically so a future hot-reload path is race-free.
func SetFreshMFAThreshold(d time.Duration) {
	if d > 0 {
		freshMFAThresholdNS.Store(int64(d))
	}
}
