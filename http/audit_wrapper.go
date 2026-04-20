package fbhttp

import (
	"net/http"
	"time"

	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
)

// withAuditEmit wraps a handleFunc and emits a structured audit event
// after the inner handler returns. Outcome derivation:
//
//	status == 0 or 200..399  → success
//	status 400..499         → reject (expected authorization failures)
//	status 500+ or err!=nil  → failure (unexpected server-side issue)
//
// Applied at route registration time so upstream handler files stay
// untouched and the monthly rebase has nothing to reconcile.
//
// CMMC:
//   3.3.1 create/retain audit records
//   3.3.2 trace actions to users
//   3.3.5 correlate records (via the CorrelationMiddleware-stamped context)
func withAuditEmit(action string, fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		start := time.Now()
		status, err := fn(w, r, d)

		outcome := audit.OutcomeSuccess
		switch {
		case err != nil || status >= 500:
			outcome = audit.OutcomeFailure
		case status >= 400:
			outcome = audit.OutcomeReject
		}

		ev := audit.New(action, outcome)
		ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
		ev.ClientIP = clientIP(r)
		ev.UserAgent = r.UserAgent()
		if d != nil && d.user != nil {
			ev.UserID = userIDString(d.user.ID)
			ev.Username = d.user.Username
		}
		ev.Resource = r.URL.Path
		ev.Status = status
		ev.LatencyMS = time.Since(start).Milliseconds()
		if err != nil {
			ev.Reason = err.Error()
		}
		audit.Emit(r.Context(), ev)

		return status, err
	}
}
