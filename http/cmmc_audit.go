package fbhttp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/cmmc/crypto/keyderive"
)

// maxGenesisParamLen caps the expected_genesis query param. A
// base64-url-encoded HMAC-SHA256 tag is exactly 43 chars (32 bytes
// raw, no padding). Accept up to 64 for forgiveness in case a
// caller pastes with padding or whitespace.
const maxGenesisParamLen = 64

// auditRing is the in-memory event buffer populated by the audit
// MultiEmitter at boot. cmd/root.go calls SetAuditRing once; handlers
// read via the package-level var.
var auditRing *audit.RingBufferEmitter

// SetAuditRing wires the ring buffer from cmd/root.go. Nil is allowed
// (the admin endpoint then returns an empty list) so the fbhttp
// package does not hard-fail on a deployment that chose not to
// mount a local buffer.
func SetAuditRing(r *audit.RingBufferEmitter) { auditRing = r }

// auditRecentHandler serves GET /api/cmmc/audit/recent. Returns the
// ring buffer contents as JSON, oldest first. Admin-only — wrapped
// via withAdmin at route registration time.
//
// Query params:
//   - limit=N (optional, default cap=all): cap returned events.
//     Useful for small viewports. Negative/invalid → ignored.
//
// Envelope shape:
//
//	{
//	  "capacity": 1000,
//	  "length": 42,
//	  "events": [ ...Event... ]
//	}
// auditVerifyHandler serves GET /api/cmmc/audit/verify. Walks the
// in-memory ring buffer through audit.VerifyRingBuffer and returns
// a ChainReport as JSON. Admin-only — wrapped via withAdmin at
// route registration time.
//
// CMMC 3.3.8 (protect audit information from unauthorized
// modification). Operators run this before trusting audit data
// for an investigation; SIEM correlation rules can also poll it
// to confirm the appliance's in-flight chain agrees with what the
// SIEM received.
//
// Query params:
//   - expected_genesis (optional, base64 URL-encoded): the
//     PrevMAC the caller expects on events[0]. Typically the last
//     known chain tip from the SIEM side. Omit for an internal-
//     consistency check only.
//
// Response: audit.ChainReport as JSON.
var auditVerifyHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	expectedGenesis := r.URL.Query().Get("expected_genesis")
	if expectedGenesis != "" {
		if len(expectedGenesis) > maxGenesisParamLen {
			return http.StatusBadRequest, nil
		}
		// Must be valid base64 (raw URL or std) — the chain
		// emitter writes RawURLEncoding; accept either for
		// operator-pasted values. A decode error = malformed.
		if _, err := base64.RawURLEncoding.DecodeString(expectedGenesis); err != nil {
			if _, err := base64.StdEncoding.DecodeString(expectedGenesis); err != nil {
				return http.StatusBadRequest, nil
			}
		}
	}
	// chainKeySource already returns the HKDF-derived audit subkey
	// (or nil if settings is unavailable / master too short).
	// VerifyRingBuffer.KeyMissing surfaces the nil case.
	report := audit.VerifyRingBuffer(auditRing, expectedGenesis, chainKeySource(d))
	// Emit the failure back into the chain itself. An attacker who
	// suppresses the HTTP response cannot also suppress the audit
	// row — the next verify will still see the fail event chained.
	if !report.Intact && !report.KeyMissing {
		ev := audit.New(audit.ActionAuditChainFail, audit.OutcomeFailure)
		ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
		ev.ClientIP = clientIP(r)
		ev.UserAgent = r.UserAgent()
		if d.user != nil {
			ev.UserID = userIDString(d.user.ID)
			ev.Username = d.user.Username
		}
		ev.Reason = "chain verify broke at index " + strconv.Itoa(report.FirstBreakIndex)
		audit.Emit(r.Context(), ev)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
	return 0, nil
})

// chainKeySource returns the HKDF-derived audit chain key. Must
// return the same bytes the boot-time HMACChainEmitter was built
// with (cmd/root.go calls keyderive.AuditChainKey(settings.Key) at
// startup). Shared via the keyderive package so mint and verify
// can't drift.
func chainKeySource(d *data) []byte {
	if d == nil || d.settings == nil {
		return nil
	}
	k, err := keyderive.AuditChainKey(d.settings.Key)
	if err != nil {
		return nil
	}
	return k
}

var auditRecentHandler = withAdmin(func(w http.ResponseWriter, r *http.Request, _ *data) (int, error) {
	if auditRing == nil {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"capacity": 0,
			"length":   0,
			"events":   []audit.Event{},
		})
		return 0, nil
	}
	events := auditRing.Snapshot()
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 && n < len(events) {
			events = events[len(events)-n:]
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"capacity": auditRing.Capacity(),
		"length":   auditRing.Len(),
		"events":   events,
	})
	return 0, nil
})
