// Package audit provides the structured event schema and emitter used
// by the CMMC-Filebrowser fork to satisfy NIST 800-171 Rev 2 3.3.x.
//
// Events are JSON-per-line records with a stable schema; they are
// written through an Emitter interface so the emission target can be
// swapped for tests (in-memory buffer) or production (stdout →
// journald → rsyslog-ossl → SIEM per architecture.md §7).
//
// Controls satisfied by a handler emitting an Event:
//   3.3.1 create and retain audit records
//   3.3.2 ensure actions of individual users can be uniquely traced
//   3.3.5 correlate audit record review across components
//
// Tamper resistance (3.3.8) and audit-admin restriction (3.3.9) are
// enforced at the ingest layer (rsyslog-ossl → WORM spool) and by
// the separate audit-admin role (separation-of-duties), both covered
// in subsequent commits.
package audit

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// Event is the canonical audit record. Fields that don't apply to a
// given action are omitted from the JSON encoding via `omitempty`.
// Adding fields is safe; renaming or removing them is an SSP-schema
// change that consumers (the customer's SIEM) must be notified about.
type Event struct {
	// Ts is RFC3339Nano UTC. The timestamp source is the host's
	// chrony-synced system clock; authenticity of time itself is
	// tracked under control 3.3.7 at the infrastructure layer.
	Ts time.Time `json:"ts"`

	// EventID uniquely identifies this record. 128 random bits
	// base64url-encoded — unguessable and collision-free in practice.
	EventID string `json:"event_id"`

	// CorrelationID groups events that belong to the same logical
	// request. Reused across the auth → callback → handler chain so
	// the SIEM can stitch a session's events together (3.3.5).
	CorrelationID string `json:"correlation_id,omitempty"`

	// Identity fields — empty when the event fires before identity
	// is known (pre-auth failures, anonymous probes).
	UserID    string `json:"user_id,omitempty"`
	Username  string `json:"username,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	// Action is a dotted namespace that names what happened.
	// Examples: auth.login.ok, auth.login.fail, authz.priv.reject,
	// user.create, user.update, user.delete, share.create,
	// share.delete, settings.update, file.upload, file.download.
	Action string `json:"action"`

	// Resource is the target of the action — a filesystem path, a
	// user identifier, a share id, etc. Intentionally a plain string
	// so consumers do not need to parse a typed union.
	Resource string `json:"resource,omitempty"`

	// Outcome is one of "success", "failure", "reject". Distinguishes
	// authorized failures (like a permission denial, outcome=reject)
	// from incidents (outcome=failure with reason).
	Outcome string `json:"outcome"`

	// Status mirrors the HTTP status code when the event originates
	// from an HTTP handler. Zero when the event is not HTTP-bound.
	Status int `json:"status,omitempty"`

	// LatencyMS is the wall-clock time the action took. Populated when
	// the emitter is wrapped with a timing helper; otherwise zero.
	LatencyMS int64 `json:"latency_ms,omitempty"`

	// Reason carries a short human-readable string for failures /
	// rejects. MUST NOT contain CUI content (file paths may — the
	// SSP notes this; operators run SIEM with CUI-adjacent handling).
	Reason string `json:"reason,omitempty"`

	// Extra holds action-specific details. Kept as a generic map so
	// the schema can evolve without breaking existing consumers.
	Extra map[string]interface{} `json:"extra,omitempty"`

	// PrevMAC and MAC are populated by HMACChainEmitter when the
	// deployment wraps the output with the chain. PrevMAC is the MAC
	// of the preceding event (empty on the chain genesis). MAC is this
	// event's HMAC-SHA256 over a fixed digest of the other fields plus
	// PrevMAC. Consumers verify via audit.VerifyChain to detect
	// insertion, deletion, reordering, or modification of the log.
	// CMMC 3.3.8.
	PrevMAC string `json:"prev_mac,omitempty"`
	MAC     string `json:"mac,omitempty"`
}

// New returns an Event with timestamp + event_id pre-populated.
// Callers set the remaining fields and pass to an Emitter.
func New(action, outcome string) *Event {
	return &Event{
		Ts:      time.Now().UTC(),
		EventID: newRandomID(),
		Action:  action,
		Outcome: outcome,
	}
}

// Outcome constants. Using typed constants avoids drift.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeReject  = "reject"
)

// Action constants for the most common events. Handlers can emit
// custom action names too — these just keep the common ones stable.
const (
	ActionAuthLoginOK     = "auth.login.ok"
	ActionAuthLoginFail   = "auth.login.fail"
	ActionAuthLogout      = "auth.logout"
	ActionAuthSignup      = "auth.signup"
	ActionSessionRenew    = "session.renew"
	ActionAuthzPrivReject = "authz.priv.reject"
	ActionSessionIdleLock = "session.idle.lock"
	ActionAuditChainFail  = "audit.chain.verify.fail"
	ActionRateLimitAuth   = "auth.ratelimit.block"
	ActionRateLimitShare  = "share.ratelimit.block"

	ActionUserCreate = "user.create"
	ActionUserUpdate = "user.update"
	ActionUserDelete = "user.delete"
	ActionUserList   = "user.list"
	ActionUserRead   = "user.read"

	ActionShareCreate = "share.create"
	ActionShareDelete = "share.delete"
	ActionShareList   = "share.list"
	ActionShareRead   = "share.read"

	ActionSettingsUpdate = "settings.update"
	ActionSettingsRead   = "settings.read"

	ActionFileUpload     = "file.upload"
	ActionFileDownload   = "file.download"
	ActionFileDelete     = "file.delete"
	ActionFileRead       = "file.read"
	ActionFileRename     = "file.rename"
	ActionFileModify     = "file.modify"
	ActionFilePreview    = "file.preview"
	ActionFileSubtitle   = "file.subtitle"
	ActionFileSearch     = "file.search"
	ActionFilePublicDL   = "file.public_download"
	ActionFilePublicRead = "file.public_share_access"

	ActionAdminUsageRead    = "admin.usage.read"
	ActionAdminCommandsRead = "admin.commands.read"

	ActionCUIMarkGet       = "cui.mark.get"
	ActionCUIMarkSet       = "cui.mark.set"
	ActionCUICatalogRead   = "cui.catalog.read"
	ActionCUIAccessReject  = "cui.access.reject"
	ActionCUIMarkOrphan    = "cui.mark.orphan"
	ActionCUIMoveBlocked   = "cui.move.blocked"
	ActionCUIDeclassify = "cui.mark.declassify"
	ActionCUIScanReject    = "cui.scan.reject"
	ActionCUIScanError     = "cui.scan.error"

	ActionAuthzGroupRead   = "authz.group.read"
	ActionAuthzGroupSet    = "authz.group.set"
	ActionAuthzGroupDelete = "authz.group.delete"
	ActionCUIACLRead       = "cui.acl.read"
	ActionCUIACLSet        = "cui.acl.set"
	ActionCUIACLDelete     = "cui.acl.delete"
	ActionCUIACLReject     = "cui.acl.reject"
)

// newRandomID returns 128 bits as base64url. The audit spec doesn't
// require ULID sortability and we don't want the extra dep.
func newRandomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand.Read failure is extraordinary; fall back to a timestamp-
		// based id so the event still emits rather than being lost.
		return "t" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
