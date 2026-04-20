package fbhttp

import (
	"errors"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/afero"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	session "github.com/filebrowser/filebrowser/v2/cmmc/auth/session"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	_ "github.com/filebrowser/filebrowser/v2/cmmc/scan" // RejectedError shape
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// cuiMarkFor resolves a user-relative path to its effective Mark —
// the file's own mark if one is set, otherwise the nearest ancestor
// folder's mark. Folder-level classification is the authority; per-
// file rows are rare overrides set by admins.
//
// Returns MarkNone (the zero value) when the store is unconfigured,
// nothing in the lineage is classified, or lookup fails — callers
// should treat real errors separately if they want strict fail-
// closed behavior.
func cuiMarkFor(d *data, userRelPath string) (cmmcmark.Mark, error) {
	if d.store == nil || d.store.FileMetadata == nil {
		return cmmcmark.MarkNone, nil
	}
	if d.user == nil {
		return cmmcmark.MarkNone, nil
	}
	md, err := d.store.FileMetadata.GetEffective(d.user.FullPath(userRelPath))
	if errors.Is(err, fberrors.ErrNotExist) {
		return cmmcmark.MarkNone, nil
	}
	if err != nil {
		return cmmcmark.MarkNone, err
	}
	return md.Mark, nil
}

// emitCUIAccessReject stamps a cui.access.reject event with the
// caller identity, the mark that triggered the block, the HTTP
// status the handler is about to return, and the reason. Mirrors
// the shape of emitPrivRejectEvent so SIEM rules can join on the
// common fields.
func emitCUIAccessReject(r *http.Request, d *data, mark cmmcmark.Mark, status int, reason string) {
	ev := audit.New(audit.ActionCUIAccessReject, audit.OutcomeReject)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = r.URL.Path
	ev.Status = status
	ev.Reason = reason + " [mark=" + string(mark) + "]"
	audit.Emit(r.Context(), ev)
}

// enforceCUIRead is the single chokepoint for read-path enforcement.
// Every handler that streams file bytes (raw, preview, encoded resource
// read, zip, public share DL) calls this before producing output.
//
// Returns an HTTP status the caller should propagate (non-zero means
// "stop and return this status"), or 0 meaning "not CUI, or CUI +
// authorized — proceed".
//
// For authenticated flows: CUI requires that the session carries an
// OIDC MFA assertion (cmmc_mfa_at > 0). We intentionally do NOT
// re-check the 10-min freshness window here — that gate is reserved
// for sensitive WRITE routes (mark-set, ACL change, share create,
// settings update). Forcing a re-MFA every 10 min to preview a PDF
// was user-hostile without meaningful CMMC uplift; CMMC 3.5.3
// mandates MFA at login, not periodic re-MFA for each read.
// For public (unauthenticated) flows: CUI is hard-403 because there
// is no step-up challenge to offer an anonymous caller.
//
// Emits a cui.access.reject event on every block. Does NOT emit on
// pass-through (the route-level withAuditEmit handles that).
func enforceCUIRead(r *http.Request, d *data, userRelPath, reason string, isPublic bool) int {
	mark, err := cuiMarkFor(d, userRelPath)
	if err != nil {
		return http.StatusInternalServerError
	}
	if !mark.IsCUI() {
		return 0
	}
	if isPublic {
		emitCUIAccessReject(r, d, mark, http.StatusForbidden, "public access to CUI blocked: "+reason)
		return http.StatusForbidden
	}
	if hasMFAClaim(r, d) {
		return 0
	}
	emitCUIAccessReject(r, d, mark, http.StatusUnauthorized, reason)
	return http.StatusUnauthorized
}

// enforceCUIReadTree walks each of the given root paths on the user's
// Fs, collects the strictest Mark across all descendants, and applies
// the same gate as enforceCUIRead. Used by the directory-zip handler
// so a caller cannot bypass CUI MFA by archiving a parent directory
// that contains CUI children.
//
// Non-public only — the dir-archive path is never exposed to
// unauthenticated share consumers (those serve single files).
func enforceCUIReadTree(r *http.Request, d *data, rootRelPaths []string) int {
	if d.store == nil || d.store.FileMetadata == nil || d.user == nil {
		return 0
	}
	var worst cmmcmark.Mark = cmmcmark.MarkNone
	for _, root := range rootRelPaths {
		absRoot := d.user.FullPath(root)
		walkErr := afero.Walk(d.user.Fs, root, func(p string, _ os.FileInfo, werr error) error {
			if werr != nil {
				return nil // skip unreadable entries; don't surface fs errors as CUI bypass
			}
			_ = absRoot
			md, gerr := d.store.FileMetadata.Get(d.user.FullPath(p))
			if gerr != nil {
				return nil
			}
			if md.Mark.IsCUI() {
				worst = md.Mark
			}
			return nil
		})
		if walkErr != nil {
			return http.StatusInternalServerError
		}
		if worst.IsCUI() {
			break
		}
	}
	if !worst.IsCUI() {
		return 0
	}
	if hasMFAClaim(r, d) {
		return 0
	}
	emitCUIAccessReject(r, d, worst, http.StatusUnauthorized, "archive contains CUI; requires session-level MFA")
	return http.StatusUnauthorized
}

// enforceCUIMoveRule applies the CMMC 3.8.3 containment rule:
// a CUI-marked source cannot end up in a destination whose effective
// classification is weaker. "Weaker" today is binary — the
// destination parent folder is not CUI at all. A stricter ordering
// (e.g., BASIC cannot be moved into a SPECIFIED-only folder) is a
// follow-up; it would slot in by replacing the IsCUI check with a
// rank comparison.
//
// Returns (status, srcMark) — status is 0 when the move is allowed,
// otherwise the HTTP code to return. srcMark is returned so the
// caller's audit event can carry the classification value. Keeping
// the audit emit out of this helper lets different call sites use
// different event actions (move-block vs copy-block in the future).
func enforceCUIMoveRule(r *http.Request, d *data, userSrc, userDst string) (int, cmmcmark.Mark) {
	_ = r
	if d.store == nil || d.store.FileMetadata == nil || d.user == nil {
		return 0, cmmcmark.MarkNone
	}
	srcAbs := d.user.FullPath(userSrc)
	dstAbs := d.user.FullPath(userDst)
	srcMark, err := srcMarkFor(d, srcAbs)
	if err != nil {
		return http.StatusInternalServerError, cmmcmark.MarkNone
	}
	if !srcMark.IsCUI() {
		return 0, cmmcmark.MarkNone // nothing to protect
	}
	// Destination's effective classification comes from its PARENT
	// folder — if the dst path itself doesn't exist yet (it's where
	// the moved file will land), walking up from dst is equivalent
	// to walking from its parent.
	dstMark, err := srcMarkFor(d, dstAbs)
	if err != nil {
		return http.StatusInternalServerError, srcMark
	}
	if !dstMark.IsCUI() {
		return http.StatusForbidden, srcMark
	}
	return 0, srcMark
}

// srcMarkFor is a helper used by enforceCUIMoveRule that resolves
// an ABSOLUTE path (already FullPath'd) to its effective mark.
// Separate from cuiMarkFor (which takes a user-relative path + runs
// FullPath) because at the rename/copy site we've already done the
// translation.
func srcMarkFor(d *data, absPath string) (cmmcmark.Mark, error) {
	if d.store.FileMetadata == nil {
		return cmmcmark.MarkNone, nil
	}
	md, err := d.store.FileMetadata.GetEffective(absPath)
	if errors.Is(err, fberrors.ErrNotExist) {
		return cmmcmark.MarkNone, nil
	}
	if err != nil {
		return cmmcmark.MarkNone, err
	}
	return md.Mark, nil
}

// emitCUIMoveBlocked is the dedicated audit action for a containment-
// rule denial (CMMC 3.8.3). Distinct from cui.access.reject (used by
// download / preview / share blocks) so SIEM rules can count move
// denials separately and operators don't have to parse reason strings.
func emitCUIMoveBlocked(r *http.Request, d *data, srcPath, dstPath string, srcMark cmmcmark.Mark) {
	ev := audit.New(audit.ActionCUIMoveBlocked, audit.OutcomeReject)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = srcPath + " -> " + dstPath
	ev.Status = http.StatusForbidden
	ev.Reason = "CUI containment rule: move to less-controlled path [mark=" + string(srcMark) + "]"
	audit.Emit(r.Context(), ev)
}

// emitCUIDeclassify stamps an admin action that removed a folder- or
// file-level CUI classification. CMMC 3.8.3 / DoDI 5200.48 expect
// this to be independently auditable AND carry a human-provided
// reason — "when did we downgrade X and why" is one SIEM query.
// The handler validates that reason is non-empty before calling us.
func emitCUIDeclassify(r *http.Request, d *data, absPath string, prevMark cmmcmark.Mark, reason string) {
	ev := audit.New(audit.ActionCUIDeclassify, audit.OutcomeSuccess)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = absPath
	// Store both fields in Reason — prior mark for correlation, the
	// operator-supplied justification for the 3.8.3 audit trail. Pipe
	// delimiter keeps SIEM parsers happy without adding a new column.
	ev.Reason = "prev=" + string(prevMark) + " | reason=" + reason
	audit.Emit(r.Context(), ev)
}

// emitScanReject records an infected-upload rejection under the
// dedicated cui.scan.reject audit action. Called from upload
// handlers that catch *scan.RejectedError from the envelope layer.
// Signature makes SIEM rules cleanly distinguish "Eicar-Test" from
// a real Win.Trojan detection.
func emitScanReject(r *http.Request, d *data, path, signature string) {
	ev := audit.New(audit.ActionCUIScanReject, audit.OutcomeReject)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = path
	ev.Status = http.StatusUnprocessableEntity
	ev.Reason = "malicious-code detected [signature=" + signature + "]"
	audit.Emit(r.Context(), ev)
}

// emitScanError records a scanner-backend failure. Separate action
// so SIEM can alert on "clamd sick" independently of actual
// detections. Only emitted in Required mode (Optional logs + passes).
func emitScanError(r *http.Request, d *data, path string, err error) {
	ev := audit.New(audit.ActionCUIScanError, audit.OutcomeFailure)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = path
	ev.Status = http.StatusServiceUnavailable
	ev.Reason = "scanner backend error: " + err.Error()
	audit.Emit(r.Context(), ev)
}

// emitCUIMarkOrphan stamps a high-signal event when the filesystem op
// (rename/copy/delete) succeeded but the marking store update failed,
// leaving a CUI file without its mark or a stale row pointing at a
// ghost path. Operators should reconcile these manually; SIEM should
// alert on this action unconditionally.
func emitCUIMarkOrphan(r *http.Request, d *data, src, dst, reason string) {
	ev := audit.New(audit.ActionCUIMarkOrphan, audit.OutcomeFailure)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = src + " -> " + dst
	ev.Reason = reason
	audit.Emit(r.Context(), ev)
}

// hasFreshMFA returns true iff the request carries a valid OIDC session
// JWT with a cmmc_mfa_at claim younger than the freshness threshold.
// Used by enforcement paths (e.g. CUI download) where MFA is conditional
// on the resource, not the route — withFreshMFA applies to every request
// on a route and doesn't fit that shape.
//
// On non-OIDC AuthMethods (json/proxy/hook/none) this returns true:
// those methods don't emit MFA claims and the fresh-MFA concept doesn't
// apply. CMMC production deployments are OIDC-gated at the router.
func hasFreshMFA(r *http.Request, d *data) bool {
	if d.settings.AuthMethod != fbAuth.MethodOIDCAuth {
		return true
	}
	rawTok, err := (&extractor{}).ExtractToken(r)
	if err != nil || rawTok == "" {
		return false
	}
	var c session.Claims
	tok, err := freshMFAParser.ParseWithClaims(rawTok, &c, func(_ *jwt.Token) (interface{}, error) {
		return sessionSigningKey(d.settings), nil
	})
	if err != nil || !tok.Valid {
		return false
	}
	return session.IsFreshMFA(&c, getFreshMFAThreshold())
}

// hasMFAClaim is the weaker sibling of hasFreshMFA: it returns true
// iff the session JWT carries *any* MFA evidence (cmmc_mfa_at > 0),
// without a freshness window. Used by CUI read paths so a logged-in
// user who authenticated via OIDC+MFA can preview/download CUI for
// the life of their session (JWT TTL still bounds this — currently
// 2h) without a re-auth every 10 min. Sensitive writes (mark set,
// ACL change, share create, settings update) keep the strict
// fresh-MFA gate via withFreshMFA at the route layer.
//
// Threat model: cookie is HttpOnly+SameSite=Lax and the JWT expires
// on its own; shortening CUI-read freshness below the JWT lifetime
// gives marginal benefit for meaningful UX cost.
//
// Non-OIDC AuthMethods return true — same reason hasFreshMFA does.
func hasMFAClaim(r *http.Request, d *data) bool {
	if d.settings.AuthMethod != fbAuth.MethodOIDCAuth {
		return true
	}
	rawTok, err := (&extractor{}).ExtractToken(r)
	if err != nil || rawTok == "" {
		return false
	}
	var c session.Claims
	tok, err := freshMFAParser.ParseWithClaims(rawTok, &c, func(_ *jwt.Token) (interface{}, error) {
		return sessionSigningKey(d.settings), nil
	})
	if err != nil || !tok.Valid {
		return false
	}
	return c.MFAAt > 0
}
