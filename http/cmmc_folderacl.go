package fbhttp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	"github.com/filebrowser/filebrowser/v2/cmmc/cabinet"
)

// maxACLBodyBytes caps PUT body reads so a pathological payload
// can't OOM the bolt row. 64 KiB comfortably fits hundreds of
// entries and still blocks abuse.
const maxACLBodyBytes = 64 * 1024

// defaultEntry mirrors folderacl.Entry but carries a Source string
// describing where the default came from (cabinet starter, admin
// group, etc.). Rendered read-only in the UI so admins see what's
// in force even when no explicit ACL has been written.
type defaultEntry struct {
	Kind   folderacl.Kind `json:"kind"`
	ID     string         `json:"id"`
	Perms  folderacl.Perms `json:"perms"`
	Source string         `json:"source"`
}

// effectiveDefaultsFor returns the starter-cabinet permissions
// that would apply at normalizedPath when no explicit ACL is
// attached. Two sources:
//
//   1. cabinet.DefaultLayout — the seeded starter roster. The
//      folder's Owner group gets read + write on the folder
//      itself + every subfolder under it. Admin-group
//      membership bypass is implicit and not listed here
//      (shown in the UI banner separately).
//   2. filebrowser-admins group always has full access (same
//      effect as the evaluator's IsAdmin bypass, surfaced so
//      operators don't wonder why their admin can see
//      everything).
//
// Matching: walk cabinet.DefaultLayout entries; the first one
// whose root-relative name is an ancestor of (or equals)
// normalizedPath wins. If none match, the return is empty —
// there's no starter default for paths the admin created at
// runtime.
func effectiveDefaultsFor(normalizedPath string) []defaultEntry {
	out := []defaultEntry{
		{
			Kind:  folderacl.KindGroup,
			ID:    "filebrowser-admins",
			Perms: folderacl.Perms{Read: true, Write: true, Share: true},
			Source: "built-in: admins bypass every ACL",
		},
	}
	// Find the matching starter drawer. Normalize each
	// DefaultLayout entry name to a leading-slash path for
	// ancestor comparison.
	trimmed := strings.TrimPrefix(normalizedPath, "/")
	for _, f := range cabinet.DefaultLayout {
		name := f.Name
		if trimmed == name || strings.HasPrefix(trimmed, name+"/") {
			out = append(out, defaultEntry{
				Kind:  folderacl.KindGroup,
				ID:    f.Owner,
				Perms: folderacl.Perms{Read: true, Write: true, Share: true},
				Source: "starter cabinet: " + f.Name + " owner",
			})
			break
		}
	}
	return out
}

// emitACLReject records a tier-4 ACL denial as a chain-stamped
// audit event. Called from data.evalFolderACL whenever an ACL
// flipped a would-be allow into a deny so SIEM rules can alert
// on 3.3.1 access-control events that never reached the resource
// handler. ACLSource is the folder at which the matching ACL is
// attached — may differ from path when inheritance fired.
func emitACLReject(d *data, path, action, aclSource string) {
	ev := audit.New(audit.ActionCUIACLReject, audit.OutcomeReject)
	if d.user != nil {
		ev.UserID = userIDString(d.user.ID)
		ev.Username = d.user.Username
	}
	ev.Resource = path
	ev.Reason = "denied by folder ACL at " + aclSource + " (action=" + action + ")"
	audit.Emit(nil, ev)
}

// aclReadHandler returns the ACL attached exactly at ?path. Admin-
// gated: an ACL enumerates principals that can access a subtree
// including principals the caller themselves is NOT a member of.
// Exposing that to non-admins is CMMC 3.1.3 information-flow
// disclosure — a sales user learns which engineering users were
// specifically granted access to a CUI drawer. Reviewer-flagged
// before release; keep withAdmin.
//
// Query:  path=/Engineering_CUI   (required; normalized server-side)
// Returns: 200 + FolderACL JSON, or an empty ACL when nothing is
//          attached so the UI can render "no explicit rules".
var aclReadHandler = withAdmin(aclReadFn)

// aclReadFn is the inner function — exposed so tests can call it
// directly without minting a withUser JWT. The admin gate is
// exercised by dedicated middleware tests; functional tests drive
// this directly with a preset d.user.Perm.Admin.
var aclReadFn = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if d.store == nil || d.store.FolderACLs == nil {
		return http.StatusServiceUnavailable, errors.New("folder ACL store not configured")
	}
	raw := strings.TrimSpace(r.URL.Query().Get("path"))
	norm, ok := folderacl.NormalizePath(raw)
	if !ok {
		return http.StatusBadRequest, nil
	}
	acl, err := d.store.FolderACLs.Get(norm)
	if err != nil && !errors.Is(err, folderacl.ErrNotExist) {
		return http.StatusInternalServerError, err
	}
	if acl == nil {
		acl = &folderacl.FolderACL{Path: norm, Entries: []folderacl.Entry{}}
	}
	// Response envelope carries both the explicit ACL AND the
	// starter defaults so the modal can render "in force now: X"
	// without a second round-trip. Admins otherwise had no way to
	// know what the implicit baseline was.
	resp := struct {
		*folderacl.FolderACL
		Defaults []defaultEntry `json:"defaults"`
	}{
		FolderACL: acl,
		Defaults:  effectiveDefaultsFor(norm),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&resp)
	return 0, nil
}

// aclPutHandler upserts the ACL at the given path. Admin + fresh
// MFA gate is applied at route-registration time (http/http.go).
var aclPutHandler = withAdmin(aclPutFn)

var aclPutFn = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if d.store == nil || d.store.FolderACLs == nil {
		return http.StatusServiceUnavailable, errors.New("folder ACL store not configured")
	}
	// Cap body so a pathological payload can't OOM the bolt row.
	body := http.MaxBytesReader(w, r.Body, maxACLBodyBytes)
	defer body.Close()
	var req folderacl.FolderACL
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			return http.StatusBadRequest, err
		}
		return http.StatusRequestEntityTooLarge, err
	}
	// Caller-supplied timestamps are ignored.
	req.CreatedAt = time.Time{}
	req.ModifiedAt = time.Time{}

	if err := req.Validate(); err != nil {
		return http.StatusBadRequest, err
	}
	if err := d.store.FolderACLs.Put(&req); err != nil {
		return http.StatusInternalServerError, err
	}
	w.Header().Set("Content-Type", "application/json")
	// Re-read so the response carries the stamped timestamps.
	saved, getErr := d.store.FolderACLs.Get(req.Path)
	if getErr != nil {
		return http.StatusInternalServerError, getErr
	}
	_ = json.NewEncoder(w).Encode(saved)
	return 0, nil
}

// aclListHandler returns every ACL in the store for the admin
// "all permissions" view. Admin-gated.
var aclListHandler = withAdmin(aclListFn)

var aclListFn = func(w http.ResponseWriter, _ *http.Request, d *data) (int, error) {
	if d.store == nil || d.store.FolderACLs == nil {
		return http.StatusServiceUnavailable, errors.New("folder ACL store not configured")
	}
	acls, err := d.store.FolderACLs.List()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if acls == nil {
		acls = []*folderacl.FolderACL{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"acls": acls})
	return 0, nil
}

// aclDeleteHandler removes the ACL at ?path. Missing is a no-op.
var aclDeleteHandler = withAdmin(aclDeleteFn)

var aclDeleteFn = func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if d.store == nil || d.store.FolderACLs == nil {
		return http.StatusServiceUnavailable, errors.New("folder ACL store not configured")
	}
	norm, ok := folderacl.NormalizePath(strings.TrimSpace(r.URL.Query().Get("path")))
	if !ok {
		return http.StatusBadRequest, nil
	}
	if err := d.store.FolderACLs.Delete(norm); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusNoContent, nil
}
