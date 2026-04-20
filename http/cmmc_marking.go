package fbhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// markingCatalog is the package default set of valid Marks. Production
// deployments can Extend it at boot from a config file; for v1 the
// starter constants in cmmc/marking are what the admin API accepts.
var markingCatalog = cmmcmark.DefaultCatalog()

// absPathForUser maps a user-scoped path (from a query parameter like
// `?path=/projects/foo.pdf`) into the server-absolute path used as the
// marking row key. Delegates to users.User.FullPath so marking keys
// line up byte-for-byte with the paths upload/download/rename handlers
// use (afero chroot + server.Root prefix applied the same way).
//
// Errors are returned rather than written; the caller picks the HTTP
// status. Keeps the handler flat.
func absPathForUser(d *data, userRelPath string) (string, error) {
	if userRelPath == "" {
		return "", errors.New("missing path parameter")
	}
	// Reject any ".." segment in the raw input. path.Clean would
	// collapse these to land within scope anyway, but we prefer an
	// explicit 400 over silently rewriting the path — a UI that sends
	// ".." is a bug worth surfacing.
	for _, seg := range strings.Split(userRelPath, "/") {
		if seg == ".." {
			return "", errors.New("path escapes scope")
		}
	}
	if d.user == nil {
		return "", errors.New("no user")
	}
	clean := path.Clean("/" + strings.TrimPrefix(userRelPath, "/"))
	return d.user.FullPath(clean), nil
}

// markingGetFn is the inner handler; exported (unexported name, package-level
// var) only so tests can invoke it without mocking the JWT-bearing
// withUser wrapper.
var markingGetFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	absPath, err := absPathForUser(d, r.URL.Query().Get("path"))
	if err != nil {
		return http.StatusBadRequest, err
	}
	if d.store.FileMetadata == nil {
		return http.StatusServiceUnavailable, errors.New("marking store not configured")
	}
	md, err := d.store.FileMetadata.Get(absPath)
	if errors.Is(err, fberrors.ErrNotExist) {
		return renderJSON(w, r, map[string]interface{}{
			"path": r.URL.Query().Get("path"),
			"mark": string(cmmcmark.MarkNone),
		})
	}
	if err != nil {
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, map[string]interface{}{
		"path":        r.URL.Query().Get("path"),
		"mark":        string(md.Mark),
		"source":      md.Source,
		"modified_at": md.ModifiedAt,
	})
}

// markingGetHandler is the route-registered handler. Any authenticated
// user may read marks — seeing the label on files they can already
// access is not a disclosure.
//
// GET /api/cmmc/marking?path=/foo/bar.pdf
// Response: {"path":"...", "mark":"CUI//BASIC", "source":"admin:1", "modified_at":"..."}
var markingGetHandler = withUser(markingGetFn)

// markingPutRequest is the body shape for PUT /api/cmmc/marking.
//
// Reason is mandatory when Mark=="" (declassify). CMMC 3.8.3 /
// DoDI 5200.48 expect decontrol decisions to be documented — the
// audit chain records who, when, and why. A short free-text field
// satisfies the "why" without forcing a separate change-request
// system. Length-capped so a runaway form can't DoS the audit pipe.
type markingPutRequest struct {
	Path   string `json:"path"`
	Mark   string `json:"mark"`
	Reason string `json:"reason,omitempty"`
}

const declassifyReasonMaxLen = 500

// markingPutFn is the inner handler; exposed at package level for tests.
var markingPutFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if r.Body == nil {
		return http.StatusBadRequest, errors.New("missing body")
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(nil, r.Body, 16*1024)
	var req markingPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, err
	}
	mark := cmmcmark.Mark(req.Mark)
	if !markingCatalog.Contains(mark) {
		return http.StatusBadRequest, errors.New("unknown mark; see catalog")
	}
	absPath, err := absPathForUser(d, req.Path)
	if err != nil {
		return http.StatusBadRequest, err
	}
	if d.store.FileMetadata == nil {
		return http.StatusServiceUnavailable, errors.New("marking store not configured")
	}

	if mark == cmmcmark.MarkNone {
		// Declassify gate (CMMC 3.8.3): a folder full of CUI cannot
		// be silently downgraded to uncontrolled. Refuse with 409
		// if the path has any CUI descendant.
		if hasCUI, err := d.store.FileMetadata.HasCUIDescendants(absPath); err != nil {
			return http.StatusInternalServerError, err
		} else if hasCUI {
			return http.StatusConflict, errors.New("cannot declassify: path contains CUI descendants")
		}
		// Reason is mandatory on declassify — see markingPutRequest
		// doc comment. Whitespace-only strings are treated as empty.
		reason := strings.TrimSpace(req.Reason)
		if reason == "" {
			return http.StatusBadRequest, errors.New("declassification requires a non-empty reason")
		}
		if len(reason) > declassifyReasonMaxLen {
			return http.StatusBadRequest, errors.New("declassification reason too long")
		}
		// Capture the prior mark BEFORE Delete so the audit trail
		// records what was downgraded (SIEM query: "show me every
		// time anyone unmarked a folder and what it used to be").
		var prevMark cmmcmark.Mark
		if prev, err := d.store.FileMetadata.Get(absPath); err == nil {
			prevMark = prev.Mark
		}
		if err := d.store.FileMetadata.Delete(absPath); err != nil {
			return http.StatusInternalServerError, err
		}
		emitCUIDeclassify(r, d, absPath, prevMark, reason)
		return renderJSON(w, r, map[string]string{"path": req.Path, "mark": ""})
	}
	md := &cmmcmark.FileMetadata{
		Path:       absPath,
		Mark:       mark,
		OwnerID:    d.user.ID,
		Source:     "admin:" + userIDString(d.user.ID),
		ModifiedAt: time.Now().UTC(),
	}
	if err := d.store.FileMetadata.Put(md); err != nil {
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, map[string]string{"path": req.Path, "mark": string(mark)})
}

// markingPutHandler sets or clears the Mark for a path. Admin-only.
//
// PUT /api/cmmc/marking
// Body: {"path":"/foo/bar.pdf", "mark":"CUI//BASIC"}
// Setting mark="" clears the mark (deletes the row) — idempotent.
var markingPutHandler = withAdmin(markingPutFn)

var markingCatalogFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	marks := markingCatalog.Marks()
	strMarks := make([]string, 0, len(marks))
	for _, m := range marks {
		strMarks = append(strMarks, string(m))
	}
	return renderJSON(w, r, map[string]interface{}{"marks": strMarks})
}

// markingCatalogHandler returns the set of valid Marks so the SPA can
// render a dropdown without hard-coding the list.
var markingCatalogHandler = withUser(markingCatalogFn)
