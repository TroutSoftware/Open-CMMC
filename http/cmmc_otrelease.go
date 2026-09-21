package fbhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	"github.com/filebrowser/filebrowser/v2/cmmc/otrelease"
)

// Shop-floor (OT) release API — cmmc/otrelease. Wired by cmd/root.go
// via SetOTRelease when FB_CMMC_SMB=required; every handler returns
// 503 until then so the SPA can hide the button on a plain deployment.
//
// Authorization for a release (3.1.3 flow control, 3.1.5 least
// privilege): admin, or an ACL entry on the path's lineage that grants
// Release explicitly. Unlike Read there is no cabinet-default fallback
// — nobody releases CUI to the shop floor by inheritance. Fresh MFA is
// required on the write routes (3.5.3 step-up), same as marking/ACL.

var (
	otReleaser *otrelease.Releaser
	otManager  *otrelease.Manager
)

// SetOTRelease installs the releaser and the inventory manager. Called
// once at boot.
func SetOTRelease(r *otrelease.Releaser, m *otrelease.Manager) {
	otReleaser, otManager = r, m
}

func otCellsNow() *otrelease.Cells {
	if otManager == nil {
		return nil
	}
	return otManager.Cells()
}

var errOTDisabled = errors.New("shop-floor SMB delivery is not enabled on this deployment")

// otCellView is what the SPA needs for the cell picker.
type otCellView struct {
	Name        string `json:"name"`
	Mark        string `json:"mark"`
	Machines    int    `json:"machines"`
	PDSAttested bool   `json:"pds_attested"`
	TTLDays     int    `json:"ttl_days"`
}

var otCellsFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	otCells := otCellsNow()
	if otCells == nil {
		return http.StatusServiceUnavailable, errOTDisabled
	}
	out := make([]otCellView, 0, len(otCells.Cells))
	for _, c := range otCells.Cells {
		out = append(out, otCellView{Name: c.Name, Mark: string(c.Mark), Machines: len(c.Machines), PDSAttested: c.PDSAttested, TTLDays: int(c.TTL().Hours() / 24)})
	}
	return renderJSON(w, r, out)
}

var otCellsHandler = withUser(otCellsFn)

// otReleaseRequest is the body for POST /api/cmmc/ot/release.
type otReleaseRequest struct {
	Path    string `json:"path"`
	Cell    string `json:"cell"`
	TTLDays int    `json:"ttl_days,omitempty"`
	Pinned  bool   `json:"pinned,omitempty"`
}

// canRelease is the explicit-grant check described above.
func canRelease(d *data, userRelPath string) bool {
	if d.user == nil {
		return false
	}
	if d.user.Perm.Admin {
		return true
	}
	if d.store == nil || d.store.FolderACLs == nil {
		return false
	}
	// ACLs are keyed on the user-relative path (see evalFolderACL in
	// data.go), not the server-absolute one.
	dec, err := folderacl.Evaluate(d.store.FolderACLs, folderaclPrincipalFromUser(d.user), userRelPath, folderacl.ActionRelease)
	if err != nil || dec.NoMatch {
		return false
	}
	return dec.Allowed
}

var otReleaseFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if otReleaser == nil {
		return http.StatusServiceUnavailable, errOTDisabled
	}
	var req otReleaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		return http.StatusBadRequest, err
	}
	rel := path.Clean("/" + strings.TrimPrefix(req.Path, "/"))
	if rel == "/" || strings.Contains(req.Path, "..") {
		return http.StatusBadRequest, errors.New("invalid path")
	}
	// Read access is the floor; the release grant is the gate.
	if !d.Check(rel) {
		return http.StatusForbidden, nil
	}
	if !canRelease(d, rel) {
		emitCUIAccessReject(r, d, "", http.StatusForbidden, "release requires admin or an ACL release grant")
		return http.StatusForbidden, nil
	}
	// Pinning (never expires) is admin-only: an ACL Release grant lets a
	// user put CUI on the floor for a bounded time, not indefinitely.
	if req.Pinned && !d.user.Perm.Admin {
		return http.StatusForbidden, errors.New("pinning a release requires admin")
	}
	if req.TTLDays < 0 || req.TTLDays > 365 {
		return http.StatusBadRequest, errors.New("ttl_days must be 1..365")
	}
	mark, err := cuiMarkFor(d, rel)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	m, err := otReleaser.Release(r.Context(), otrelease.ReleaseRequest{
		Fs: d.user.Fs, RelPath: rel, AbsPath: d.user.FullPath(rel), Cell: req.Cell, Mark: mark,
		ReleasedBy: d.user.Username, UserID: userIDString(d.user.ID), ClientIP: clientIP(r),
		CorrelationID: audit.CorrelationIDFromContext(r.Context()),
		TTL:           time.Duration(req.TTLDays) * 24 * time.Hour, Pinned: req.Pinned,
		Admin: d.user.Perm.Admin,
	})
	switch {
	case err == nil:
		return renderJSON(w, r, m)
	case errors.Is(err, otrelease.ErrUnknownCell):
		return http.StatusNotFound, err
	case errors.Is(err, otrelease.ErrCellDesignation), errors.Is(err, otrelease.ErrReleaseConflict):
		return http.StatusConflict, err
	case errors.Is(err, otrelease.ErrBadName):
		return http.StatusBadRequest, err
	default:
		return errToStatus(err), err
	}
}

var otReleaseHandler = withUser(otReleaseFn)

// releasedView is a manifest as shown to a web user: the cabinet path is
// user-relative (never the on-disk root) and only entries the caller may
// read are included (3.1.3 need-to-know holds for what is on the floor).
type releasedView struct {
	Name       string    `json:"name"`
	Cell       string    `json:"cell"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	Mark       string    `json:"mark"`
	Path       string    `json:"path"`
	ReleasedBy string    `json:"released_by"`
	ReleasedAt time.Time `json:"released_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Pinned     bool      `json:"pinned"`
	CanRevoke  bool      `json:"can_revoke"`
}

func userRelFromAbs(d *data, abs string) (string, bool) {
	root := strings.TrimSuffix(d.user.FullPath("/"), "/")
	if !strings.HasPrefix(abs, root+"/") {
		return "", false
	}
	return strings.TrimPrefix(abs, root), true
}

var otReleasedFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if otReleaser == nil {
		return http.StatusServiceUnavailable, errOTDisabled
	}
	cell := r.URL.Query().Get("cell")
	list, err := otReleaser.List(cell)
	if errors.Is(err, otrelease.ErrUnknownCell) {
		return http.StatusNotFound, err
	}
	if err != nil {
		return http.StatusInternalServerError, err
	}
	out := make([]releasedView, 0, len(list))
	for _, m := range list {
		rel, ok := userRelFromAbs(d, m.Source)
		if !ok || !d.Check(rel) {
			continue
		}
		out = append(out, releasedView{
			Name: m.Name, Cell: m.Cell, SHA256: m.SHA256, Size: m.Size, Mark: string(m.Mark), Path: rel,
			ReleasedBy: m.ReleasedBy, ReleasedAt: m.ReleasedAt, ExpiresAt: m.ExpiresAt, Pinned: m.Pinned,
			CanRevoke: canRelease(d, rel),
		})
	}
	return renderJSON(w, r, out)
}

var otReleasedHandler = withUser(otReleasedFn)

// otRevokeRequest is the body for DELETE /api/cmmc/ot/release.
type otRevokeRequest struct {
	Cell   string `json:"cell"`
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

var otRevokeFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if otReleaser == nil {
		return http.StatusServiceUnavailable, errOTDisabled
	}
	var req otRevokeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		return http.StatusBadRequest, err
	}
	// Revoking needs the same grant as releasing: admin, or a release
	// grant on the file's original cabinet path (read from its
	// manifest so the caller cannot forge a permitted path).
	if !d.user.Perm.Admin {
		list, err := otReleaser.List(req.Cell)
		if err != nil {
			return http.StatusNotFound, err
		}
		var src string
		for _, m := range list {
			if m.Name == req.Name {
				src = m.Source
			}
		}
		relSrc, ok := userRelFromAbs(d, src)
		if src == "" || !ok || !canRelease(d, relSrc) {
			return http.StatusForbidden, nil
		}
	}
	reason := req.Reason
	if reason == "" {
		reason = "operator"
	}
	who := otrelease.ReleaseRequest{ReleasedBy: d.user.Username, UserID: userIDString(d.user.ID), ClientIP: clientIP(r), CorrelationID: audit.CorrelationIDFromContext(r.Context())}
	err := otReleaser.Revoke(r.Context(), req.Cell, req.Name, reason, who)
	switch {
	case err == nil:
		return http.StatusNoContent, nil
	case errors.Is(err, otrelease.ErrUnknownCell), errors.Is(err, otrelease.ErrNotReleased):
		return http.StatusNotFound, err
	case errors.Is(err, otrelease.ErrBadName):
		return http.StatusBadRequest, err
	default:
		return errToStatus(err), err
	}
}

var otRevokeHandler = withUser(otRevokeFn)

// --- inventory --------------------------------------------------------

// otInventoryView is what Settings → Shop floor edits: the cells as in
// cells.yaml plus the apply status.
type otInventoryView struct {
	Cells  []otrelease.Cell `json:"cells"`
	Status otrelease.Status `json:"status"`
}

var otInventoryGetFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if otManager == nil {
		return http.StatusServiceUnavailable, errOTDisabled
	}
	return renderJSON(w, r, otInventoryView{Cells: otManager.Cells().Cells, Status: otManager.Status()})
}

var otInventoryGetHandler = withAdmin(otInventoryGetFn)

// otInventoryPut replaces the whole inventory. The body is the cells
// list plus the `modified` timestamp the client last read, so two
// admins editing at once get a 409 instead of silently overwriting each
// other. Validation is the loader's (same rules as cells.yaml by hand).
type otInventoryPut struct {
	Cells    []otrelease.Cell `json:"cells"`
	Modified time.Time        `json:"modified"`
}

var otInventoryPutFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if otManager == nil {
		return http.StatusServiceUnavailable, errOTDisabled
	}
	var req otInventoryPut
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		return http.StatusBadRequest, err
	}
	who := otrelease.ReleaseRequest{ReleasedBy: d.user.Username, UserID: userIDString(d.user.ID), ClientIP: clientIP(r), CorrelationID: audit.CorrelationIDFromContext(r.Context())}
	cells, err := otManager.Save(r.Context(), &otrelease.Cells{Cells: req.Cells}, req.Modified, who)
	switch {
	case err == nil:
		return renderJSON(w, r, otInventoryView{Cells: cells.Cells, Status: otManager.Status()})
	case errors.Is(err, otrelease.ErrInventoryConflict):
		return http.StatusConflict, err
	case errors.Is(err, otrelease.ErrInvalidCells):
		return http.StatusUnprocessableEntity, err
	default:
		return http.StatusInternalServerError, err
	}
}

var otInventoryPutHandler = withAdmin(otInventoryPutFn)
