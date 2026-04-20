package fbhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// groupsListFn handles GET /api/cmmc/groups — returns every
// group→role mapping. Any authenticated user may read the table;
// seeing which group confers which role is not a disclosure — the
// roles themselves are enforced at the file-request level.
var groupsListFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if d.store.GroupPerms == nil {
		return renderJSON(w, r, map[string]interface{}{
			"groups": []interface{}{},
			"roles":  authz.AllRoles(),
		})
	}
	rows, err := d.store.GroupPerms.List()
	if err != nil {
		return http.StatusInternalServerError, err
	}
	// Flatten the rows into a JSON-friendly shape that the SPA can
	// render without knowing storm's ID field.
	out := make([]map[string]interface{}, 0, len(rows))
	for _, gp := range rows {
		out = append(out, map[string]interface{}{
			"group":       gp.GroupName,
			"role":        string(gp.Role),
			"label":       authz.RoleLabel(gp.Role),
			"source":      gp.Source,
			"modified_at": gp.ModifiedAt,
		})
	}
	return renderJSON(w, r, map[string]interface{}{
		"groups": out,
		"roles":  authz.AllRoles(),
	})
}

var groupsListHandler = withUser(groupsListFn)

// groupPermRequest is the body shape for PUT /api/cmmc/groups.
type groupPermRequest struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

// groupsPutFn upserts a group→role mapping. Admin-only + fresh MFA
// (wired at route registration). Setting role="" clears the mapping.
var groupsPutFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if r.Body == nil {
		return http.StatusBadRequest, errors.New("missing body")
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(nil, r.Body, 8*1024)
	var req groupPermRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return http.StatusBadRequest, err
	}
	group := strings.TrimSpace(req.Group)
	if group == "" {
		return http.StatusBadRequest, errors.New("missing group")
	}
	if d.store.GroupPerms == nil {
		return http.StatusServiceUnavailable, errors.New("authz store not configured")
	}

	role := authz.RolePreset(req.Role)
	if !roleIsKnown(role) {
		return http.StatusBadRequest, errors.New("unknown role; see /api/cmmc/groups for valid values")
	}

	if role == authz.RoleNone {
		if err := d.store.GroupPerms.Delete(group); err != nil {
			return http.StatusInternalServerError, err
		}
		return renderJSON(w, r, map[string]string{"group": group, "role": ""})
	}

	gp := &authz.GroupPermission{
		GroupName:  group,
		Role:       role,
		Source:     "admin:" + userIDString(d.user.ID),
		ModifiedAt: time.Now().UTC(),
	}
	if err := d.store.GroupPerms.Put(gp); err != nil {
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, map[string]string{
		"group": group,
		"role":  string(role),
		"label": authz.RoleLabel(role),
	})
}

var groupsPutHandler = withAdmin(groupsPutFn)

// groupsDeleteFn clears a group→role row. Admin-only. Effect:
// users whose only authorization came from this group lose all
// perms on next login; multi-group users lose only what this role
// uniquely granted (because ComputeEffectivePerms unions the rest).
var groupsDeleteFn handleFunc = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	// Path form: /api/cmmc/groups/<name>
	group := strings.TrimPrefix(r.URL.Path, "/")
	if group == "" {
		return http.StatusBadRequest, errors.New("missing group name in path")
	}
	if d.store.GroupPerms == nil {
		return http.StatusServiceUnavailable, errors.New("authz store not configured")
	}
	if err := d.store.GroupPerms.Delete(group); err != nil {
		if errors.Is(err, fberrors.ErrNotExist) {
			return http.StatusNotFound, nil
		}
		return http.StatusInternalServerError, err
	}
	return renderJSON(w, r, map[string]string{"group": group, "deleted": "true"})
}

var groupsDeleteHandler = withAdmin(groupsDeleteFn)

func roleIsKnown(r authz.RolePreset) bool {
	for _, k := range authz.AllRoles() {
		if r == k {
			return true
		}
	}
	return false
}
