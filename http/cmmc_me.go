package fbhttp

import (
	"net/http"
	"strconv"

	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
)

// meHandler serves GET /api/cmmc/me — the current user's own
// profile page: identity claims sourced from Keycloak at last
// login + group→role derivation + recent audit activity. Any
// authenticated user can call this about themselves; it does not
// expose any other user's state.
//
// Response:
//
//	{
//	  "username": "alice",
//	  "email":    "alice@example.local",
//	  "fullName": "Alice Chen",
//	  "groups":   ["engineering"],
//	  "roleLabels": {"engineering": "Contributor"},  // group→role for the user's groups
//	  "scope":    "/users/alice",
//	  "perm":     {...},
//	  "activity": [ ...last 20 audit events for this user_id, newest first... ]
//	}
//
// The roleLabels map lets the SPA render "Alice is a Contributor
// via engineering" without making the frontend re-join group→role
// itself — the join is already cheap on the backend.
var meHandler = withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	u := d.user
	// Group→role join for the groups this user actually belongs to.
	// Skip entirely if the authz store isn't wired (legacy deployment).
	roleLabels := map[string]string{}
	if d.store.GroupPerms != nil {
		for _, g := range u.Groups {
			if gp, err := d.store.GroupPerms.Get(g); err == nil && gp != nil {
				roleLabels[g] = authz.RoleLabel(gp.Role)
			} else {
				roleLabels[g] = authz.RoleLabel(authz.RoleNone)
			}
		}
	}
	// Per-user recent activity: filter the ring buffer by this user's
	// numeric id. Newest first for the UI; cap at 20 so the default
	// page stays light.
	cap := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			cap = n
		}
	}
	activity := []audit.Event{}
	if auditRing != nil {
		uid := userIDString(u.ID)
		snap := auditRing.Snapshot()
		// Iterate newest→oldest so we can break early.
		for i := len(snap) - 1; i >= 0 && len(activity) < cap; i-- {
			if snap[i].UserID == uid {
				activity = append(activity, snap[i])
			}
		}
	}
	return renderJSON(w, r, map[string]interface{}{
		"username":    u.Username,
		"email":       u.Email,
		"fullName":    u.FullName,
		"groups":      u.Groups,
		"roleLabels":  roleLabels,
		"scope":       u.Scope,
		"perm":        u.Perm,
		"activity":    activity,
	})
})
