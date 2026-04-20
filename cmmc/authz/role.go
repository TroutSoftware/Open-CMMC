// Package authz is filebrowser's app-layer authorization. Identity
// lives in Keycloak (who the user is, which groups they belong to);
// authz here answers what they're allowed to DO with files.
//
// The model is opinionated: four role presets collapse the upstream
// 8-checkbox permission matrix into choices an ISSO can actually
// reason about during an audit. Group membership is the unit of
// assignment — users inherit the UNION of their groups' roles on
// every login, so changes in Keycloak take effect the next time the
// user authenticates.
package authz

import (
	"time"

	"github.com/filebrowser/filebrowser/v2/users"
)

// RolePreset is a coarse-grained permission bundle. Four presets is
// a deliberate design constraint: more granularity hasn't paid off
// in CMMC assessments where auditors want "who can do what" to fit
// on one page. If a deployment really needs a 5th role, add it here
// and the frontend dropdown picks it up automatically via RoleMeta().
type RolePreset string

const (
	// RoleNone denies every action. Used as the empty default for
	// groups that have never been configured — safer than silently
	// granting read.
	RoleNone RolePreset = ""

	// RoleViewer can download, preview, and search files. Cannot
	// upload, modify, rename, delete, or share.
	RoleViewer RolePreset = "viewer"

	// RoleContributor can read + upload + modify existing files.
	// Cannot rename, delete, or share. Typical for engineering
	// users who add drawings but don't manage the filesystem.
	RoleContributor RolePreset = "contributor"

	// RoleCollaborator is Contributor + rename + delete + share.
	// Typical for PMs and quality leads who reorganize folders and
	// send transfers to external parties.
	RoleCollaborator RolePreset = "collaborator"

	// RoleAdmin is Collaborator + Admin flag (marking CUI, reading
	// audit, managing users/groups). ISSO-level role. Also mapped
	// from the FB_OIDC_ADMIN_GROUPS config so operators can keep
	// using the existing "filebrowser-admins" convention.
	RoleAdmin RolePreset = "admin"
)

// RoleLabel returns a human-readable label for UI display and audit
// reasons. Keeping this in the backend so SIEM events can include
// the label without the frontend having to maintain a separate map.
func RoleLabel(r RolePreset) string {
	switch r {
	case RoleViewer:
		return "Viewer"
	case RoleContributor:
		return "Contributor"
	case RoleCollaborator:
		return "Collaborator"
	case RoleAdmin:
		return "Admin (ISSO)"
	}
	return "No access"
}

// AllRoles lists the presets in display order. Frontend dropdowns
// render this verbatim.
func AllRoles() []RolePreset {
	return []RolePreset{RoleNone, RoleViewer, RoleContributor, RoleCollaborator, RoleAdmin}
}

// ApplyRole translates a role preset into users.Permissions. This is
// the single place role→perm mapping lives; the HTTP handlers read
// only the resulting struct so the mapping table can evolve without
// touching the request path.
//
// The mapping intentionally never sets Perm.Execute — command
// execution is incompatible with a CMMC cabinet and has been
// disabled at the binary build level (enableExec=false). If a
// deployment re-enables exec, Execute must be added explicitly to
// the Admin preset here.
func ApplyRole(r RolePreset) users.Permissions {
	switch r {
	case RoleAdmin:
		return users.Permissions{
			Admin: true, Download: true, Create: true,
			Rename: true, Modify: true, Delete: true, Share: true,
		}
	case RoleCollaborator:
		return users.Permissions{
			Download: true, Create: true,
			Rename: true, Modify: true, Delete: true, Share: true,
		}
	case RoleContributor:
		return users.Permissions{
			Download: true, Create: true, Modify: true,
		}
	case RoleViewer:
		return users.Permissions{
			Download: true,
		}
	}
	return users.Permissions{} // RoleNone — everything false
}

// MergePerms returns the UNION of two permission sets. A user in
// multiple groups gets the superset; this is the "OR across groups"
// contract documented in the model.
func MergePerms(a, b users.Permissions) users.Permissions {
	return users.Permissions{
		Admin:    a.Admin || b.Admin,
		Execute:  a.Execute || b.Execute,
		Create:   a.Create || b.Create,
		Rename:   a.Rename || b.Rename,
		Modify:   a.Modify || b.Modify,
		Delete:   a.Delete || b.Delete,
		Share:    a.Share || b.Share,
		Download: a.Download || b.Download,
	}
}

// GroupPermission is the per-Keycloak-group authorization record
// stored in the backend. Indexed by GroupName (unique); ID is storm
// auto-increment.
type GroupPermission struct {
	ID         uint       `storm:"id,increment"`
	GroupName  string     `storm:"unique"`
	Role       RolePreset
	CreatedAt  time.Time
	ModifiedAt time.Time

	// Source records who assigned this role — "admin:N" for
	// explicit assignment, "bootstrap" for first-boot defaults,
	// "migration" for the Phase 2 sweep. Keeps the audit trail
	// honest about authority provenance.
	Source string
}
