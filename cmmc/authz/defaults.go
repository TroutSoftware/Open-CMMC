package authz

import (
	"errors"
	"time"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// SeedDefaultGroupPerms writes an opinionated starter roster to the
// authz store — but ONLY if the store is empty. Re-running bootstrap
// on a populated deployment is a no-op, so operators can reassign
// roles via the admin UI without the seeder fighting them.
//
// The roster mirrors the Keycloak group seed in config/keycloak/
// bootstrap.sh so a fresh install lands with working authz out of
// the box: engineering+quality+management can upload and edit,
// sales can only view, compliance is the ISSO (Admin).
//
// Returns the number of rows actually written (zero on re-run).
func SeedDefaultGroupPerms(store Store) (int, error) {
	if store == nil {
		return 0, nil
	}
	existing, err := store.List()
	if err != nil {
		return 0, err
	}
	if len(existing) > 0 {
		return 0, nil
	}
	defaults := []struct {
		Group string
		Role  RolePreset
	}{
		{"engineering", RoleContributor},
		{"quality", RoleContributor},
		{"management", RoleContributor},
		{"operations", RoleContributor},
		{"sales", RoleViewer},
		{"compliance", RoleAdmin},
		// filebrowser-admins is the existing FB_OIDC_ADMIN_GROUPS
		// convention. We still seed it as an explicit row so the
		// Groups & Permissions UI shows it; membership there also
		// wins via the admin-group short-circuit in
		// ComputeEffectivePerms.
		{"filebrowser-admins", RoleAdmin},
	}
	now := time.Now().UTC()
	written := 0
	for _, d := range defaults {
		// Defensive: another process could have inserted a row
		// between List and here. Skip if present.
		if _, err := store.Get(d.Group); err == nil {
			continue
		} else if !errors.Is(err, fberrors.ErrNotExist) {
			return written, err
		}
		gp := &GroupPermission{
			GroupName:  d.Group,
			Role:       d.Role,
			Source:     "bootstrap",
			CreatedAt:  now,
			ModifiedAt: now,
		}
		if err := store.Put(gp); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}
