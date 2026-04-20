package cabinet

import (
	"strings"

	"github.com/filebrowser/filebrowser/v2/rules"
)

// GroupRules returns the deny-list that restricts a user's visibility
// to only the folders their Keycloak group membership entitles them
// to. The cabinet is a shared root (everyone has scope "/"), so rules
// do the visibility filtering — CUI enforcement happens independently
// via the marking layer.
//
// Policy:
//   * Any user in adminGroups (e.g., filebrowser-admins): no rules,
//     full visibility. ISSO / ops needs to see every drawer.
//   * Any other user: allowed to see /Public and the {Group}/{Group}_CUI
//     pair for every group they belong to. Every other top-level
//     folder from layout is denied via an explicit rule.
//
// Denies are path-prefix rules (not regex) — cheap to match and
// consistent with how upstream filebrowser evaluates access in the
// hot path (rules/rules.go Matches). Directory browsing naturally
// hides the denied folders from the UI.
//
// Owner-to-group mapping is taken from the Folder.Owner field on the
// layout; this keeps the single source of truth (DefaultLayout) and
// avoids a separate mapping table that could drift.
func GroupRules(userGroups, adminGroups []string, layout []Folder) []rules.Rule {
	// Case-folded admin-group check. Folder.Owner matching below
	// also case-folds — inconsistent casing between those two
	// checks would let a Keycloak rename (engineering → Engineering)
	// silently drop admin status while preserving visibility for
	// other groups. Fold both sides.
	adminSet := make(map[string]struct{}, len(adminGroups))
	for _, g := range adminGroups {
		adminSet[strings.ToLower(g)] = struct{}{}
	}
	for _, g := range userGroups {
		if _, ok := adminSet[strings.ToLower(g)]; ok {
			return nil // admin sees everything
		}
	}

	userGroupSet := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		userGroupSet[strings.ToLower(g)] = struct{}{}
	}

	var out []rules.Rule
	for _, f := range layout {
		// Always visible:
		//   * Public (everyone)
		//   * folders owned by "everyone"
		if f.Owner == "everyone" || f.Name == "Public" {
			continue
		}
		// Visible if owner matches one of the user's groups.
		if _, ok := userGroupSet[strings.ToLower(f.Owner)]; ok {
			continue
		}
		// Otherwise deny browse/access at this prefix.
		out = append(out, rules.Rule{
			Allow: false,
			Path:  "/" + f.Name,
		})
	}
	return out
}
