package folderacl

import "strings"

// Action names one of the three operations the evaluator knows
// about. Deliberately separate from Perms so a future action (e.g.
// "admin") can be added without forcing every existing ACL record
// to grow a field.
type Action string

const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
	ActionShare Action = "share"
)

// Decision is the evaluator's output. Matched carries the path of
// the ACL that produced the result so the UI + audit can explain
// "access granted by /Engineering_CUI" even when the call was on
// /Engineering_CUI/rev-B/drawing.pdf.
type Decision struct {
	Allowed bool
	// Reason is a short human-readable string for audit. Kept
	// out of the wire protocol; the HTTP layer stamps it on the
	// audit event, not the response body.
	Reason string
	// MatchedPath is the path of the ACL that produced the
	// decision, or "" when no ACL along the chain named the
	// caller (evaluator returned the "no match" sentinel).
	MatchedPath string
	// NoMatch is true when evaluation ran through every ancestor
	// without finding a rule that names the caller. Callers
	// then fall back to the cabinet group-rules (implicit
	// Folder.Owner).
	NoMatch bool
}

// Principal is the caller identity the evaluator matches against
// ACL entries. username is the filebrowser username (matches
// Entry.ID when Kind=KindUser). groups is the user's Keycloak
// group list (matches Entry.ID when Kind=KindGroup). isAdmin
// short-circuits to allow.
type Principal struct {
	Username string
	Groups   []string
	IsAdmin  bool
}

// Evaluate walks the store's ancestors of path and returns the
// nearest Decision that matches the principal. Admin bypass runs
// first; if no entry along the whole chain matches the principal,
// returns a Decision with NoMatch=true so the caller can fall
// through to cabinet defaults.
//
// This function does NOT read the database directly — the Store
// abstraction lets tests inject an in-memory fake without BoltDB.
func Evaluate(store Store, principal Principal, p string, action Action) (Decision, error) {
	if principal.IsAdmin {
		return Decision{
			Allowed:     true,
			Reason:      "admin bypass",
			MatchedPath: "",
		}, nil
	}
	norm, ok := NormalizePath(p)
	if !ok {
		// Empty/malformed paths come through Check() from
		// upstream share handlers that legitimately probe "does
		// the user have access?" without a concrete path. Return
		// NoMatch so the caller's upstream allow stays intact;
		// ACL evaluation has nothing to say here.
		return Decision{NoMatch: true, Reason: "invalid path"}, nil
	}

	var out Decision
	out.NoMatch = true
	err := store.WalkAncestors(norm, func(acl *FolderACL) bool {
		if acl == nil {
			return true
		}
		if entry, matched := matchPrincipal(acl, principal); matched {
			out.NoMatch = false
			out.Allowed = permForAction(entry.Perms, action)
			out.MatchedPath = acl.Path
			if out.Allowed {
				out.Reason = "granted by ACL at " + acl.Path
			} else {
				out.Reason = "denied by ACL at " + acl.Path + " (principal matched, action not permitted)"
			}
			return false // nearest-match wins; stop walking up
		}
		return true // keep walking up
	})
	if err != nil {
		return Decision{}, err
	}
	return out, nil
}

// matchPrincipal finds the entry in acl that names the caller. A
// user's own username takes precedence over any group membership
// at the same ACL level — so an admin can individually revoke a
// user whose group would otherwise grant them. Returns the matched
// entry and true, or a zero entry and false.
//
// Comparisons are case-insensitive. IdPs vary: Keycloak preserves
// case on usernames but some installs lowercase on emission; Okta
// and Entra treat the identifier as case-insensitive end-to-end.
// Matching case-insensitively here means an admin who types "Alice"
// in the ACL grid still matches the OIDC-asserted "alice" — the
// alternative (silent lockout OR silent bypass depending on which
// way the mismatch runs) is the dangerous default.
func matchPrincipal(acl *FolderACL, principal Principal) (Entry, bool) {
	// Username match first (more specific).
	if principal.Username != "" {
		for _, e := range acl.Entries {
			if e.Kind == KindUser && strings.EqualFold(e.ID, principal.Username) {
				return e, true
			}
		}
	}
	// Group match. Lowercase the membership set once and compare
	// each entry's lowercased ID — cheaper than EqualFold per
	// candidate when the user has many groups.
	if len(principal.Groups) > 0 {
		groupSet := make(map[string]struct{}, len(principal.Groups))
		for _, g := range principal.Groups {
			groupSet[strings.ToLower(g)] = struct{}{}
		}
		for _, e := range acl.Entries {
			if e.Kind != KindGroup {
				continue
			}
			if _, ok := groupSet[strings.ToLower(e.ID)]; ok {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// permForAction maps an Action to the corresponding Perms boolean.
func permForAction(p Perms, a Action) bool {
	switch a {
	case ActionRead:
		return p.Read
	case ActionWrite:
		return p.Write
	case ActionShare:
		return p.Share
	}
	return false
}
