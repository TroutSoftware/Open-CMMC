// Package folderacl implements per-folder access control lists for
// the CMMC filebrowser cabinet. Starter folders in seed.go give every
// user-owned group a default drawer; folderacl layers on top so an
// admin can grant additional groups or individual users explicit
// permissions on any path — including paths created at runtime.
//
// Design in one paragraph:
//
//   - An ACL is keyed on an absolute path (e.g. "/Engineering_CUI").
//   - Each ACL carries zero or more entries; each entry names one
//     principal (either a Keycloak group or a filebrowser username)
//     and three boolean permissions: read, write, share.
//   - Evaluation walks from the leaf path up to "/". The nearest
//     ACL that names the user's principal wins. Multiple entries
//     within the same ACL that match the user's principals union.
//   - Members of filebrowser-admins bypass entirely.
//   - If no ACL along the chain names the caller, evaluation falls
//     through to the cabinet's implicit group-rules (seed.go owners)
//     so starter-cabinet behavior is unchanged until an admin writes
//     an ACL.
//
// CMMC anchors:
//   - 3.1.1 / 3.1.2 — access enforcement
//   - 3.1.5 / 3.1.7 — separation of duties / least privilege
//   - 3.1.3 — information flow control when combined with the
//     existing CUI marking rules
package folderacl

import (
	"errors"
	"path"
	"strings"
	"time"
)

// Perms carries the three permissions a principal can hold on a
// folder subtree. Omitted (false) fields are denials.
//
// Read:  list the directory and read its contents (including CUI
//        reads, subject to marking/MFA gates that live elsewhere).
// Write: create, rename, overwrite, and delete within the subtree.
// Share: generate a public share link for files in the subtree.
type Perms struct {
	Read  bool `json:"read"`
	Write bool `json:"write"`
	Share bool `json:"share"`
}

// Kind is the principal type. We deliberately avoid a free-form
// string (e.g. "role", "realm") so new kinds are an explicit code
// change, not a config-drift surface.
type Kind string

const (
	KindGroup Kind = "group"
	KindUser  Kind = "user"
)

// IsValid reports whether k is one of the declared constants.
func (k Kind) IsValid() bool {
	return k == KindGroup || k == KindUser
}

// Entry is one line in the ACL: a principal plus its grant.
type Entry struct {
	Kind  Kind   `json:"kind"`
	ID    string `json:"id"`
	Perms Perms  `json:"perms"`
}

// FolderACL is the persisted record. Path is the absolute path the
// ACL attaches to (e.g. "/Engineering_CUI"), normalized: no
// trailing slash, no "." or "..". CreatedAt/ModifiedAt are stamped
// by the backend; callers must not set them.
type FolderACL struct {
	Path       string    `json:"path"`
	Entries    []Entry   `json:"entries"`
	CreatedAt  time.Time `json:"createdAt"`
	ModifiedAt time.Time `json:"modifiedAt"`
}

// NormalizePath canonicalizes the path used as the ACL key. Leading
// slash required; trailing slash stripped; path.Clean-equivalent.
// Returns ("/", true) for the root and ("", false) when the input
// contains traversal we refuse to store (e.g. "/a/..").
func NormalizePath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	// Clean collapses "/a/.." → "/" but also turns "/..foo" into
	// "/..foo" — we don't try to be fancy. Reject any result whose
	// components include literal ".." (shouldn't happen post-Clean
	// from a rooted path, but be defensive).
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return "", false
		}
	}
	return cleaned, true
}

// Validate enforces the runtime invariants a backend can't enforce
// via its schema. Returns the first error encountered. Callers must
// run this before Put.
func (a *FolderACL) Validate() error {
	if a == nil {
		return errors.New("folderacl: nil ACL")
	}
	if _, ok := NormalizePath(a.Path); !ok {
		return errors.New("folderacl: invalid path")
	}
	seen := map[string]struct{}{}
	for i, e := range a.Entries {
		if !e.Kind.IsValid() {
			return errors.New("folderacl: entry " + itoa(i) + " has unknown kind")
		}
		if strings.TrimSpace(e.ID) == "" {
			return errors.New("folderacl: entry " + itoa(i) + " has empty id")
		}
		// A single ACL may not name the same principal twice; an
		// admin merging perms must union them into one entry.
		key := string(e.Kind) + ":" + e.ID
		if _, dup := seen[key]; dup {
			return errors.New("folderacl: duplicate entry for " + key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// itoa avoids importing strconv for a one-shot index render.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Store is the persistence contract. Implementations live under
// storage/bolt. Kept small so a future in-memory / postgres backend
// is a drop-in.
type Store interface {
	// Get returns the ACL attached at exactly this path (no
	// inheritance). Missing returns (nil, ErrNotExist) so the
	// evaluator can walk the chain cleanly.
	Get(normalizedPath string) (*FolderACL, error)

	// Put upserts the row. The backend stamps ModifiedAt and
	// preserves CreatedAt across upserts.
	Put(a *FolderACL) error

	// Delete removes the ACL at exactly this path. Missing is a
	// no-op. Subtree paths are NOT cascaded — each remains until
	// explicitly deleted.
	Delete(normalizedPath string) error

	// List returns every ACL, ordered by path. Admin UI uses this
	// for the "all permissions" view.
	List() ([]*FolderACL, error)

	// WalkAncestors calls fn for each ACL attached to any ancestor
	// of path, starting at path itself and walking up to "/".
	// Returning false from fn stops the walk — the evaluator uses
	// this to short-circuit on the nearest match.
	WalkAncestors(normalizedPath string, fn func(*FolderACL) bool) error
}

// ErrNotExist is returned by Get when the requested path has no ACL
// attached. Matches the shape used by other storage packages so
// callers can errors.Is-check across stores.
var ErrNotExist = errors.New("folderacl: not exist")
