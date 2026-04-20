package oidc

// Identity maps a stable OIDC subject (issuer + sub claim) to a local
// filebrowser user id. Keyed by issSubKey = iss + "|" + sub.
//
// The stable identifier is (iss, sub) per OIDC Core §2. Username is
// display-only — some IdPs (Entra notably) allow users to rewrite
// preferred_username, so keying by username would let a user rename
// themselves onto an existing administrator and inherit their row.
type Identity struct {
	// ID is storm's auto-incremented primary key. We never reference it
	// externally; IssSubKey is the stable external identifier.
	ID uint `storm:"id,increment"`

	// IssSubKey is the composite "iss|sub" value, unique per IdP subject.
	IssSubKey string `storm:"unique"`

	// UserID is the filebrowser users.User.ID this subject is bound to.
	// Indexed so we can fast-reverse (e.g., during user deletion cleanup).
	UserID uint `storm:"index"`
}

// IdentityStore persists (iss, sub) → user_id mappings. Implementations
// live in the storage backends (storage/bolt for production). The
// provisioning logic queries this store first; on a miss it falls back
// to username matching for the legacy backfill path.
type IdentityStore interface {
	// Get returns the Identity for a given issSubKey, or an error if
	// no mapping exists. Implementations MUST return a filebrowser/v2/errors
	// ErrNotExist when the key is absent so callers can distinguish
	// not-found from other failures.
	Get(issSubKey string) (*Identity, error)

	// Put atomically upserts a mapping. For a new entry, ID is assigned by
	// the backend. For an update (same IssSubKey), UserID replaces the
	// previous value (this supports user-reassignment scenarios during
	// an incident response).
	Put(identity *Identity) error

	// DeleteByUserID removes all mappings for a given user id. Called when
	// a user is deleted so stale subject bindings do not route to a
	// non-existent user row.
	DeleteByUserID(userID uint) error
}

// IssSubKey constructs the composite storage key from the issuer URL and
// sub claim. Using "|" as a separator is safe because the OIDC iss is
// always a URL (RFC 3986 reserves "|" but URLs don't use it unescaped) and
// the sub claim is opaque to filebrowser.
func IssSubKey(iss, sub string) string {
	return iss + "|" + sub
}
