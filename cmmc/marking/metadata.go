package marking

import "time"

// FileMetadata is the per-file CUI state the deployment tracks in
// addition to the filesystem's own metadata. Keyed on the server-
// absolute path (not the user-scoped relative path) so the same
// physical file carries the same mark regardless of which admin /
// user accesses it.
//
// Fields beyond Mark (SHA256, LastScannedAt, etc.) live here so
// the envelope-encryption + AV commits can grow this row rather
// than a parallel table. Every addition must also be mirrored in
// the HMAC-chain AAD (commit where envelope encryption lands) so
// a DB-row swap cannot re-mark a file.
type FileMetadata struct {
	// ID is storm's auto-incremented PK. Never referenced externally.
	ID uint `storm:"id,increment"`

	// Path is the absolute server-side path to the file. Unique per
	// row. When a file is renamed/moved, the Rename() method on the
	// store rewrites this field in-place.
	Path string `storm:"unique"`

	// Mark is the current CUI designation. Empty string = not CUI.
	Mark Mark

	// OwnerID is the users.User.ID that created / uploaded the file.
	// Indexed so cleanup-on-user-delete (3.5.5 / 3.9.2) is cheap.
	OwnerID uint `storm:"index"`

	// SHA256 of the plaintext content, hex-encoded. Populated by the
	// upload handler in a later commit; useful for integrity checks
	// and as a secondary rename-survival signal.
	SHA256 string

	// LastScannedAt — when ClamAV last scanned the file clean.
	// Zero means never. Populated by cmmc/scan in a later commit.
	LastScannedAt time.Time

	// Source is a short string describing who applied the current
	// Mark — an admin user id, "system" for policy-engine applied
	// marks, or "import" for bulk-loaded deployments.
	Source string

	CreatedAt  time.Time
	ModifiedAt time.Time
}

// Store persists FileMetadata rows. Implementations live in the
// storage backends (storage/bolt for production).
type Store interface {
	// Get returns the metadata for the given absolute path. Missing
	// rows return (nil, ErrNotExist) so callers can default to
	// MarkNone without a type assertion.
	Get(absPath string) (*FileMetadata, error)

	// GetEffective returns the mark that should apply to a path,
	// walking up ancestors until a row is found or the search
	// bottoms out at the root. Returns (nil, ErrNotExist) only when
	// nothing in the lineage is marked — a genuinely uncontrolled
	// path.
	//
	// This is the canonical lookup for enforcement: a file inside a
	// CUI-classified folder inherits that classification without
	// needing its own row. Folder-level classification is the
	// authority; per-file rows are overrides.
	GetEffective(absPath string) (*FileMetadata, error)

	// HasCUIDescendants reports whether any descendant of absPath
	// carries a CUI mark. Used by the declassify handler to refuse
	// unmarking a folder that still contains controlled content —
	// CMMC 3.8.3 does not allow silently downgrading a folder full
	// of CUI to uncontrolled.
	HasCUIDescendants(absPath string) (bool, error)

	// Put upserts the row. ModifiedAt is updated by the caller; the
	// store does not mutate fields beyond persisting them.
	Put(md *FileMetadata) error

	// Delete removes the row for the given path. Missing rows are
	// not an error (delete-is-idempotent contract).
	Delete(absPath string) error

	// Rename moves a row from oldPath to newPath, preserving ID and
	// Mark. Used by the file-rename / file-modify handlers. If no
	// row exists at oldPath, Rename is a no-op.
	Rename(oldPath, newPath string) error

	// Copy clones the Mark (and fields relevant to re-derivation —
	// SHA256, OwnerID) from srcPath to dstPath as a new row, stamping
	// Source with sourceTag so audit can distinguish propagated-by-
	// copy marks from admin-set ones. Transactional: reads src and
	// upserts dst atomically so a concurrent Rename of src can't
	// produce a half-copied mark. If src has no row, Copy is a
	// no-op (a copy of an unmarked file stays unmarked).
	Copy(srcPath, dstPath, sourceTag string) error

	// GetMany returns the metadata for the given absolute paths in a
	// single query. Returns a map keyed by path; paths not in the
	// store are omitted from the result. Used by directory-listing
	// handlers to fetch marks for every child in one DB round-trip.
	//
	// Exact-match only — if a file has no row of its own but inherits
	// from a CUI folder, this returns nothing. Use GetManyEffective
	// when the UI needs to render inherited classifications.
	GetMany(absPaths []string) (map[string]*FileMetadata, error)

	// GetManyEffective is GetMany with ancestor walk-up applied per
	// input path. Each returned entry is either that path's own row
	// or the nearest ancestor's row. Paths whose entire lineage is
	// uncontrolled are omitted.
	//
	// Implementation shares ancestor lookups across inputs so a
	// directory listing pays one batched query rather than
	// O(children × depth) Gets. Used by the resource listing handler
	// so the SPA renders a CUI badge on inherited files — without
	// this, a file inside /Engineering_CUI/ with no explicit row
	// would render as unmarked even though enforcement treats it
	// as CUI.
	GetManyEffective(absPaths []string) (map[string]*FileMetadata, error)

	// DeleteByOwnerID purges every row owned by the given user id.
	// Called during user deletion to avoid stranding metadata.
	DeleteByOwnerID(userID uint) error
}
