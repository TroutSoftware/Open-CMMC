package bolt

import (
	"errors"
	"path"
	"strings"
	"time"

	"github.com/asdine/storm/v3"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// markingBackend is the bolt-backed implementation of
// cmmc/marking.Store. Storm manages the unique Path constraint and
// the OwnerID index via the struct tags on FileMetadata.
type markingBackend struct {
	db *storm.DB
}

// NewMarkingBackend wires a marking.Store onto the given bolt db.
// Called from NewStorage below.
func NewMarkingBackend(db *storm.DB) cmmcmark.Store {
	return &markingBackend{db: db}
}

func (b *markingBackend) Get(absPath string) (*cmmcmark.FileMetadata, error) {
	var md cmmcmark.FileMetadata
	err := b.db.One("Path", absPath, &md)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, fberrors.ErrNotExist
		}
		return nil, err
	}
	return &md, nil
}

// GetEffective walks up ancestors until a classified row is found.
// This is where folder classification becomes the inheritance source
// for every file underneath — uploading into /Engineering_CUI/ gets
// the folder's mark without needing a per-file row.
//
// Walk: /a/b/c/file → /a/b/c → /a/b → /a → /. Each step one Get.
// Tree depths in practice are shallow (≤ 10 levels), so the O(depth)
// lookups are not a hot-path concern. Callers that fire this for
// every item in a big directory listing should consider batching.
func (b *markingBackend) GetEffective(absPath string) (*cmmcmark.FileMetadata, error) {
	cur := absPath
	for {
		md, err := b.Get(cur)
		if err == nil {
			return md, nil
		}
		if !errors.Is(err, fberrors.ErrNotExist) {
			return nil, err
		}
		parent := path.Dir(cur)
		if parent == cur || parent == "." {
			return nil, fberrors.ErrNotExist
		}
		cur = parent
	}
}

// HasCUIDescendants returns true if any path under absPath carries
// a CUI mark. Used to refuse a folder declassification that would
// orphan CUI-marked children (CMMC 3.8.3 does not accept implicit
// downgrades of bulk CUI). Iterates all rows — fine for the CMMC
// cabinet scale (O(files)), not suitable for a multi-million-row
// corpus without an index scan.
func (b *markingBackend) HasCUIDescendants(absPath string) (bool, error) {
	prefix := strings.TrimSuffix(absPath, "/") + "/"
	var rows []cmmcmark.FileMetadata
	if err := b.db.All(&rows); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	for i := range rows {
		if strings.HasPrefix(rows[i].Path, prefix) && rows[i].Mark.IsCUI() {
			return true, nil
		}
	}
	return false, nil
}

func (b *markingBackend) Put(md *cmmcmark.FileMetadata) error {
	now := time.Now().UTC()
	md.ModifiedAt = now

	// Carry ID + CreatedAt from any existing row so Save upserts rather
	// than failing on the unique-Path constraint, and so the original
	// creation timestamp survives updates.
	existing, err := b.Get(md.Path)
	switch {
	case err == nil:
		md.ID = existing.ID
		md.CreatedAt = existing.CreatedAt
	case errors.Is(err, fberrors.ErrNotExist):
		if md.CreatedAt.IsZero() {
			md.CreatedAt = now
		}
	default:
		return err
	}
	return b.db.Save(md)
}

func (b *markingBackend) Delete(absPath string) error {
	md, err := b.Get(absPath)
	if err != nil {
		if errors.Is(err, fberrors.ErrNotExist) {
			return nil // idempotent
		}
		return err
	}
	return b.db.DeleteStruct(md)
}

func (b *markingBackend) Rename(oldPath, newPath string) error {
	// Wrap in a storm transaction so a crash or concurrent Put can't
	// leave the store in a half-renamed state (old gone, new missing).
	tx, err := b.db.Begin(true)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var md cmmcmark.FileMetadata
	if err := tx.One("Path", oldPath, &md); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil // nothing to move; commit not required
		}
		return err
	}
	if err := tx.DeleteStruct(&md); err != nil {
		return err
	}
	md.Path = newPath
	md.ModifiedAt = time.Now().UTC()
	if err := tx.Save(&md); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *markingBackend) Copy(srcPath, dstPath, sourceTag string) error {
	// One write tx: read src, upsert dst. Makes the operation safe
	// against a concurrent Rename of src between the two statements.
	tx, err := b.db.Begin(true)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var src cmmcmark.FileMetadata
	if err := tx.One("Path", srcPath, &src); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil // nothing to copy; unmarked stays unmarked
		}
		return err
	}
	now := time.Now().UTC()
	dst := cmmcmark.FileMetadata{
		Path:       dstPath,
		Mark:       src.Mark,
		OwnerID:    src.OwnerID,
		SHA256:     src.SHA256, // bytes are identical on file copy
		Source:     sourceTag,
		CreatedAt:  now,
		ModifiedAt: now,
	}
	// If a row already sits at dstPath (e.g. previous copy here),
	// carry its ID + CreatedAt so the Save upserts.
	var existing cmmcmark.FileMetadata
	if err := tx.One("Path", dstPath, &existing); err == nil {
		dst.ID = existing.ID
		dst.CreatedAt = existing.CreatedAt
	} else if !errors.Is(err, storm.ErrNotFound) {
		return err
	}
	if err := tx.Save(&dst); err != nil {
		return err
	}
	return tx.Commit()
}

// GetManyEffective resolves every input path to its effective mark
// (own row OR nearest ancestor's). One batched lookup over the union
// of all ancestor paths, then an in-memory walk-up per input.
//
// For a listing of N children at depth D the cost is O(N·D) bolt
// lookups in the worst case without batching; here we batch the
// distinct ancestor set (typically O(D + N) since many children
// share ancestors), so it's roughly O(D + N) Gets + O(N·D) map
// lookups. Well-suited to the directory-listing hot path.
func (b *markingBackend) GetManyEffective(absPaths []string) (map[string]*cmmcmark.FileMetadata, error) {
	// Collect every distinct path we'd need to look at — each
	// input plus all of its ancestors up to root.
	lookups := make(map[string]struct{})
	for _, p := range absPaths {
		cur := p
		for {
			lookups[cur] = struct{}{}
			parent := path.Dir(cur)
			if parent == cur || parent == "." {
				break
			}
			cur = parent
		}
	}
	pathList := make([]string, 0, len(lookups))
	for p := range lookups {
		pathList = append(pathList, p)
	}
	found, err := b.GetMany(pathList)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*cmmcmark.FileMetadata, len(absPaths))
	for _, p := range absPaths {
		cur := p
		for {
			if md, ok := found[cur]; ok {
				out[p] = md
				break
			}
			parent := path.Dir(cur)
			if parent == cur || parent == "." {
				break
			}
			cur = parent
		}
	}
	return out, nil
}

func (b *markingBackend) GetMany(absPaths []string) (map[string]*cmmcmark.FileMetadata, error) {
	out := make(map[string]*cmmcmark.FileMetadata, len(absPaths))
	// Storm does not have a native "IN" query over an indexed field,
	// so we iterate. For the directory-listing use case this runs
	// over <=N-children paths, not the whole store. Can be switched
	// to a prefix scan in a later commit if profiling shows a hot
	// path.
	for _, p := range absPaths {
		md, err := b.Get(p)
		if err != nil {
			if errors.Is(err, fberrors.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out[p] = md
	}
	return out, nil
}

func (b *markingBackend) DeleteByOwnerID(userID uint) error {
	var rows []cmmcmark.FileMetadata
	err := b.db.Find("OwnerID", userID, &rows)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil
		}
		return err
	}
	for i := range rows {
		if err := b.db.DeleteStruct(&rows[i]); err != nil {
			return err
		}
	}
	return nil
}
