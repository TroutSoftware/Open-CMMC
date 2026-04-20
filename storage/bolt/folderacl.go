package bolt

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
)

// folderACLRow is the storm-persisted shape. A separate type from
// folderacl.FolderACL because storm requires a struct-tagged ID
// field and we want Path to be the unique index, not the primary
// key.
type folderACLRow struct {
	// ID is assigned by storm; we treat Path as the logical key.
	ID         int    `storm:"id,increment"`
	Path       string `storm:"unique"`
	EntriesJSON string
	CreatedAt  time.Time
	ModifiedAt time.Time
}

// folderACLBackend is the bolt-backed folderacl.Store. Entries are
// stored as a JSON blob inside each row to avoid exploding the
// schema for a variable-length nested list — storm's indexing
// only buys us something for Path, not Entries.
type folderACLBackend struct {
	db *storm.DB
}

// NewFolderACLBackend wires a folderacl.Store onto the given bolt
// database. Called from NewStorage at boot.
func NewFolderACLBackend(db *storm.DB) folderacl.Store {
	return &folderACLBackend{db: db}
}

func (b *folderACLBackend) Get(normalizedPath string) (*folderacl.FolderACL, error) {
	var row folderACLRow
	err := b.db.One("Path", normalizedPath, &row)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, folderacl.ErrNotExist
		}
		return nil, err
	}
	return rowToACL(row)
}

func (b *folderACLBackend) Put(a *folderacl.FolderACL) error {
	if err := a.Validate(); err != nil {
		return err
	}
	norm, _ := folderacl.NormalizePath(a.Path)
	a.Path = norm
	now := time.Now().UTC()
	a.ModifiedAt = now

	// Preserve CreatedAt + primary ID across upserts.
	var existing folderACLRow
	findErr := b.db.One("Path", norm, &existing)
	switch {
	case findErr == nil:
		a.CreatedAt = existing.CreatedAt
	case errors.Is(findErr, storm.ErrNotFound):
		if a.CreatedAt.IsZero() {
			a.CreatedAt = now
		}
	default:
		return findErr
	}

	entriesBlob, err := marshalEntries(a.Entries)
	if err != nil {
		return err
	}
	row := folderACLRow{
		ID:          existing.ID,
		Path:        norm,
		EntriesJSON: entriesBlob,
		CreatedAt:   a.CreatedAt,
		ModifiedAt:  a.ModifiedAt,
	}
	return b.db.Save(&row)
}

func (b *folderACLBackend) Delete(normalizedPath string) error {
	var row folderACLRow
	err := b.db.One("Path", normalizedPath, &row)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil
		}
		return err
	}
	return b.db.DeleteStruct(&row)
}

func (b *folderACLBackend) List() ([]*folderacl.FolderACL, error) {
	var rows []folderACLRow
	if err := b.db.All(&rows); err != nil {
		return nil, err
	}
	out := make([]*folderacl.FolderACL, 0, len(rows))
	for _, r := range rows {
		a, err := rowToACL(r)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (b *folderACLBackend) WalkAncestors(normalizedPath string, fn func(*folderacl.FolderACL) bool) error {
	cur := normalizedPath
	for {
		a, err := b.Get(cur)
		if err != nil && !errors.Is(err, folderacl.ErrNotExist) {
			return err
		}
		if a != nil {
			if !fn(a) {
				return nil
			}
		}
		if cur == "/" {
			return nil
		}
		i := strings.LastIndex(cur, "/")
		if i <= 0 {
			cur = "/"
		} else {
			cur = cur[:i]
		}
	}
}

// rowToACL converts the stored row into the API-facing shape.
// Keeps the JSON-encoded entries blob out of the package
// interface so callers don't have to think about serialization.
func rowToACL(r folderACLRow) (*folderacl.FolderACL, error) {
	entries, err := unmarshalEntries(r.EntriesJSON)
	if err != nil {
		return nil, err
	}
	return &folderacl.FolderACL{
		Path:       r.Path,
		Entries:    entries,
		CreatedAt:  r.CreatedAt,
		ModifiedAt: r.ModifiedAt,
	}, nil
}
