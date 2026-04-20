package bolt

import (
	"errors"
	"sort"
	"time"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// groupPermBackend is the bolt-backed authz.Store. Storm manages the
// unique GroupName constraint via the struct tag.
type groupPermBackend struct {
	db *storm.DB
}

// NewGroupPermBackend wires an authz.Store onto the given bolt db.
// Called from NewStorage.
func NewGroupPermBackend(db *storm.DB) authz.Store {
	return &groupPermBackend{db: db}
}

func (b *groupPermBackend) Get(groupName string) (*authz.GroupPermission, error) {
	var gp authz.GroupPermission
	err := b.db.One("GroupName", groupName, &gp)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, fberrors.ErrNotExist
		}
		return nil, err
	}
	return &gp, nil
}

func (b *groupPermBackend) Put(gp *authz.GroupPermission) error {
	now := time.Now().UTC()
	gp.ModifiedAt = now
	// Carry ID + CreatedAt from any existing row so Save upserts
	// rather than failing on the unique-GroupName constraint.
	existing, err := b.Get(gp.GroupName)
	switch {
	case err == nil:
		gp.ID = existing.ID
		gp.CreatedAt = existing.CreatedAt
	case errors.Is(err, fberrors.ErrNotExist):
		if gp.CreatedAt.IsZero() {
			gp.CreatedAt = now
		}
	default:
		return err
	}
	return b.db.Save(gp)
}

func (b *groupPermBackend) Delete(groupName string) error {
	gp, err := b.Get(groupName)
	if err != nil {
		if errors.Is(err, fberrors.ErrNotExist) {
			return nil // idempotent
		}
		return err
	}
	return b.db.DeleteStruct(gp)
}

func (b *groupPermBackend) List() ([]*authz.GroupPermission, error) {
	var rows []authz.GroupPermission
	err := b.db.All(&rows)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return []*authz.GroupPermission{}, nil
		}
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].GroupName < rows[j].GroupName })
	out := make([]*authz.GroupPermission, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}
