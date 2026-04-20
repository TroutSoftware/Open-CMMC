package bolt

import (
	"errors"

	"github.com/asdine/storm/v3"

	oidc "github.com/filebrowser/filebrowser/v2/cmmc/auth/oidc"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// oidcIdentityBackend is the bolt-backed implementation of
// oidc.IdentityStore. Storm provides the indexing and unique-constraint
// enforcement via struct tags on oidc.Identity.
type oidcIdentityBackend struct {
	db *storm.DB
}

// NewOIDCIdentityBackend returns an oidc.IdentityStore backed by the
// given bolt db handle. Called once during NewStorage.
func NewOIDCIdentityBackend(db *storm.DB) oidc.IdentityStore {
	return &oidcIdentityBackend{db: db}
}

func (b *oidcIdentityBackend) Get(issSubKey string) (*oidc.Identity, error) {
	var id oidc.Identity
	err := b.db.One("IssSubKey", issSubKey, &id)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, fberrors.ErrNotExist
		}
		return nil, err
	}
	return &id, nil
}

func (b *oidcIdentityBackend) Put(identity *oidc.Identity) error {
	// Save() performs an upsert when ID is set; for new records (ID==0)
	// storm auto-increments. The `unique` tag on IssSubKey enforces
	// uniqueness at the backend layer — a concurrent Put with the same
	// key will fail fast, which the provisioning logic handles.
	existing, err := b.Get(identity.IssSubKey)
	if err == nil {
		// Update in place — keep the existing primary key.
		identity.ID = existing.ID
	} else if !errors.Is(err, fberrors.ErrNotExist) {
		return err
	}
	return b.db.Save(identity)
}

// HasUserID implements the userLookup extension used by the oidc package
// to detect username-collision attacks on existing users during
// backfill. Returns true if ANY identity already maps to this user id.
func (b *oidcIdentityBackend) HasUserID(userID uint) (bool, error) {
	var id oidc.Identity
	err := b.db.One("UserID", userID, &id)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *oidcIdentityBackend) DeleteByUserID(userID uint) error {
	var ids []oidc.Identity
	err := b.db.Find("UserID", userID, &ids)
	if err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil
		}
		return err
	}
	for i := range ids {
		if delErr := b.db.DeleteStruct(&ids[i]); delErr != nil {
			return delErr
		}
	}
	return nil
}
