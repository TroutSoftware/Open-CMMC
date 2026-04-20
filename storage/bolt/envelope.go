package bolt

import (
	"errors"
	"time"

	"github.com/asdine/storm/v3"

	envpkg "github.com/filebrowser/filebrowser/v2/cmmc/crypto/envelope"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// envelopeRow is the storm-persisted shape. Keeping Envelope itself
// pure-Go (no storm tags) means the encryption package doesn't
// import storm — a cleaner dependency graph and easier to swap the
// backend later.
type envelopeRow struct {
	ID            uint   `storm:"id,increment"`
	Path          string `storm:"unique"`
	EncDEKNonce   []byte
	EncDEK        []byte
	FileNonce     []byte
	PlaintextSize int64
	CreatedAt     time.Time
	ModifiedAt    time.Time
}

type envelopeBackend struct {
	db *storm.DB
}

// NewEnvelopeBackend wires an envelope.Store onto the given bolt db.
// Called from NewStorage.
func NewEnvelopeBackend(db *storm.DB) envpkg.Store {
	return &envelopeBackend{db: db}
}

func (b *envelopeBackend) Get(absPath string) (*envpkg.Envelope, error) {
	var row envelopeRow
	if err := b.db.One("Path", absPath, &row); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil, fberrors.ErrNotExist
		}
		return nil, err
	}
	return &envpkg.Envelope{
		EncDEKNonce:   row.EncDEKNonce,
		EncDEK:        row.EncDEK,
		FileNonce:     row.FileNonce,
		PlaintextSize: row.PlaintextSize,
	}, nil
}

func (b *envelopeBackend) Put(absPath string, env *envpkg.Envelope) error {
	now := time.Now().UTC()
	row := envelopeRow{
		Path:          absPath,
		EncDEKNonce:   env.EncDEKNonce,
		EncDEK:        env.EncDEK,
		FileNonce:     env.FileNonce,
		PlaintextSize: env.PlaintextSize,
		ModifiedAt:    now,
	}
	// Upsert: preserve CreatedAt + ID from any existing row.
	var existing envelopeRow
	if err := b.db.One("Path", absPath, &existing); err == nil {
		row.ID = existing.ID
		row.CreatedAt = existing.CreatedAt
	} else if errors.Is(err, storm.ErrNotFound) {
		row.CreatedAt = now
	} else {
		return err
	}
	return b.db.Save(&row)
}

func (b *envelopeBackend) Delete(absPath string) error {
	var row envelopeRow
	if err := b.db.One("Path", absPath, &row); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil // idempotent
		}
		return err
	}
	return b.db.DeleteStruct(&row)
}

func (b *envelopeBackend) Rename(oldPath, newPath string) error {
	// Single write tx so a concurrent Put at oldPath or newPath
	// can't interleave and produce a half-renamed state.
	tx, err := b.db.Begin(true)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var row envelopeRow
	if err := tx.One("Path", oldPath, &row); err != nil {
		if errors.Is(err, storm.ErrNotFound) {
			return nil // nothing to move
		}
		return err
	}
	if err := tx.DeleteStruct(&row); err != nil {
		return err
	}
	row.Path = newPath
	row.ModifiedAt = time.Now().UTC()
	if err := tx.Save(&row); err != nil {
		return err
	}
	return tx.Commit()
}
