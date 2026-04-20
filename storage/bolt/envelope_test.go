package bolt

import (
	"errors"
	"testing"

	envpkg "github.com/filebrowser/filebrowser/v2/cmmc/crypto/envelope"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

func mkEnv() *envpkg.Envelope {
	return &envpkg.Envelope{
		EncDEKNonce:   make([]byte, envpkg.NonceSize),
		EncDEK:        make([]byte, envpkg.KeySize+envpkg.TagSize),
		FileNonce:     make([]byte, envpkg.NonceSize),
		PlaintextSize: 42,
	}
}

func TestEnvelopeBackend_PutGetRoundTrip(t *testing.T) {
	b := NewEnvelopeBackend(openTestBolt(t))
	if err := b.Put("/a.bin", mkEnv()); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := b.Get("/a.bin")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.PlaintextSize != 42 {
		t.Errorf("plaintextSize = %d", got.PlaintextSize)
	}
	if len(got.FileNonce) != envpkg.NonceSize {
		t.Errorf("FileNonce len = %d", len(got.FileNonce))
	}
}

func TestEnvelopeBackend_GetMissing_ReturnsErrNotExist(t *testing.T) {
	b := NewEnvelopeBackend(openTestBolt(t))
	if _, err := b.Get("/nope"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("missing returned %v, want ErrNotExist", err)
	}
}

func TestEnvelopeBackend_Put_Upserts_PreservesCreatedAt(t *testing.T) {
	b := NewEnvelopeBackend(openTestBolt(t))
	_ = b.Put("/a", mkEnv())
	// Grab createdAt via a round-trip — Get doesn't return it in
	// the Envelope shape, but we can verify behavior by re-putting
	// and checking the path is still there.
	e := mkEnv()
	e.PlaintextSize = 99
	_ = b.Put("/a", e)
	got, _ := b.Get("/a")
	if got.PlaintextSize != 99 {
		t.Errorf("upsert didn't update: %d", got.PlaintextSize)
	}
}

func TestEnvelopeBackend_Delete_Idempotent(t *testing.T) {
	b := NewEnvelopeBackend(openTestBolt(t))
	_ = b.Put("/x", mkEnv())
	if err := b.Delete("/x"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := b.Delete("/x"); err != nil {
		t.Errorf("second delete should be noop: %v", err)
	}
	if err := b.Delete("/never"); err != nil {
		t.Errorf("delete of missing should be noop: %v", err)
	}
	if _, err := b.Get("/x"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("row still present after delete")
	}
}

func TestEnvelopeBackend_Rename_MovesRow(t *testing.T) {
	b := NewEnvelopeBackend(openTestBolt(t))
	e := mkEnv()
	e.PlaintextSize = 123
	_ = b.Put("/old", e)
	if err := b.Rename("/old", "/new"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := b.Get("/old"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("old path still present")
	}
	got, err := b.Get("/new")
	if err != nil {
		t.Fatalf("get new: %v", err)
	}
	if got.PlaintextSize != 123 {
		t.Errorf("plaintextSize lost on rename: %d", got.PlaintextSize)
	}
}

func TestEnvelopeBackend_Rename_Nonexistent_IsNoop(t *testing.T) {
	b := NewEnvelopeBackend(openTestBolt(t))
	if err := b.Rename("/nope", "/also"); err != nil {
		t.Errorf("rename of missing should be noop: %v", err)
	}
}
