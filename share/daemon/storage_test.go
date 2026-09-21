package daemon

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mkStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod tempdir: %v", err)
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func mkMeta(t *testing.T, id string) *Metadata {
	t.Helper()
	return &Metadata{
		ID:                 id,
		CreatedAt:          time.Now().UTC(),
		ExpiresAt:          time.Now().Add(72 * time.Hour).UTC(),
		MaxDownloads:       1,
		DownloadsRemaining: 1,
		MaxFailures:        5,
		CUIMark:            "BASIC",
		SenderUserID:       "flo",
		RecipientEmailHash: "deadbeef",
		CorrelationID:      "cor-123",
		Filename:           "report.pdf",
		ContentType:        "application/pdf",
		Wrap: WrapParams{
			KDF:        "argon2id",
			Argon2Time: 3,
			Argon2Mem:  64 * 1024,
			Argon2Par:  4,
			SaltB64:    "AAAA",
			PepperID:   "p1",
			WrappedDEK: "deadbeefcafe",
			BlobNonce:  "nonce",
			BlobAEAD:   "aes-256-gcm",
		},
	}
}

func TestNewStore_RejectsWidePerms(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err := NewStore(dir)
	if err == nil || !strings.Contains(err.Error(), "too permissive") {
		t.Fatalf("expected too-permissive error, got %v", err)
	}
}

func TestNewID_UniqueAndValid(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if !validID(id) {
			t.Fatalf("validID rejects fresh id %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id in 100 draws: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestValidID_RejectsBadInput(t *testing.T) {
	bads := []string{
		"",                            // empty
		"short",                       // too short
		"0123456789ABCDEFGHJKMNPQRST", // too long by 1
		"../../../etc/passwd-AAAAAA",  // traversal attempt
		"OIL0123456789ABCDEFGHJKMNP",  // contains forbidden chars O, I, L
	}
	for _, b := range bads {
		if validID(b) {
			t.Errorf("validID accepted %q but should not", b)
		}
	}
}

func TestCreate_LoadRoundTrip(t *testing.T) {
	s := mkStore(t)
	id, _ := NewID()
	m := mkMeta(t, id)
	blob := []byte("encrypted bytes go here")
	m.BlobSize = int64(len(blob))

	if err := s.Create(m, bytes.NewReader(blob)); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Load(id)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.ID != id || got.CUIMark != "BASIC" || got.DownloadsRemaining != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	rc, err := s.OpenBlob(id)
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(data, blob) {
		t.Fatalf("blob mismatch: got %q", data)
	}
}

func TestCreate_RejectsDuplicateID(t *testing.T) {
	s := mkStore(t)
	id, _ := NewID()
	m := mkMeta(t, id)
	m.BlobSize = 3
	if err := s.Create(m, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := s.Create(m, bytes.NewReader([]byte("abc")))
	if !errors.Is(err, ErrIDConflict) {
		t.Fatalf("expected ErrIDConflict, got %v", err)
	}
}

func TestCreate_BlobSizeMismatchFails(t *testing.T) {
	s := mkStore(t)
	id, _ := NewID()
	m := mkMeta(t, id)
	m.BlobSize = 999 // lie about size
	err := s.Create(m, bytes.NewReader([]byte("abc")))
	if !errors.Is(err, ErrBlobMismatch) {
		t.Fatalf("expected ErrBlobMismatch, got %v", err)
	}
	// Store should be clean — no partial files left behind.
	files, _ := os.ReadDir(s.root)
	for _, f := range files {
		t.Errorf("leftover file: %s", f.Name())
	}
}

func TestRecordDownload_DecrementsAndBurnsAtZero(t *testing.T) {
	s := mkStore(t)
	id, _ := NewID()
	m := mkMeta(t, id)
	m.MaxDownloads = 2
	m.DownloadsRemaining = 2
	m.BlobSize = 3
	if err := s.Create(m, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.RecordDownload(id); err != nil {
		t.Fatalf("1st RecordDownload: %v", err)
	}
	got, err := s.Load(id)
	if err != nil {
		t.Fatalf("Load after 1st: %v", err)
	}
	if got.DownloadsRemaining != 1 {
		t.Fatalf("expected 1 remaining, got %d", got.DownloadsRemaining)
	}

	if _, err := s.RecordDownload(id); err != nil {
		t.Fatalf("2nd RecordDownload: %v", err)
	}
	if _, err := s.Load(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after exhaust, got %v", err)
	}
}

func TestRecordFailure_AutoBurnsAtThreshold(t *testing.T) {
	s := mkStore(t)
	id, _ := NewID()
	m := mkMeta(t, id)
	m.MaxFailures = 3
	m.BlobSize = 3
	if err := s.Create(m, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.RecordFailure(id); err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}
	if _, err := s.Load(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after max failures, got %v", err)
	}
}

func TestSweep_RemovesExpired(t *testing.T) {
	s := mkStore(t)
	idOld, _ := NewID()
	idNew, _ := NewID()
	old := mkMeta(t, idOld)
	old.ExpiresAt = time.Now().Add(-1 * time.Hour)
	old.BlobSize = 1
	fresh := mkMeta(t, idNew)
	fresh.BlobSize = 1

	_ = s.Create(old, bytes.NewReader([]byte("x")))
	_ = s.Create(fresh, bytes.NewReader([]byte("y")))

	n, err := s.Sweep(time.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 removed, got %d", n)
	}
	if _, err := s.Load(idOld); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected old removed, got %v", err)
	}
	if _, err := s.Load(idNew); err != nil {
		t.Fatalf("expected fresh kept, got %v", err)
	}
}

func TestBurn_IsIdempotent(t *testing.T) {
	s := mkStore(t)
	id, _ := NewID()
	m := mkMeta(t, id)
	m.BlobSize = 1
	_ = s.Create(m, bytes.NewReader([]byte("x")))

	if err := s.Burn(id); err != nil {
		t.Fatalf("1st Burn: %v", err)
	}
	// Calling Burn again on a gone share is intentionally not an
	// error — sweeper and admin-revoke races are expected.
	if err := s.Burn(id); err != nil {
		t.Fatalf("2nd Burn: %v", err)
	}
	// Filesystem is clean.
	files, _ := os.ReadDir(s.root)
	if len(files) != 0 {
		for _, f := range files {
			t.Errorf("leftover file: %s", filepath.Base(f.Name()))
		}
	}
}

func TestLoad_RejectsInvalidID(t *testing.T) {
	s := mkStore(t)
	if _, err := s.Load("../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for traversal, got %v", err)
	}
}

func TestExpired_Predicate(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		m    Metadata
		want bool
	}{
		{"fresh", Metadata{ExpiresAt: now.Add(1 * time.Hour), DownloadsRemaining: 1, MaxFailures: 5}, false},
		{"past-ttl", Metadata{ExpiresAt: now.Add(-1 * time.Hour), DownloadsRemaining: 1, MaxFailures: 5}, true},
		{"no-dl", Metadata{ExpiresAt: now.Add(1 * time.Hour), DownloadsRemaining: 0, MaxFailures: 5}, true},
		{"brute", Metadata{ExpiresAt: now.Add(1 * time.Hour), DownloadsRemaining: 1, MaxFailures: 3, FailureCount: 3}, true},
	}
	for _, tc := range cases {
		if tc.m.Expired(now) != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, !tc.want, tc.want)
		}
	}
}
