// Package daemon implements the cmmc-share binary — the DMZ-facing
// component of Open-CMMC that serves passphrase-protected one-off
// CUI share links to external recipients.
//
// The daemon is cryptographically blind. It stores:
//   - Ciphertext blobs, already wrapped in the enclave under a DEK
//     that is itself wrapped with Argon2id(passphrase, salt, pepper).
//   - Metadata rows containing a share id, recipient email hash, TTL,
//     max-downloads counter, failure counter, and the CUI mark.
//   - A local audit buffer that the enclave drains on each backchannel
//     pull.
//
// It never receives the KEK or the passphrase across the backchannel;
// the passphrase is delivered out-of-band to the recipient and arrives
// only as an HTTP form post at download time, held in RAM for the
// duration of that single request.
package daemon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Store is the on-disk home of shares. Two files per share-id:
//
//	<root>/<id>.meta  — JSON metadata row (0600, root:cmmc-share)
//	<root>/<id>.blob  — raw ciphertext from the enclave push (0600)
//
// Concurrency: a single Store is goroutine-safe. Reads take a shared
// lock; writes take exclusive. Per-share mutation (decrement counter,
// bump failure count) runs under exclusive to avoid TOCTOU against
// the delete-on-exhaust path.
type Store struct {
	root string
	mu   sync.Mutex
}

// Metadata is what the daemon tracks per share.
//
// Anything that would let the daemon decrypt the blob is deliberately
// absent: no KEK, no passphrase, no plaintext file name (that lives
// inside the ciphertext along with the file's original mime type).
//
// RecipientEmailHash — sha256(lowercase(email) || meta_pepper). The
// daemon never stores the email itself. The hash is used only for
// audit correlation.
type Metadata struct {
	ID                 string    `json:"id"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	MaxDownloads       int       `json:"max_downloads"`
	DownloadsRemaining int       `json:"downloads_remaining"`
	FailureCount       int       `json:"failure_count"`
	MaxFailures        int       `json:"max_failures"`
	CUIMark            string    `json:"cui_mark"`
	SenderUserID       string    `json:"sender_user_id"`
	RecipientEmailHash string    `json:"recipient_email_hash"`
	CorrelationID      string    `json:"correlation_id"`

	// Wrap holds everything needed to attempt a passphrase unwrap.
	// The blob itself is stored in <id>.blob, not here.
	Wrap WrapParams `json:"wrap"`

	// BlobSize is stamped on push so the daemon can reject short
	// reads without having to trust the filesystem's Stat alone.
	BlobSize int64 `json:"blob_size"`

	// Filename and ContentType are extracted from the envelope's
	// AAD by the enclave before rewrap and carried here in plaintext
	// solely to set Content-Disposition/Content-Type on download.
	// Leaking them is not a CUI leak — the mark already signals
	// sensitivity and the filename is at the sender's discretion.
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
}

// WrapParams captures the Argon2id parameters and AEAD framing used
// by the enclave to wrap the DEK. Written by the enclave, read by the
// daemon at unwrap time. Fields are explicit so a future tuning of
// Argon2 parameters doesn't silently invalidate old shares.
type WrapParams struct {
	KDF         string `json:"kdf"`     // "argon2id"
	Argon2Time  uint32 `json:"t"`       // time cost
	Argon2Mem   uint32 `json:"m"`       // memory cost (KiB)
	Argon2Par   uint8  `json:"p"`       // parallelism
	SaltB64     string `json:"salt"`    // per-share random salt
	PepperID    string `json:"peppid"`  // which server-side pepper, for rotation
	WrappedDEK  string `json:"wdek"`    // AES-256-GCM(DEK) under Argon2-derived key (nonce||ciphertext, base64)
	BlobNonce   string `json:"bnonce"`  // nonce for the outer blob AEAD (base64)
	BlobAEAD    string `json:"bmode"`   // "aes-256-gcm"
}

// Expired returns whether m is past its TTL or out of downloads or
// out of passphrase attempts.
func (m *Metadata) Expired(now time.Time) bool {
	return now.After(m.ExpiresAt) ||
		m.DownloadsRemaining <= 0 ||
		(m.MaxFailures > 0 && m.FailureCount >= m.MaxFailures)
}

// NewStore opens root and refuses to continue if its mode is wider
// than 0700 — the ciphertext + metadata directory is the crown jewel
// of the DMZ, a world-readable directory is a finding.
func NewStore(root string) (*Store, error) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("share store: stat %q: %w", root, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("share store: %q is not a directory", root)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("share store: %q too permissive (%o); must be 0700 or narrower", root, fi.Mode().Perm())
	}
	return &Store{root: root}, nil
}

// shareIDAlphabet is Crockford-base32 without the digit/letter
// lookalikes that trip up email copy-paste (I, L, O, U). 26-char IDs
// give us >120 bits of entropy — unpredictable even in a world where
// the attacker has seen 2^32 prior share IDs.
const shareIDAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Share IDs are the only identifier in the URL. They must be
// unguessable. 16 random bytes → 26 base32 chars.
const shareIDLen = 26

var shareIDEncoding = base32.NewEncoding(shareIDAlphabet).WithPadding(base32.NoPadding)

// NewID returns a fresh random share id. Caller verifies
// collision-free by attempting a Create; on ErrIDConflict, regenerate.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("share id: random: %w", err)
	}
	return shareIDEncoding.EncodeToString(b[:])[:shareIDLen], nil
}

// validID rejects path traversal and anything that isn't our alphabet.
// Hit on every request before touching the filesystem.
func validID(id string) bool {
	if len(id) != shareIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(shareIDAlphabet, rune(id[i])) {
			return false
		}
	}
	return true
}

// ErrNotFound signals the share does not exist (or has expired and
// been swept). Serve 404 to the recipient; never distinguish from
// ErrExpired — leaking "existed once" is a correlation side-channel.
var ErrNotFound = errors.New("share: not found")

// ErrIDConflict is returned when Create hits an existing file. Caller
// should regenerate the id and retry (astronomically unlikely given
// 120 bits of entropy but cheap to handle correctly).
var ErrIDConflict = errors.New("share: id conflict")

// ErrBlobMismatch — size on disk differs from metadata. Could be a
// truncated push, filesystem corruption, or tampering. Fail closed.
var ErrBlobMismatch = errors.New("share: blob size mismatch")

// Create atomically writes both files. Uses <id>.meta.tmp + rename
// pattern so a crashed write can't leave half-rows readable.
// Errors if a metadata row already exists for id.
func (s *Store) Create(m *Metadata, blob io.Reader) error {
	if !validID(m.ID) {
		return fmt.Errorf("share: invalid id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	metaPath := filepath.Join(s.root, m.ID+".meta")
	blobPath := filepath.Join(s.root, m.ID+".blob")

	if _, err := os.Stat(metaPath); err == nil {
		return ErrIDConflict
	}

	// Blob first. A blob without metadata is orphan garbage the
	// sweeper will clean; metadata without a blob would 500 the
	// recipient.
	blobTmp := blobPath + ".tmp"
	bf, err := os.OpenFile(blobTmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("share: open blob: %w", err)
	}
	n, copyErr := io.Copy(bf, blob)
	closeErr := bf.Close()
	if copyErr != nil {
		_ = os.Remove(blobTmp)
		return fmt.Errorf("share: copy blob: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(blobTmp)
		return fmt.Errorf("share: close blob: %w", closeErr)
	}
	if m.BlobSize > 0 && n != m.BlobSize {
		_ = os.Remove(blobTmp)
		return ErrBlobMismatch
	}
	m.BlobSize = n
	if err := os.Rename(blobTmp, blobPath); err != nil {
		_ = os.Remove(blobTmp)
		return fmt.Errorf("share: rename blob: %w", err)
	}

	if err := s.writeMeta(metaPath, m); err != nil {
		_ = os.Remove(blobPath)
		return err
	}
	return nil
}

// writeMeta is atomic via tempfile + rename; callers must hold s.mu.
func (s *Store) writeMeta(metaPath string, m *Metadata) error {
	buf, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("share: marshal meta: %w", err)
	}
	tmp := metaPath + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("share: write meta: %w", err)
	}
	if err := os.Rename(tmp, metaPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("share: rename meta: %w", err)
	}
	return nil
}

// Load reads a share's metadata. Does NOT open the blob.
// Callers that go on to serve a download should call OpenBlob
// separately so the read-vs-write-vs-delete dance stays explicit.
func (s *Store) Load(id string) (*Metadata, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(id)
}

func (s *Store) loadLocked(id string) (*Metadata, error) {
	metaPath := filepath.Join(s.root, id+".meta")
	buf, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("share: read meta: %w", err)
	}
	var m Metadata
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, fmt.Errorf("share: parse meta: %w", err)
	}
	return &m, nil
}

// OpenBlob returns a reader over the ciphertext. Caller closes.
// The returned ReadCloser wraps a *os.File so Stat-based size checks
// work in the caller if needed.
func (s *Store) OpenBlob(id string) (io.ReadCloser, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	f, err := os.Open(filepath.Join(s.root, id+".blob"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("share: open blob: %w", err)
	}
	return f, nil
}

// RecordFailure bumps the failure counter. Returns the updated
// metadata. Auto-burns the share when MaxFailures is reached so a
// brute-force attempt costs the attacker the only artifact they
// had access to.
func (s *Store) RecordFailure(id string) (*Metadata, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked(id)
	if err != nil {
		return nil, err
	}
	m.FailureCount++
	if m.MaxFailures > 0 && m.FailureCount >= m.MaxFailures {
		// Mark for the sweeper + burn immediately. We don't return
		// ErrNotFound here so the caller can still emit a final
		// "share.burned-on-brute-force" audit event.
		_ = s.deleteLocked(id)
		return m, nil
	}
	if err := s.writeMeta(filepath.Join(s.root, id+".meta"), m); err != nil {
		return nil, err
	}
	return m, nil
}

// RecordDownload decrements the download counter. If it hits zero,
// the share is burned atomically inside the same critical section
// so a concurrent request can't sneak a second download through.
func (s *Store) RecordDownload(id string) (*Metadata, error) {
	if !validID(id) {
		return nil, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.loadLocked(id)
	if err != nil {
		return nil, err
	}
	if m.DownloadsRemaining <= 0 {
		return m, ErrNotFound
	}
	m.DownloadsRemaining--
	if m.DownloadsRemaining <= 0 {
		_ = s.deleteLocked(id)
		return m, nil
	}
	if err := s.writeMeta(filepath.Join(s.root, id+".meta"), m); err != nil {
		return nil, err
	}
	return m, nil
}

// Burn forcibly removes a share — used by the admin hot-revoke path
// and by the sweeper.
func (s *Store) Burn(id string) error {
	if !validID(id) {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(id)
}

func (s *Store) deleteLocked(id string) error {
	// Best-effort removal of both files. A missing blob after a
	// successful meta delete is fine — it just means a prior
	// sweep already cleaned up.
	metaErr := os.Remove(filepath.Join(s.root, id+".meta"))
	blobErr := os.Remove(filepath.Join(s.root, id+".blob"))
	if metaErr != nil && !errors.Is(metaErr, os.ErrNotExist) {
		return fmt.Errorf("share: delete meta: %w", metaErr)
	}
	if blobErr != nil && !errors.Is(blobErr, os.ErrNotExist) {
		return fmt.Errorf("share: delete blob: %w", blobErr)
	}
	return nil
}

// Sweep walks the store and burns every share whose TTL has passed
// or whose download/failure counters are already at zero. Returns
// the number of shares removed. Designed to be safe to run
// concurrently with Create / RecordDownload / RecordFailure.
func (s *Store) Sweep(now time.Time) (int, error) {
	s.mu.Lock()
	entries, err := os.ReadDir(s.root)
	s.mu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("share: list: %w", err)
	}

	removed := 0
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".meta") {
			continue
		}
		id := strings.TrimSuffix(name, ".meta")
		if !validID(id) {
			continue
		}
		// Re-take the lock per-share. Keeping a walk-long lock
		// would block the hot path; short locks keep the sweeper
		// polite.
		s.mu.Lock()
		m, err := s.loadLocked(id)
		if err != nil {
			s.mu.Unlock()
			continue
		}
		if m.Expired(now) {
			_ = s.deleteLocked(id)
			removed++
		}
		s.mu.Unlock()
	}
	return removed, nil
}

// ConstantTimeEqualID is subtle-equal on two share IDs — used only
// in tests; production lookup goes through validID + filesystem so
// timing is already dominated by disk I/O.
func ConstantTimeEqualID(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
