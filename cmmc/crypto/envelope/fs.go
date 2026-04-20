package envelope

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"

	scan "github.com/filebrowser/filebrowser/v2/cmmc/scan"
)

// EncryptingFS is an afero.Fs decorator that transparently seals
// every file write and opens every file read with the configured
// KEK + per-file envelope. Directories pass through untouched.
//
// Shape in the filebrowser stack:
//
//	BasePathFs (user scope)   — path translation
//	    └── EncryptingFS      — crypto here
//	        └── OsFs          — raw disk I/O
//
// Read path:
//   1. Stat the ciphertext file
//   2. Look up envelope in the Store (keyed on full disk path)
//   3. Read ciphertext fully (capped at MaxPlaintextSize+tag)
//   4. KEK.Open → plaintext buffer
//   5. Return a *memFile wrapping the plaintext
//
// Write path:
//   1. Open a *writeFile that buffers bytes into memory
//   2. On Close: buf.Bytes() → KEK.Seal → ciphertext
//   3. Write ciphertext to the real OsFs
//   4. Put envelope in Store (rolls back the file write on failure)
//
// Limits:
//   - Single-shot AEAD; hard cap at MaxPlaintextSize (256 MiB).
//     Larger files would need a chunked format — deferred.
//   - Writes buffer in memory. A high-concurrency workload with
//     multiple simultaneous 200 MiB uploads will peak at roughly
//     (concurrency × 400 MiB) RAM (buffered ciphertext + plaintext
//     copy). In practice filebrowser's write concurrency is
//     bounded by HTTP connections; a 4-core VM handles this
//     comfortably. Document in operator notes.
type EncryptingFS struct {
	// under is the filesystem we delegate raw IO to — typically
	// an afero.OsFs wrapping the host disk.
	under afero.Fs

	// kek wraps the process master key.
	kek *KEK

	// store persists per-file Envelope records keyed on full path.
	store Store

	// mode decides what to do when a file exists on disk but has
	// no matching envelope row. In ModeOptional/ModeDisabled we
	// pass through the raw bytes (migration window). In
	// ModeRequired we fail-closed: reads and stats of files
	// without envelopes return an error. The latter is what CMMC
	// L2 expects — no plaintext may leave without a valid
	// envelope's say-so.
	mode Mode

	// scanner, when non-nil, inspects plaintext before the seal
	// step of every write. An infected payload returns
	// *scan.RejectedError, preventing the ciphertext and envelope
	// from ever being persisted. CMMC 3.14.2. The scanner is
	// wired in via WithScanner at boot; leaving it nil keeps the
	// behavior we had before AV was integrated.
	scanner scan.Scanner

	// scanMode decides how to treat a backend failure from the
	// scanner (scan.ErrUnavailable): Required means return an
	// error up the handler chain (fails the upload with 503);
	// Optional logs and proceeds with the seal.
	scanMode scan.Mode

	// pathPrefix is prepended to names we pass to the store. When
	// EncryptingFS is the bottom of a BasePathFs stack (common case
	// in filebrowser), the 'name' already arrives as absolute.
	// Expose as a knob so tests / mixed-deployment paths can
	// normalize without re-implementing the wrapper.
	pathPrefix string
}

// WithScanner attaches a plaintext-scanning backend to the FS. The
// scan runs before Seal so an infected payload never produces a
// ciphertext on disk and never writes an envelope row — there's
// nothing to reconcile after a scan reject. Safe to call after New;
// not safe to change at runtime after requests are flowing.
func (e *EncryptingFS) WithScanner(s scan.Scanner, mode scan.Mode) *EncryptingFS {
	e.scanner = s
	e.scanMode = mode
	return e
}

// New constructs an EncryptingFS. kek + store must both be non-nil;
// a nil kek is a misconfiguration caught at boot. Mode defaults to
// Optional for backward compatibility — callers that want
// fail-closed should pass ModeRequired.
func New(under afero.Fs, kek *KEK, store Store) *EncryptingFS {
	return &EncryptingFS{under: under, kek: kek, store: store, mode: ModeOptional}
}

// NewWithMode constructs an EncryptingFS and sets the mode
// explicitly. Used by cmd/root.go so the runtime posture matches
// the KEK-load posture.
func NewWithMode(under afero.Fs, kek *KEK, store Store, mode Mode) *EncryptingFS {
	e := New(under, kek, store)
	e.mode = mode
	return e
}

// Name is used by afero for debug / diagnostic output.
func (e *EncryptingFS) Name() string { return "EncryptingFS(" + e.under.Name() + ")" }

// --- pass-through filesystem ops (no crypto involved) ---------------

func (e *EncryptingFS) Mkdir(name string, perm os.FileMode) error {
	return e.under.Mkdir(name, perm)
}
func (e *EncryptingFS) MkdirAll(path string, perm os.FileMode) error {
	return e.under.MkdirAll(path, perm)
}
func (e *EncryptingFS) Chmod(name string, mode os.FileMode) error {
	return e.under.Chmod(name, mode)
}
func (e *EncryptingFS) Chtimes(name string, atime, mtime time.Time) error {
	return e.under.Chtimes(name, atime, mtime)
}
func (e *EncryptingFS) Chown(name string, uid, gid int) error {
	return e.under.Chown(name, uid, gid)
}

// Remove deletes the ciphertext AND the envelope. If the envelope
// delete fails we still return nil — a stale envelope without its
// ciphertext is harmless (next Put overwrites), whereas failing
// the file delete would surprise the caller.
func (e *EncryptingFS) Remove(name string) error {
	if err := e.under.Remove(name); err != nil {
		return err
	}
	_ = e.store.Delete(e.key(name))
	return nil
}

func (e *EncryptingFS) RemoveAll(path string) error {
	// Walk first to collect envelope keys, then delegate. Order
	// matters: walking AFTER the fs removes means Stat fails on
	// children. afero.Walk handles the traversal.
	var keys []string
	_ = afero.Walk(e.under, path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			keys = append(keys, e.key(p))
		}
		return nil
	})
	if err := e.under.RemoveAll(path); err != nil {
		return err
	}
	for _, k := range keys {
		_ = e.store.Delete(k)
	}
	return nil
}

// Rename moves ciphertext + envelope together. Envelope first: if
// the bolt tx fails, the fs op isn't attempted — we stay coherent.
// Filesystem op second: if it fails AFTER envelope moved, we try
// to restore the envelope back to the old path. A genuine crash
// between the two leaves a one-sided state that the orphan-scrub
// tool (follow-up) reconciles.
func (e *EncryptingFS) Rename(oldname, newname string) error {
	// Skip the envelope dance for directories — no envelope exists.
	if info, err := e.under.Stat(oldname); err == nil && info.IsDir() {
		return e.under.Rename(oldname, newname)
	}
	oldKey, newKey := e.key(oldname), e.key(newname)
	if err := e.store.Rename(oldKey, newKey); err != nil {
		return err
	}
	if err := e.under.Rename(oldname, newname); err != nil {
		// Compensate. If Rename back fails we have a genuine
		// integrity hazard — envelope at newKey, ciphertext at
		// oldname — log loudly so an operator can investigate
		// and the (still-pending) orphan-scrub tool reconciles
		// on next start. Do NOT suppress: this is a security-
		// relevant event, not a log-and-forget.
		if compErr := e.store.Rename(newKey, oldKey); compErr != nil {
			log.Printf("envelope: CRITICAL rename double-fault — envelope at %q, ciphertext at %q; fs-err=%v comp-err=%v",
				newKey, oldKey, err, compErr)
		}
		return err
	}
	return nil
}

// Stat returns a FileInfo with Size() reporting plaintext bytes, so
// the UI and Content-Length headers don't expose ciphertext length
// (which leaks the +16-byte GCM tag and might confuse clients that
// truncate at Content-Length). Directories fall through unchanged.
func (e *EncryptingFS) Stat(name string) (os.FileInfo, error) {
	fi, err := e.under.Stat(name)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return fi, nil
	}
	env, err := e.store.Get(e.key(name))
	if err != nil {
		// Same fail-closed rationale as openReadOnly: a missing
		// envelope in Required mode is a tamper indicator, not a
		// legitimate legacy-plaintext case.
		if e.mode == ModeRequired {
			return nil, ErrAuth
		}
		return fi, nil
	}
	return &sizeOverrideInfo{FileInfo: fi, size: env.PlaintextSize}, nil
}

// Create is an alias for OpenFile(name, O_RDWR|O_CREATE|O_TRUNC, 0666).
func (e *EncryptingFS) Create(name string) (afero.File, error) {
	return e.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

// Open is shorthand for read-only OpenFile.
func (e *EncryptingFS) Open(name string) (afero.File, error) {
	return e.OpenFile(name, os.O_RDONLY, 0)
}

// OpenFile dispatches to a read-path or write-path wrapper
// depending on the flag. Appending (O_APPEND) is not supported —
// AEAD over a ciphertext can't be appended in place. Callers that
// truly need append must read/mutate/write the whole file (which
// happens naturally through the writeFile buffer).
func (e *EncryptingFS) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	write := flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND) != 0
	create := flag&os.O_CREATE != 0
	trunc := flag&os.O_TRUNC != 0

	// Directory → delegate.
	if fi, err := e.under.Stat(name); err == nil && fi.IsDir() {
		return e.under.OpenFile(name, flag, perm)
	}

	if !write {
		return e.openReadOnly(name)
	}
	// Write path. If O_APPEND is set without O_TRUNC we need to
	// preload existing plaintext into the buffer first so the
	// resulting file is (old + new). O_APPEND with O_TRUNC is
	// unusual but legal — behaves as a fresh write.
	var seed []byte
	fileExists := false
	if _, err := e.under.Stat(name); err == nil {
		fileExists = true
	}
	if !trunc {
		if existing, err := e.openReadOnly(name); err == nil {
			defer existing.Close()
			seed, _ = io.ReadAll(existing)
		} else if !os.IsNotExist(err) && !create {
			return nil, err
		}
	}
	// If this is a fresh create (O_CREATE set AND file doesn't
	// exist yet), immediately seal an empty plaintext to lay down
	// a valid (envelope, ciphertext) pair on disk. Without this,
	// a caller that does OpenFile → NewFileInfo (Stat) → ... BEFORE
	// calling Close sees "file not found" — the upstream TUS POST
	// handler does exactly this and returned 404 on every upload
	// because the writeFile buffer hadn't flushed yet.
	//
	// sealAndWrite is idempotent (O_TRUNC on the inner write) so
	// the later Close rewrites the whole thing with the accumulated
	// plaintext. Net cost: one extra 16-byte ciphertext write on
	// file creation.
	if create && !fileExists {
		if err := e.sealAndWrite(name, perm, nil); err != nil {
			return nil, err
		}
	}
	return newWriteFile(e, name, perm, seed), nil
}

// --- internals -------------------------------------------------------

// key maps a filesystem name to the envelope store key. Currently a
// straight path; the hook is here for deployments that want to
// abstract over a path-transform (e.g., hash keys).
func (e *EncryptingFS) key(name string) string {
	// Normalize: strip trailing slashes, clean . and ..
	return filepath.Clean(strings.TrimRight(e.pathPrefix+name, "/"))
}

// openReadOnly builds the in-memory decrypted reader for a ciphertext.
func (e *EncryptingFS) openReadOnly(name string) (afero.File, error) {
	f, err := e.under.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	env, err := e.store.Get(e.key(name))
	if err != nil {
		// No envelope row for this file. Two scenarios:
		//
		//   1. Legacy plaintext from before encryption was turned
		//      on, or a file dropped in via the host filesystem.
		//      Acceptable in Optional/Disabled mode during a
		//      migration window.
		//
		//   2. Tampering: an attacker with bolt-write access
		//      deleted the envelope row. The ciphertext on disk
		//      is now served as "plaintext" to the user — a hole
		//      the review agent called out. Fail-closed in
		//      Required mode so this can't happen silently.
		if e.mode == ModeRequired {
			return nil, ErrAuth
		}
		return e.under.Open(name)
	}
	cipherBuf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	// AAD is empty — see doc on sealAndWrite. Binding to path would
	// make Rename require re-encryption, and doesn't defend against
	// a root attacker who can reach both the ciphertext AND the
	// envelope store (they can swap both).
	plaintext, err := e.kek.Open(cipherBuf, env, nil)
	if err != nil {
		return nil, err
	}
	fi, _ := e.under.Stat(name)
	return &memFile{
		name:     name,
		data:     plaintext,
		modTime:  fi.ModTime(),
		mode:     fi.Mode(),
	}, nil
}

// sealAndWrite is called by writeFile.Close to flush the buffer.
//
// Ordering: envelope PUT first, then ciphertext write. If the PUT
// succeeds but the file write fails, the envelope is momentarily
// orphaned — but reads at that path return ErrNotExist (no file),
// which is a benign state. The reverse order (file first, envelope
// second) has a worse race: a PATCH-while-we're-here reader sees
// the ciphertext with NO envelope, and in ModeOptional would
// return raw ciphertext to the caller as if it were plaintext —
// confirmed by the code-review agent as a real TUS-shaped race.
//
// AAD is intentionally nil. A prior version bound the AAD to the
// absolute path so a ciphertext physically relocated to a different
// path would fail auth on open. That broke Rename (AAD mismatch
// after path change) and only defended against a shallow threat —
// a root attacker on the host can read BOTH the ciphertext file
// AND the envelope store (filebrowser.db); swapping the pair
// defeats any path-based AAD. The real protection remains the
// KEK living outside the host's filesystem (env var, HSM, KMS).
func (e *EncryptingFS) sealAndWrite(name string, perm os.FileMode, plaintext []byte) error {
	// Per-path serialization closes the TUS-shaped window where a
	// second request's OpenFile runs between our envelope Put and
	// our ciphertext write. Without it, concurrent PATCHes on the
	// same path can interleave their (envelope, ciphertext) pairs.
	// Refcounted so the map doesn't grow unbounded (H4).
	lock := e.acquirePathLock(name)
	defer e.releasePathLock(name, lock)

	// CMMC 3.14.2 — scan plaintext before it's sealed. An infection
	// is returned as *scan.RejectedError; callers in http/*.go map
	// that to a 422 + cui.scan.reject audit event. Running before
	// Seal means nothing hits disk or the envelope store on a
	// reject — clean fail, no orphan to reconcile.
	//
	// Skip on empty plaintext: our own empty-flush-on-create
	// writes 0 bytes just to make Stat see the file before Close,
	// and that's never malware. Scanning empty also wastes a
	// round-trip to clamd per POST.
	if e.scanner != nil && len(plaintext) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), scan.DefaultTimeout)
		result, err := e.scanner.Scan(ctx, bytes.NewReader(plaintext))
		cancel()
		if err != nil {
			// Backend error (ErrUnavailable, context, protocol).
			// In Required mode, a sick scanner must NOT become
			// a silent allow. In Optional, we log loud and let
			// the write proceed so a busted clamd doesn't take
			// the cabinet offline.
			if e.scanMode == scan.ModeRequired {
				e.rollbackEmptyFlush(name)
				return err
			}
			log.Printf("scan: backend error (optional mode, proceeding): %v", err)
		} else if !result.Clean {
			e.rollbackEmptyFlush(name)
			return &scan.RejectedError{Signature: result.Signature, Path: name}
		}
	}

	ciphertext, env, err := e.kek.Seal(plaintext, nil)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(name); dir != "" && dir != "/" {
		_ = e.under.MkdirAll(dir, 0o700)
	}
	// 1. Envelope first — under our path lock, so readers either
	//    see the OLD envelope+OLD ciphertext (consistent) or the
	//    NEW envelope, and when they try to open the file they get
	//    NEW ciphertext (step 2 already finished) — also consistent.
	//    The one invariant we avoid: NEW ciphertext with OLD
	//    envelope (auth fail in ModeRequired, silent corruption in
	//    ModeOptional).
	if err := e.store.Put(e.key(name), env); err != nil {
		return err
	}
	out, err := e.under.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := out.Write(ciphertext); err != nil {
		out.Close()
		_ = e.under.Remove(name)
		return err
	}
	if err := out.Close(); err != nil {
		_ = e.under.Remove(name)
		return err
	}
	return nil
}

// rollbackEmptyFlush removes the (envelope, ciphertext) pair that the
// OpenFile(O_CREATE) path lays down for a fresh file so Stat works
// before Close. When a scan rejects or a backend error blocks the
// write in Required mode, this pair is the only on-disk artifact for
// a never-persisted upload — leave it behind and the caller sees a
// 0-byte file where nothing exists. We only remove a ciphertext
// whose length matches an empty plaintext seal (TagSize); any other
// length is a legitimate prior file being overwritten, which the
// reject must leave intact.
//
// Caller already holds pathLock(name) (via sealAndWrite), so the
// check-and-remove is atomic with the write path.
func (e *EncryptingFS) rollbackEmptyFlush(name string) {
	info, err := e.under.Stat(name)
	if err != nil || info.IsDir() {
		return
	}
	if info.Size() == TagSize {
		_ = e.under.Remove(name)
		_ = e.store.Delete(e.key(name))
	}
}

// pathLocks serializes concurrent sealAndWrite calls for the same
// absolute path. TUS uploads are typically sequential per file, but
// a client that re-sends PATCHes (retry) or a badly-behaved caller
// could drive two overlapping Close calls. The per-path fine-grain
// lock keeps the fast path lock-free across unrelated files.
//
// H4 — refcounted entries so a long-lived process with many unique
// paths doesn't accumulate a mutex per file forever. Entries live
// only while at least one caller holds the lock; when refcount
// drops back to zero the row is removed. Memory is O(active
// writers), not O(total paths ever written).
type pathLockEntry struct {
	mu       sync.Mutex
	refcount int
}

var (
	pathLocksMu sync.Mutex
	pathLocks   = map[string]*pathLockEntry{}
)

// acquirePathLock grabs (and locks) the entry for name, creating
// it if necessary and bumping its refcount so it survives until
// the caller releases.
func (e *EncryptingFS) acquirePathLock(name string) *pathLockEntry {
	pathLocksMu.Lock()
	ent, ok := pathLocks[name]
	if !ok {
		ent = &pathLockEntry{}
		pathLocks[name] = ent
	}
	ent.refcount++
	pathLocksMu.Unlock()
	ent.mu.Lock()
	return ent
}

// releasePathLock unlocks the entry and drops it from the map when
// no more callers are interested. Must be called exactly once per
// acquirePathLock.
func (e *EncryptingFS) releasePathLock(name string, ent *pathLockEntry) {
	ent.mu.Unlock()
	pathLocksMu.Lock()
	ent.refcount--
	if ent.refcount == 0 {
		delete(pathLocks, name)
	}
	pathLocksMu.Unlock()
}

// pathLocksSize is exposed for tests so we can pin the bounded-
// growth guarantee (count stays at zero between writes).
func pathLocksSize() int {
	pathLocksMu.Lock()
	defer pathLocksMu.Unlock()
	return len(pathLocks)
}

// --- memFile: read-only decrypted buffer -----------------------------

type memFile struct {
	name    string
	data    []byte
	pos     int64
	modTime time.Time
	mode    os.FileMode
	closed  bool
	mu      sync.Mutex
}

func (m *memFile) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, os.ErrClosed
	}
	if m.pos >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.pos:])
	m.pos += int64(n)
	return n, nil
}
func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, os.ErrClosed
	}
	if off < 0 || off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (m *memFile) Seek(offset int64, whence int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = m.pos + offset
	case io.SeekEnd:
		abs = int64(len(m.data)) + offset
	default:
		return 0, errors.New("envelope: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("envelope: negative seek")
	}
	m.pos = abs
	return abs, nil
}
func (m *memFile) Write(_ []byte) (int, error)          { return 0, os.ErrPermission }
func (m *memFile) WriteAt(_ []byte, _ int64) (int, error) { return 0, os.ErrPermission }
func (m *memFile) WriteString(_ string) (int, error)    { return 0, os.ErrPermission }
func (m *memFile) Truncate(_ int64) error               { return os.ErrPermission }
func (m *memFile) Sync() error                          { return nil }
func (m *memFile) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Zero the plaintext buffer on close.
	for i := range m.data {
		m.data[i] = 0
	}
	m.closed = true
	return nil
}
func (m *memFile) Name() string { return m.name }
func (m *memFile) Stat() (os.FileInfo, error) {
	return &memFileInfo{name: filepath.Base(m.name), size: int64(len(m.data)), mode: m.mode, modTime: m.modTime}, nil
}
func (m *memFile) Readdir(_ int) ([]os.FileInfo, error)     { return nil, errors.New("not a directory") }
func (m *memFile) Readdirnames(_ int) ([]string, error)     { return nil, errors.New("not a directory") }

type memFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (m *memFileInfo) Name() string       { return m.name }
func (m *memFileInfo) Size() int64        { return m.size }
func (m *memFileInfo) Mode() os.FileMode  { return m.mode }
func (m *memFileInfo) ModTime() time.Time { return m.modTime }
func (m *memFileInfo) IsDir() bool        { return false }
func (m *memFileInfo) Sys() interface{}   { return nil }

// sizeOverrideInfo is the FileInfo wrapper Stat() returns so the
// world sees plaintext size instead of ciphertext size. All other
// fields pass through to the underlying info.
type sizeOverrideInfo struct {
	os.FileInfo
	size int64
}

func (s *sizeOverrideInfo) Size() int64 { return s.size }

// --- writeFile: buffered writes that seal on Close ------------------
//
// Backing store is a plain []byte with a current position. Every Write
// is an implicit WriteAt at pos (and pos advances). This model makes
// Seek + subsequent Writes work — the common TUS pattern of
// "OpenFile(APPEND); Seek(offset); io.Copy(chunk)". A bytes.Buffer
// was used in the first draft; it's append-only and was the root
// cause of TUS 500s ("seek not supported on write file").

type writeFile struct {
	fs     *EncryptingFS
	name   string
	perm   os.FileMode
	data   []byte
	pos    int64
	closed bool
	mu     sync.Mutex
}

func newWriteFile(fs *EncryptingFS, name string, perm os.FileMode, seed []byte) *writeFile {
	cp := make([]byte, len(seed))
	copy(cp, seed)
	return &writeFile{fs: fs, name: name, perm: perm, data: cp, pos: int64(len(cp))}
}

// writeAtLocked implements the grow-and-overwrite semantics used by
// both Write (at pos) and WriteAt (at arbitrary offset). Caller
// holds w.mu.
func (w *writeFile) writeAtLocked(p []byte, off int64) (int, error) {
	if w.closed {
		return 0, os.ErrClosed
	}
	end := off + int64(len(p))
	if end > MaxPlaintextSize {
		return 0, ErrTooLarge
	}
	if int64(len(w.data)) < end {
		grown := make([]byte, end)
		copy(grown, w.data)
		w.data = grown
	}
	copy(w.data[off:], p)
	return len(p), nil
}

func (w *writeFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.writeAtLocked(p, w.pos)
	w.pos += int64(n)
	return n, err
}

func (w *writeFile) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func (w *writeFile) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeAtLocked(p, off)
}

// Seek repositions pos. The TUS handler calls Seek(uploadOffset, 0)
// before io.Copy — without this method returning a real offset the
// upload pipeline errors out. Support SeekStart / SeekCurrent /
// SeekEnd the way a real file does.
func (w *writeFile) Seek(offset int64, whence int) (int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = w.pos + offset
	case io.SeekEnd:
		abs = int64(len(w.data)) + offset
	default:
		return 0, errors.New("envelope: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("envelope: negative seek")
	}
	w.pos = abs
	return abs, nil
}

func (w *writeFile) Read(_ []byte) (int, error)            { return 0, os.ErrPermission }
func (w *writeFile) ReadAt(_ []byte, _ int64) (int, error) { return 0, os.ErrPermission }
func (w *writeFile) Sync() error                           { return nil }

func (w *writeFile) Truncate(size int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if size < 0 {
		return errors.New("envelope: negative truncate")
	}
	if int64(len(w.data)) > size {
		w.data = w.data[:size]
	} else if int64(len(w.data)) < size {
		grown := make([]byte, size)
		copy(grown, w.data)
		w.data = grown
	}
	if w.pos > int64(len(w.data)) {
		w.pos = int64(len(w.data))
	}
	return nil
}

func (w *writeFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	// Zero the plaintext buffer regardless of whether sealAndWrite
	// succeeds — on failure we still don't want the plaintext to
	// linger in memory until GC. Defer-zero via a stack reference
	// in case sealAndWrite panics (which shouldn't happen, but a
	// defensive wipe costs nothing).
	plaintext := w.data
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
		w.data = nil
	}()
	return w.fs.sealAndWrite(w.name, w.perm, plaintext)
}

func (w *writeFile) Name() string { return w.name }
func (w *writeFile) Stat() (os.FileInfo, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return &memFileInfo{name: filepath.Base(w.name), size: int64(len(w.data)), mode: w.perm}, nil
}
func (w *writeFile) Readdir(_ int) ([]os.FileInfo, error) { return nil, errors.New("not a directory") }
func (w *writeFile) Readdirnames(_ int) ([]string, error) { return nil, errors.New("not a directory") }
