package envelope

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/spf13/afero"

	scan "github.com/filebrowser/filebrowser/v2/cmmc/scan"
)

// fakeStore is a minimal in-memory envelope.Store for fs tests.
type fakeStore struct {
	mu   sync.Mutex
	rows map[string]*Envelope
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]*Envelope{}} }
func (f *fakeStore) Get(p string) (*Envelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.rows[p]; ok {
		return v, nil
	}
	return nil, errNotExistStub
}
func (f *fakeStore) Put(p string, e *Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows[p] = e
	return nil
}
func (f *fakeStore) Delete(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, p)
	return nil
}
func (f *fakeStore) Rename(o, n string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.rows[o]; ok {
		f.rows[n] = v
		delete(f.rows, o)
	}
	return nil
}

type errNotExistStubT struct{}

func (errNotExistStubT) Error() string { return "not found" }

var errNotExistStub = errNotExistStubT{}

func newTestFS(t *testing.T) (*EncryptingFS, *fakeStore) {
	t.Helper()
	return New(afero.NewMemMapFs(), mustKEK(t), newFakeStore()), nil
}

// TestEncryptingFS_WriteThenRead_CiphertextOnDisk_PlaintextOnOpen —
// the core contract. Writing a file produces ciphertext on the
// underlying Fs and plaintext through the wrapper. If this breaks,
// either encryption is skipped (CUI leak) or decryption is skipped
// (unreadable files).
func TestEncryptingFS_WriteThenRead_CiphertextOnDisk_PlaintextOnOpen(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()
	fs := New(under, mustKEK(t), store)

	plaintext := []byte("CUI drawing revision C — part 904-A12 — do not distribute")

	// Write via EncryptingFS.
	w, err := fs.Create("/secret.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Envelope stored for the absolute path.
	if _, err := store.Get("/secret.bin"); err != nil {
		t.Fatalf("envelope not persisted: %v", err)
	}
	// Raw bytes on disk are ciphertext, not plaintext.
	raw, err := afero.ReadFile(under, "/secret.bin")
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if bytes.Contains(raw, plaintext) {
		t.Errorf("raw bytes contain plaintext — encryption skipped!")
	}
	if int64(len(raw)) != int64(len(plaintext))+TagSize {
		t.Errorf("ciphertext size = %d, want %d (plaintext+tag)", len(raw), len(plaintext)+TagSize)
	}

	// Read via EncryptingFS returns plaintext.
	r, err := fs.Open("/secret.bin")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch:\n got %q\nwant %q", got, plaintext)
	}
}

// TestEncryptingFS_StatReturnsPlaintextSize — the UI must see the
// logical size, not the ciphertext + 16-byte tag.
func TestEncryptingFS_StatReturnsPlaintextSize(t *testing.T) {
	under := afero.NewMemMapFs()
	fs := New(under, mustKEK(t), newFakeStore())
	w, _ := fs.Create("/x.bin")
	_, _ = w.Write([]byte("hello"))
	_ = w.Close()

	info, err := fs.Stat("/x.bin")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 5 {
		t.Errorf("Stat.Size()=%d via wrapper, want 5 (plaintext)", info.Size())
	}
	// And the underlying Fs sees 5+16=21.
	rawInfo, _ := under.Stat("/x.bin")
	if rawInfo.Size() != 5+int64(TagSize) {
		t.Errorf("underlying Size=%d, want %d", rawInfo.Size(), 5+TagSize)
	}
}

// TestEncryptingFS_RemoveClearsEnvelope — orphan envelopes lead to
// next-upload pseudo-collision (path reuse but stale envelope).
// Delete must reap both.
func TestEncryptingFS_RemoveClearsEnvelope(t *testing.T) {
	store := newFakeStore()
	fs := New(afero.NewMemMapFs(), mustKEK(t), store)
	w, _ := fs.Create("/a.bin")
	_, _ = w.Write([]byte("data"))
	_ = w.Close()

	if err := fs.Remove("/a.bin"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := store.Get("/a.bin"); err == nil {
		t.Errorf("envelope not cleaned on Remove")
	}
}

// TestEncryptingFS_Rename_MovesEnvelope — the envelope must follow
// the ciphertext, otherwise subsequent reads produce auth failures.
func TestEncryptingFS_Rename_MovesEnvelope(t *testing.T) {
	store := newFakeStore()
	fs := New(afero.NewMemMapFs(), mustKEK(t), store)
	w, _ := fs.Create("/before.bin")
	_, _ = w.Write([]byte("hello"))
	_ = w.Close()

	if err := fs.Rename("/before.bin", "/after.bin"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := store.Get("/after.bin"); err != nil {
		t.Errorf("envelope not at new path after rename")
	}
	if _, err := store.Get("/before.bin"); err == nil {
		t.Errorf("envelope still at old path after rename")
	}
	// Read-after-rename round-trip.
	r, err := fs.Open("/after.bin")
	if err != nil {
		t.Fatalf("Open after rename: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if string(got) != "hello" {
		t.Errorf("after rename read = %q", got)
	}
}

// TestEncryptingFS_OpensLegacyPlaintextWhenNoEnvelope — during a
// migration window a file may exist on disk without an envelope.
// The wrapper must not ErrAuth on those; it must read them through.
func TestEncryptingFS_OpensLegacyPlaintextWhenNoEnvelope(t *testing.T) {
	under := afero.NewMemMapFs()
	fs := New(under, mustKEK(t), newFakeStore())
	// Write directly to underlying — no envelope.
	_ = afero.WriteFile(under, "/legacy.txt", []byte("pre-encryption content"), 0o600)

	r, err := fs.Open("/legacy.txt")
	if err != nil {
		t.Fatalf("Open legacy: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if string(got) != "pre-encryption content" {
		t.Errorf("legacy read got %q", got)
	}
}

// TestEncryptingFS_DirectoryOpsPassThrough — no surprise crypto on
// directories. Mkdir, Stat on dir, etc.
func TestEncryptingFS_DirectoryOpsPassThrough(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())
	if err := fs.MkdirAll("/a/b/c", 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	info, err := fs.Stat("/a/b")
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected dir; got %v", info.Mode())
	}
}

// TestEncryptingFS_Writer_AbortsBeyondCap — oversize writes fail
// before hitting disk, so the caller sees the error without a
// partial ciphertext artifact.
func TestEncryptingFS_Writer_AbortsBeyondCap(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())
	w, err := fs.Create("/big.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Write up to cap in one shot, then one more byte → ErrTooLarge
	// returned by Write (wrapped). Exact behavior documented.
	// Easier test: write MaxPlaintextSize+1 in one shot.
	n, err := w.Write(make([]byte, MaxPlaintextSize+1))
	if err == nil || n != 0 {
		t.Errorf("expected ErrTooLarge, got n=%d err=%v", n, err)
	}
	_ = w.Close()
}

// TestEncryptingFS_ModeRequired_FailsClosedOnMissingEnvelope pins
// the fail-closed contract. An attacker with bolt-write could
// delete envelope rows and trick the wrapper into serving
// ciphertext as plaintext; in Required mode that must fail.
func TestEncryptingFS_ModeRequired_FailsClosedOnMissingEnvelope(t *testing.T) {
	under := afero.NewMemMapFs()
	fs := NewWithMode(under, mustKEK(t), newFakeStore(), ModeRequired)
	// Write raw ciphertext-looking bytes directly, no envelope row.
	_ = afero.WriteFile(under, "/tampered.bin", []byte("raw bytes no envelope"), 0o600)

	if _, err := fs.Open("/tampered.bin"); err == nil {
		t.Errorf("Open succeeded on missing envelope in Required mode")
	}
	if _, err := fs.Stat("/tampered.bin"); err == nil {
		t.Errorf("Stat succeeded on missing envelope in Required mode")
	}
}

// TestEncryptingFS_ModeOptional_FallsThroughOnMissingEnvelope pins
// the migration-window behavior: Optional mode still reads legacy
// plaintext so existing files aren't stranded during rollout.
func TestEncryptingFS_ModeOptional_FallsThroughOnMissingEnvelope(t *testing.T) {
	under := afero.NewMemMapFs()
	fs := NewWithMode(under, mustKEK(t), newFakeStore(), ModeOptional)
	_ = afero.WriteFile(under, "/legacy.txt", []byte("legacy content"), 0o600)

	r, err := fs.Open("/legacy.txt")
	if err != nil {
		t.Fatalf("Optional mode should pass through; got %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if string(got) != "legacy content" {
		t.Errorf("Optional legacy read got %q", got)
	}
}

// TestEncryptingFS_EmptyFileRoundTrip pins the touch-style case.
// A 0-byte Create+Close produces a 16-byte GCM tag as ciphertext
// and a PlaintextSize=0 envelope; Open must round-trip to 0 bytes.
func TestEncryptingFS_EmptyFileRoundTrip(t *testing.T) {
	store := newFakeStore()
	fs := New(afero.NewMemMapFs(), mustKEK(t), store)
	w, err := fs.Create("/empty.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	env, err := store.Get("/empty.bin")
	if err != nil {
		t.Fatalf("envelope not persisted for empty file: %v", err)
	}
	if env.PlaintextSize != 0 {
		t.Errorf("PlaintextSize = %d, want 0", env.PlaintextSize)
	}
	r, err := fs.Open("/empty.bin")
	if err != nil {
		t.Fatalf("Open empty: %v", err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty-file round-trip got %d bytes, want 0", len(got))
	}
}

// TestEncryptingFS_TUSPattern_AppendSeekWrite pins the chunked-
// upload pattern: POST creates an empty file, then N PATCHes each
// OpenFile(O_WRONLY|O_APPEND) + Seek(existingLen, 0) + Write(chunk)
// + Close. A regression here (writeFile missing Seek, or seed lost
// across PATCHes) 500s every upload over a few MB.
func TestEncryptingFS_TUSPattern_AppendSeekWrite(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())

	// 1. POST-like create: empty file.
	w, err := fs.OpenFile("/up.bin", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("POST create: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("POST close: %v", err)
	}

	// 2. Three chunks appended, TUS PATCH-style.
	chunks := [][]byte{
		[]byte("AAAAAAAAAAAA"),
		[]byte("BBBBBBBB"),
		[]byte("CCCC"),
	}
	var offset int64
	for i, c := range chunks {
		pf, err := fs.OpenFile("/up.bin", os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("PATCH %d open: %v", i, err)
		}
		// TUS seeks to the existing length before writing.
		if _, err := pf.Seek(offset, io.SeekStart); err != nil {
			t.Fatalf("PATCH %d seek: %v", i, err)
		}
		n, err := pf.Write(c)
		if err != nil || n != len(c) {
			t.Fatalf("PATCH %d write: n=%d err=%v", i, n, err)
		}
		if err := pf.Close(); err != nil {
			t.Fatalf("PATCH %d close: %v", i, err)
		}
		offset += int64(len(c))

		// After each PATCH, Stat must report the accumulated size so
		// the next HEAD / Stat returns the right Upload-Offset.
		info, err := fs.Stat("/up.bin")
		if err != nil {
			t.Fatalf("Stat after PATCH %d: %v", i, err)
		}
		if info.Size() != offset {
			t.Errorf("after chunk %d: Stat size=%d, want %d", i, info.Size(), offset)
		}
	}

	// 3. Final read returns the concatenated plaintext.
	r, err := fs.Open("/up.bin")
	if err != nil {
		t.Fatalf("final Open: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	want := "AAAAAAAAAAAABBBBBBBBCCCC"
	if string(got) != want {
		t.Errorf("final content = %q, want %q", got, want)
	}
}

// --- Failure-mode tests (flagged by review + test agents) -----------

// failingStore lets a test force Put/Get/Delete to fail so we can
// exercise the error paths that real bolt would hit under load.
// `failAfter` counts successful Puts before starting to fail — set
// to 0 for "fail first Put", 1 for "succeed once then fail", etc.
// EncryptingFS now does an immediate seal-on-Create (to make Stat
// see newly-opened write files, fixing a TUS POST 404), so tests
// that want to fail the Close's Put need failAfter ≥ 1.
type failingStore struct {
	inner     *fakeStore
	failAfter int
	puts      int
}

func (f *failingStore) Get(p string) (*Envelope, error) { return f.inner.Get(p) }
func (f *failingStore) Put(p string, e *Envelope) error {
	f.puts++
	if f.puts > f.failAfter {
		return errors.New("injected Put failure")
	}
	return f.inner.Put(p, e)
}
func (f *failingStore) Delete(p string) error    { return f.inner.Delete(p) }
func (f *failingStore) Rename(a, b string) error { return f.inner.Rename(a, b) }

// TestEncryptingFS_SealAndWrite_EnvelopeFirst pins the ordering
// fix. If envelope Put fails, we must NOT have written ciphertext
// to disk (otherwise a reader sees orphan ciphertext + no envelope).
// failAfter=1 → the immediate-flush at Create succeeds, the Close's
// Put is the one that fails. The critical invariant is that after
// the failed Close the on-disk file must match the state established
// by the initial flush (empty), not an orphan partially-written mess.
func TestEncryptingFS_SealAndWrite_EnvelopeFirst(t *testing.T) {
	under := afero.NewMemMapFs()
	store := &failingStore{inner: newFakeStore(), failAfter: 1}
	fs := New(under, mustKEK(t), store)

	w, err := fs.Create("/x.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, _ = w.Write([]byte("payload"))
	err = w.Close()
	if err == nil {
		t.Fatal("Close should have failed with injected Put error")
	}
	// The empty-flush established a valid (envelope, ciphertext)
	// pair for an empty file. The failing Close must leave that
	// pair intact — NOT upgrade to a ciphertext with no matching
	// envelope, which would be silently-corrupting in Optional mode.
	env, err := store.Get("/x.bin")
	if err != nil {
		t.Fatalf("empty-flush envelope disappeared: %v", err)
	}
	if env.PlaintextSize != 0 {
		t.Errorf("envelope PlaintextSize = %d, want 0 (Close failed, empty flush retained)", env.PlaintextSize)
	}
	// The on-disk ciphertext should still decrypt cleanly against
	// the surviving envelope — confirming we didn't half-write.
	r, err := fs.Open("/x.bin")
	if err != nil {
		t.Fatalf("Open after failed Close: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if len(got) != 0 {
		t.Errorf("after failed Close, got %d bytes, want 0 (empty-flush survived)", len(got))
	}
}

// TestEncryptingFS_Close_ZeroesPlaintextOnError — review agent
// flagged that the original Close returned early on sealAndWrite
// error, leaving w.data holding plaintext until GC. Defer-zero
// must run on every path.
func TestEncryptingFS_Close_ZeroesPlaintextOnError(t *testing.T) {
	store := &failingStore{inner: newFakeStore(), failAfter: 1}
	fs := New(afero.NewMemMapFs(), mustKEK(t), store)

	w, err := fs.Create("/x.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	wf := w.(*writeFile)
	_, _ = w.Write([]byte("secret"))
	buf := wf.data
	_ = w.Close() // returns error — the injected Put failure
	for i, b := range buf {
		if b != 0 {
			t.Errorf("plaintext byte %d = %#x, want 0 — Close leaked plaintext", i, b)
			break
		}
	}
}

// TestEncryptingFS_PathLock_SerializesConcurrentWrites — the
// per-path Mutex added alongside the ordering fix ensures two
// concurrent Close calls on the same path can't interleave their
// (envelope, ciphertext) writes and produce an inconsistent pair.
func TestEncryptingFS_PathLock_SerializesConcurrentWrites(t *testing.T) {
	store := newFakeStore()
	fs := New(afero.NewMemMapFs(), mustKEK(t), store)

	const N = 8
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, err := fs.Create("/contested.bin")
			if err != nil {
				t.Errorf("goroutine %d Create: %v", i, err)
				return
			}
			_, _ = w.Write([]byte{byte(i)})
			_ = w.Close()
		}(i)
	}
	wg.Wait()
	// Whatever the winner — the ciphertext + envelope on disk
	// must be consistent (readable). If the lock didn't hold, we
	// could end up with a mismatched pair that ErrAuths.
	r, err := fs.Open("/contested.bin")
	if err != nil {
		t.Fatalf("after concurrent writes, Open failed: %v — (envelope, ciphertext) diverged", err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d bytes, want 1 (last-writer-wins)", len(got))
	}
}

// TestEncryptingFS_WriteFile_WriteAfterSeekBeyondEnd pins the
// sparse-hole semantics: Seek past EOF then Write must zero-pad
// the gap, matching OsFs behavior so clients that rely on it
// (e.g., TUS-over-range or partial re-upload) don't silently
// produce garbage.
func TestEncryptingFS_WriteFile_WriteAfterSeekBeyondEnd(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())
	w, err := fs.Create("/sparse.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Seek(10, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	if _, err := w.Write([]byte("X")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, err := fs.Open("/sparse.bin")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if len(got) != 11 {
		t.Fatalf("size = %d, want 11 (10 zero-bytes + 1 X)", len(got))
	}
	for i := 0; i < 10; i++ {
		if got[i] != 0 {
			t.Errorf("byte %d = %#x, want 0 (sparse hole)", i, got[i])
		}
	}
	if got[10] != 'X' {
		t.Errorf("byte 10 = %#x, want 'X'", got[10])
	}
}

// TestEncryptingFS_Truncate_ClampsPos — shrinking below the
// current position must clamp pos. Otherwise a subsequent Write
// would materialize a sparse hole using the stale pos.
func TestEncryptingFS_Truncate_ClampsPos(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())
	w, _ := fs.Create("/trunc.bin")
	_, _ = w.Write([]byte("0123456789"))
	wf := w.(*writeFile)
	// pos is now 10.
	if err := wf.Truncate(4); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	// pos must have clamped to 4.
	if _, err := w.Write([]byte("AB")); err != nil {
		t.Fatalf("Write after Truncate: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, _ := fs.Open("/trunc.bin")
	got, _ := io.ReadAll(r)
	r.Close()
	// Expect: "0123" (from original, first 4) + "AB" at pos 4 → "0123AB"
	if string(got) != "0123AB" {
		t.Errorf("truncate-then-write got %q, want %q", got, "0123AB")
	}
}

// TestEncryptingFS_OpenFile_CreateFlushesImmediately pins the fix
// for the TUS POST 404: OpenFile(O_CREATE|O_WRONLY) on a new file
// must make Stat see that file BEFORE the caller's deferred Close
// fires. Upstream TUS calls OpenFile then immediately NewFileInfo
// on the same path — without the immediate flush this 404s.
func TestEncryptingFS_OpenFile_CreateFlushesImmediately(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())

	// Simulate the TUS POST pattern: OpenFile then Stat BEFORE
	// Close.
	w, err := fs.OpenFile("/fresh.bin", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer w.Close()

	// THIS is the call that used to 404.
	info, err := fs.Stat("/fresh.bin")
	if err != nil {
		t.Fatalf("Stat on freshly-opened file failed: %v (TUS POST regression)", err)
	}
	if info.Size() != 0 {
		t.Errorf("fresh file size = %d, want 0", info.Size())
	}
}

// TestEncryptingFS_PathLocks_BoundedGrowth — writing many distinct
// paths must not leave a mutex per path in the package-global
// map. After each write completes, refcount drops to 0 and the
// entry is removed (H4).
func TestEncryptingFS_PathLocks_BoundedGrowth(t *testing.T) {
	// Serial writes under one fs: after each Close the lock row
	// should be gone.
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())
	for i := 0; i < 100; i++ {
		name := "/file" + string(rune('a'+(i%26))) + string(rune('0'+(i%10))) + ".bin"
		w, err := fs.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		_, _ = w.Write([]byte("x"))
		if err := w.Close(); err != nil {
			t.Fatalf("close %s: %v", name, err)
		}
	}
	if sz := pathLocksSize(); sz != 0 {
		t.Errorf("pathLocks not drained: size=%d after 100 serial writes (H4 regression)", sz)
	}
}

// TestEncryptingFS_PathLocks_ConcurrentSamePath — two goroutines
// writing the SAME path must serialize through one shared entry
// (refcount=2 momentarily) and then drop it.
func TestEncryptingFS_PathLocks_ConcurrentSamePath(t *testing.T) {
	fs := New(afero.NewMemMapFs(), mustKEK(t), newFakeStore())
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			w, err := fs.Create("/same.bin")
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			_, _ = w.Write([]byte("payload"))
			_ = w.Close()
		}()
	}
	wg.Wait()
	if sz := pathLocksSize(); sz != 0 {
		t.Errorf("pathLocks not drained after concurrent same-path writes: size=%d", sz)
	}
}

// scriptedScanner returns canned verdicts / errors — enough to drive
// every branch of sealAndWrite's scan gate.
type scriptedScanner struct {
	result scan.Result
	err    error
	calls  int
	lastRd []byte
}

func (s *scriptedScanner) Scan(_ context.Context, r io.Reader) (scan.Result, error) {
	s.calls++
	buf, _ := io.ReadAll(r)
	s.lastRd = buf
	return s.result, s.err
}

// TestEncryptingFS_Scanner_RejectsInfected — the central 3.14.2
// invariant: an infected payload must NOT produce a ciphertext file
// or an envelope row. Close returns *scan.RejectedError so the HTTP
// layer maps to 422.
func TestEncryptingFS_Scanner_RejectsInfected(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()
	sc := &scriptedScanner{result: scan.Result{Clean: false, Signature: "Eicar-Test"}}
	fs := New(under, mustKEK(t), store).WithScanner(sc, scan.ModeRequired)

	w, err := fs.Create("/evil.bin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.Write([]byte("X5O!P%@AP[4...EICAR...")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	closeErr := w.Close()
	var rej *scan.RejectedError
	if !errors.As(closeErr, &rej) {
		t.Fatalf("Close err = %v, want *scan.RejectedError", closeErr)
	}
	if rej.Signature != "Eicar-Test" {
		t.Errorf("signature = %q", rej.Signature)
	}

	// No ciphertext. No envelope. The file reject must be atomic —
	// nothing orphaned for operators to clean up.
	if exists, _ := afero.Exists(under, "/evil.bin"); exists {
		t.Error("ciphertext landed on disk despite reject")
	}
	if _, err := store.Get("/evil.bin"); err == nil {
		t.Error("envelope persisted despite reject")
	}
	if sc.calls != 1 {
		t.Errorf("scanner called %d times, want 1", sc.calls)
	}
}

// TestEncryptingFS_Scanner_PassesClean — confirms the scan hook does
// not break the happy path. Clean verdict → file round-trips normally.
func TestEncryptingFS_Scanner_PassesClean(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()
	sc := &scriptedScanner{result: scan.Result{Clean: true}}
	fs := New(under, mustKEK(t), store).WithScanner(sc, scan.ModeRequired)

	w, _ := fs.Create("/safe.bin")
	plaintext := []byte("benign contract draft")
	_, _ = w.Write(plaintext)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, err := fs.Open("/safe.bin")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch")
	}
	if !bytes.Equal(sc.lastRd, plaintext) {
		t.Errorf("scanner saw %q, want full plaintext", sc.lastRd)
	}
}

// TestEncryptingFS_Scanner_RequiredMode_BackendErrorBlocks — a sick
// clamd must NOT become a silent allow-list in Required mode.
func TestEncryptingFS_Scanner_RequiredMode_BackendErrorBlocks(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()
	sc := &scriptedScanner{err: scan.ErrUnavailable}
	fs := New(under, mustKEK(t), store).WithScanner(sc, scan.ModeRequired)

	w, _ := fs.Create("/x.bin")
	_, _ = w.Write([]byte("any payload"))
	closeErr := w.Close()
	if !errors.Is(closeErr, scan.ErrUnavailable) {
		t.Fatalf("Close err = %v, want ErrUnavailable", closeErr)
	}
	if exists, _ := afero.Exists(under, "/x.bin"); exists {
		t.Error("ciphertext written despite backend error in required mode")
	}
}

// TestEncryptingFS_Scanner_OptionalMode_BackendErrorAllows — optional
// mode trades enforcement for availability: a broken clamd logs
// loudly but lets the write through.
func TestEncryptingFS_Scanner_OptionalMode_BackendErrorAllows(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()
	sc := &scriptedScanner{err: scan.ErrUnavailable}
	fs := New(under, mustKEK(t), store).WithScanner(sc, scan.ModeOptional)

	w, _ := fs.Create("/x.bin")
	plaintext := []byte("any payload")
	_, _ = w.Write(plaintext)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v (optional mode must tolerate backend error)", err)
	}
	if exists, _ := afero.Exists(under, "/x.bin"); !exists {
		t.Error("ciphertext missing in optional mode")
	}
}

// TestEncryptingFS_Scanner_TUSPattern_RejectsInfected — pins the
// actual TUS-PATCH code path (OpenFile O_APPEND + Seek + Write +
// Sync + Close), which is what the UI uses for every upload. If
// this test passes, the scan hook fires on the TUS path; if it
// fails, scan-on-upload is broken for the default upload surface.
func TestEncryptingFS_Scanner_TUSPattern_RejectsInfected(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()
	sc := &scriptedScanner{result: scan.Result{Clean: false, Signature: "Eicar-Test"}}
	fs := New(under, mustKEK(t), store).WithScanner(sc, scan.ModeRequired)

	// Step 1: tusPostHandler-equivalent. Create the file with the
	// OpenFile O_CREATE|O_WRONLY shape — this triggers the empty
	// flush so Stat works.
	create, err := fs.OpenFile("/upload.bin", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := create.Close(); err != nil {
		t.Fatalf("close fresh create: %v", err)
	}

	// Step 2: tusPatchHandler-equivalent. OpenFile O_APPEND, Seek
	// to the reported offset, write the payload, Sync, Close.
	f, err := fs.OpenFile("/upload.bin", os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("patch open: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	// Full EICAR test string.
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if _, err := f.Write(eicar); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	closeErr := f.Close()

	// Scanner must have been invoked with the full payload, and the
	// Close must surface *RejectedError so the TUS handler can map
	// it to 422 + audit.
	if sc.calls == 0 {
		t.Fatal("scanner never called on TUS path — scan-on-upload bypass")
	}
	if !bytes.Equal(sc.lastRd, eicar) {
		t.Errorf("scanner saw %d bytes, want %d (full EICAR)", len(sc.lastRd), len(eicar))
	}
	var rej *scan.RejectedError
	if !errors.As(closeErr, &rej) {
		t.Fatalf("Close err = %v, want *scan.RejectedError", closeErr)
	}
	// And the empty-flush placeholder from Step 1 must be cleaned up.
	if exists, _ := afero.Exists(under, "/upload.bin"); exists {
		info, _ := under.Stat("/upload.bin")
		var size int64
		if info != nil {
			size = info.Size()
		}
		t.Errorf("ciphertext placeholder left on disk after reject (size=%d)", size)
	}
}

// TestEncryptingFS_Scanner_Reject_PreservesExistingFile — an
// infected overwrite must NOT destroy the already-persisted clean
// file at the same path. Reject should be a refused replacement, not
// a wipe. Without the TagSize guard in rollbackEmptyFlush we'd
// delete the operator's existing good content on any infected
// upload to the same name.
func TestEncryptingFS_Scanner_Reject_PreservesExistingFile(t *testing.T) {
	under := afero.NewMemMapFs()
	store := newFakeStore()

	// Seed a clean file first (scanner off).
	baseline := New(under, mustKEK(t), store)
	w, _ := baseline.Create("/doc.bin")
	good := []byte("approved revision B — 40 pages")
	_, _ = w.Write(good)
	if err := w.Close(); err != nil {
		t.Fatalf("baseline Close: %v", err)
	}
	goodEnv, err := store.Get("/doc.bin")
	if err != nil {
		t.Fatalf("baseline envelope: %v", err)
	}

	// Now attach an infected-verdict scanner and try to overwrite.
	sc := &scriptedScanner{result: scan.Result{Clean: false, Signature: "Eicar-Test"}}
	fs := baseline.WithScanner(sc, scan.ModeRequired)
	w2, _ := fs.OpenFile("/doc.bin", os.O_WRONLY|os.O_TRUNC, 0o600)
	_, _ = w2.Write([]byte("X5O!...infected replacement"))
	closeErr := w2.Close()
	var rej *scan.RejectedError
	if !errors.As(closeErr, &rej) {
		t.Fatalf("Close err = %v, want *scan.RejectedError", closeErr)
	}
	// The baseline file and envelope must be intact.
	env, err := store.Get("/doc.bin")
	if err != nil {
		t.Fatalf("baseline envelope removed by reject: %v", err)
	}
	if !bytes.Equal(env.EncDEK, goodEnv.EncDEK) {
		t.Error("envelope mutated by reject path")
	}
	r, err := fs.Open("/doc.bin")
	if err != nil {
		t.Fatalf("baseline file unopenable after reject: %v", err)
	}
	defer r.Close()
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, good) {
		t.Errorf("baseline content lost on reject:\n got %q\nwant %q", got, good)
	}
}

// TestEncryptingFS_Scanner_SkipsEmptyPlaintext — the OpenFile
// O_CREATE path flushes an empty buffer to make Stat see the file;
// scanning it would burn a round-trip per upload for no value.
func TestEncryptingFS_Scanner_SkipsEmptyPlaintext(t *testing.T) {
	under := afero.NewMemMapFs()
	sc := &scriptedScanner{result: scan.Result{Clean: false, Signature: "should-never-fire"}}
	fs := New(under, mustKEK(t), newFakeStore()).WithScanner(sc, scan.ModeRequired)

	// OpenFile with O_CREATE on a fresh path triggers the empty
	// flush in writeFile.
	f, err := fs.OpenFile("/empty.bin", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v (empty file flush must not invoke scanner)", err)
	}
	if sc.calls != 0 {
		t.Errorf("scanner called on empty flush (calls=%d)", sc.calls)
	}
}
