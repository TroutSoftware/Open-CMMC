package otrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
)

// Manifest describes one release. The authoritative copy lives in the
// appliance-private state tree (<root>/state/out/<cell>/<name>.json),
// which the Samba container never sees, and is what Revoke, List,
// ExpireOnce and intake's matches_release read — a machine on the
// share cannot alter Source, Pinned or ExpiresAt. A read-only copy is
// published next to the payload (<name>.manifest.json) as the
// machine-readable half of the 3.8.4 marking that travels with the
// plaintext.
type Manifest struct {
	Name       string        `json:"name"`
	Cell       string        `json:"cell"`
	SHA256     string        `json:"sha256"`
	Size       int64         `json:"size"`
	Mark       cmmcmark.Mark `json:"mark"`
	Source     string        `json:"source"` // cabinet path (server-absolute)
	ReleasedBy string        `json:"released_by"`
	ReleasedAt time.Time     `json:"released_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	Pinned     bool          `json:"pinned"`
}

// ManifestSuffix is appended to the released file name for the public
// copy on the share. The private copy is <name>.json under state/.
const ManifestSuffix = ".manifest.json"

// MaxTTL bounds a caller-supplied TTL so a typo cannot leave plaintext
// on the floor for years. Pinned releases are the explicit exception.
const MaxTTL = 365 * 24 * time.Hour

// Sentinel errors the HTTP layer maps to statuses.
var (
	ErrUnknownCell     = errors.New("otrelease: unknown cell")
	ErrCellDesignation = errors.New("otrelease: file mark not permitted in this cell")
	ErrNotReleased     = errors.New("otrelease: not released")
	ErrBadName         = errors.New("otrelease: unsafe file name")
	ErrReleaseConflict = errors.New("otrelease: name already released from another file")
)

// ReleaseRequest is one release decision.
type ReleaseRequest struct {
	// Fs is the caller's decrypting filesystem (users.User.Fs); RelPath
	// is the path within it. The releaser never opens the cabinet
	// directly — it goes through the same EncryptingFS the HTTP
	// handlers use, so a misconfigured KEK fails here exactly as it
	// would on download.
	Fs      afero.Fs
	RelPath string
	// AbsPath is the server-absolute path, used as the marking key and
	// recorded in the manifest.
	AbsPath string
	Cell    string
	// Mark is the file's effective mark, resolved by the caller (the
	// handler already has the marking store and the user context).
	Mark       cmmcmark.Mark
	ReleasedBy string
	// TTL overrides the cell default when > 0.
	TTL    time.Duration
	Pinned bool
	// Admin lets a release replace an existing one from a different
	// cabinet source. A Release-grant holder may only refresh their own.
	Admin bool
	// Audit identity for the emitted event.
	UserID, ClientIP, CorrelationID string
}

// Releaser writes released files into <root>/out/<cell>/ and manages
// their lifetime. Safe for concurrent use.
type Releaser struct {
	root  string
	cells *Cells
	mu    sync.Mutex
	now   func() time.Time
}

// NewReleaser creates the out/ tree for every cell and returns a
// releaser. Directories are 0750 so the container (group member) can
// read but not write them.
func NewReleaser(root string, cells *Cells) (*Releaser, error) {
	for _, name := range cells.Names() {
		if err := os.MkdirAll(filepath.Join(root, "out", name), 0o750); err != nil {
			return nil, fmt.Errorf("otrelease: create out dir: %w", err)
		}
		if err := os.MkdirAll(filepath.Join(root, "state", "out", name), 0o700); err != nil {
			return nil, fmt.Errorf("otrelease: create state dir: %w", err)
		}
	}
	return &Releaser{root: root, cells: cells, now: time.Now}, nil
}

// OutDir is the cell's release directory (exported read-only).
func (r *Releaser) OutDir(cell string) string {
	return filepath.Join(r.root, "out", cell)
}

// stateDir holds the authoritative manifests (never exported).
func (r *Releaser) stateDir(cell string) string {
	return filepath.Join(r.root, "state", "out", cell)
}

func (r *Releaser) statePath(cell, name string) string {
	return filepath.Join(r.stateDir(cell), name+".json")
}

// Release copies one cabinet file into the cell's out directory.
// Atomic: bytes land in a temp file in the same directory and are
// renamed into place, so a machine listing the share never sees a
// partial program. Emits file.release.ot on success and a reject event
// on a designation refusal.
// cellsSnapshot returns the current inventory pointer (swapped by Reload).
func (r *Releaser) cellsSnapshot() *Cells {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cells
}

func (r *Releaser) Release(ctx context.Context, req ReleaseRequest) (*Manifest, error) {
	cell, ok := r.cellsSnapshot().Get(req.Cell)
	if !ok {
		return nil, ErrUnknownCell
	}
	name := path.Base(req.RelPath)
	if !safeName(name) {
		return nil, ErrBadName
	}
	if !cell.AcceptsMark(req.Mark) {
		ev := r.event(audit.ActionOTRelease, audit.OutcomeReject, req, name, "")
		ev.Reason = "cell designation does not permit mark"
		audit.Emit(ctx, ev)
		return nil, fmt.Errorf("%w: %s → %s", ErrCellDesignation, req.Mark, cell.Name)
	}

	src, err := req.Fs.Open(req.RelPath)
	if err != nil {
		return nil, fmt.Errorf("otrelease: open source: %w", err)
	}
	defer src.Close()
	if st, err := src.Stat(); err != nil {
		return nil, err
	} else if st.IsDir() {
		return nil, fmt.Errorf("%w: directories cannot be released", ErrBadName)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	dir := r.OutDir(cell.Name)
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("otrelease: temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), src)
	if err != nil {
		tmp.Close()
		cleanup()
		return nil, fmt.Errorf("otrelease: copy: %w", err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		cleanup()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return nil, err
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = cell.TTL()
	}
	if ttl > MaxTTL {
		ttl = MaxTTL
	}
	// Re-releasing the same name replaces the previous release; keep
	// the fact in the audit trail, and keep a pin the previous
	// release carried (an operator pinned it for a reason).
	prev, _ := readManifest(r.statePath(cell.Name, name))
	replaced := prev != nil
	if prev != nil && prev.Source != req.AbsPath && !req.Admin {
		cleanup()
		return nil, fmt.Errorf("%w: %q is already released to %s from a different file", ErrReleaseConflict, name, cell.Name)
	}
	// A pin survives a refresh from the same source; a different source
	// starts a new lifetime.
	if prev != nil && prev.Pinned && prev.Source == req.AbsPath {
		req.Pinned = true
	}
	now := r.now().UTC()
	m := &Manifest{
		Name:       name,
		Cell:       cell.Name,
		SHA256:     hex.EncodeToString(h.Sum(nil)),
		Size:       n,
		Mark:       req.Mark,
		Source:     req.AbsPath,
		ReleasedBy: req.ReleasedBy,
		ReleasedAt: now,
		ExpiresAt:  now.Add(ttl),
		Pinned:     req.Pinned,
	}
	// Order: private manifest, public sidecar, then the payload rename.
	// A reader that sees the program always finds its manifest, and
	// the authoritative record exists before anything is visible.
	if err := writeManifest(r.statePath(cell.Name, name), m); err != nil {
		cleanup()
		return nil, err
	}
	if err := writeManifest(filepath.Join(dir, name+ManifestSuffix), m); err != nil {
		cleanup()
		_ = os.Remove(r.statePath(cell.Name, name))
		return nil, err
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		cleanup()
		_ = os.Remove(filepath.Join(dir, name+ManifestSuffix))
		_ = os.Remove(r.statePath(cell.Name, name))
		return nil, fmt.Errorf("otrelease: publish: %w", err)
	}

	ev := r.event(audit.ActionOTRelease, audit.OutcomeSuccess, req, name, m.SHA256)
	ev.Extra["expires_at"] = m.ExpiresAt
	ev.Extra["pinned"] = m.Pinned
	ev.Extra["replaced"] = replaced
	audit.Emit(ctx, ev)
	return m, nil
}

// Revoke removes a released file and its manifest.
func (r *Releaser) Revoke(ctx context.Context, cellName, name, reason string, who ReleaseRequest) error {
	if _, ok := r.cellsSnapshot().Get(cellName); !ok {
		return ErrUnknownCell
	}
	if !safeName(name) {
		return ErrBadName
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revokeLocked(ctx, cellName, name, reason, who)
}

func (r *Releaser) revokeLocked(ctx context.Context, cellName, name, reason string, who ReleaseRequest) error {
	dir := r.OutDir(cellName)
	m, err := readManifest(r.statePath(cellName, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotReleased
		}
		return err
	}
	// Payload first, then the public sidecar, then the private record
	// — the inverse of Release, so a crash mid-way leaves an orphan
	// record (cleaned by the next ExpireOnce) rather than an
	// unmanifested file on the share.
	for _, p := range []string{filepath.Join(dir, name), filepath.Join(dir, name+ManifestSuffix), r.statePath(cellName, name)} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	who.Cell = cellName
	who.Mark = m.Mark
	ev := r.event(audit.ActionOTReleaseRevoke, audit.OutcomeSuccess, who, name, m.SHA256)
	ev.Reason = reason
	audit.Emit(ctx, ev)
	return nil
}

// List returns the manifests currently released to a cell, sorted by
// name. Orphan payloads (no manifest) are reported with an empty
// SHA256 so an operator can see and clean them.
func (r *Releaser) List(cellName string) ([]Manifest, error) {
	if _, ok := r.cellsSnapshot().Get(cellName); !ok {
		return nil, ErrUnknownCell
	}
	entries, err := os.ReadDir(r.stateDir(cellName))
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		m, err := readManifest(filepath.Join(r.stateDir(cellName), e.Name()))
		if err != nil {
			continue
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ExpireOnce revokes every unpinned release whose ExpiresAt has passed,
// across all cells, and removes orphan manifests. Returns "<cell>/<name>"
// for each removal. Called by the TTL loop in cmd/root.go and by tests.
func (r *Releaser) ExpireOnce(ctx context.Context) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UTC()
	var removed []string
	for _, cellName := range r.cells.Names() { // r.mu held
		entries, err := os.ReadDir(r.stateDir(cellName))
		if err != nil {
			return removed, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			m, err := readManifest(filepath.Join(r.stateDir(cellName), e.Name()))
			if err != nil {
				continue
			}
			if m.Pinned || now.Before(m.ExpiresAt) {
				continue
			}
			who := ReleaseRequest{ReleasedBy: "system", UserID: "system"}
			if err := r.revokeLocked(ctx, cellName, m.Name, "ttl", who); err != nil {
				return removed, err
			}
			removed = append(removed, cellName+"/"+m.Name)
		}
		// Orphans on the share (payload or sidecar without a private
		// record — a crash between steps, or something that is not
		// ours) are removed: nothing sits on an exported share without
		// an authoritative record behind it.
		shareEntries, err := os.ReadDir(r.OutDir(cellName))
		if err != nil {
			return removed, err
		}
		for _, e := range shareEntries {
			if e.IsDir() {
				continue
			}
			base := strings.TrimSuffix(e.Name(), ManifestSuffix)
			if _, err := os.Stat(r.statePath(cellName, base)); errors.Is(err, os.ErrNotExist) {
				_ = os.Remove(filepath.Join(r.OutDir(cellName), e.Name()))
				removed = append(removed, cellName+"/"+e.Name()+" (orphan)")
			}
		}
	}
	return removed, nil
}

// RunExpiry runs ExpireOnce every interval until ctx is done.
func (r *Releaser) RunExpiry(ctx context.Context, interval time.Duration, logf func(string, ...interface{})) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if gone, err := r.ExpireOnce(ctx); err != nil {
				logf("otrelease: expiry: %v", err)
			} else if len(gone) > 0 {
				logf("otrelease: expired %d release(s): %s", len(gone), strings.Join(gone, ", "))
			}
		}
	}
}

func (r *Releaser) event(action, outcome string, req ReleaseRequest, name, sum string) *audit.Event {
	ev := audit.New(action, outcome)
	ev.UserID = req.UserID
	ev.Username = req.ReleasedBy
	ev.ClientIP = req.ClientIP
	ev.CorrelationID = req.CorrelationID
	ev.Resource = req.AbsPath
	ev.Extra = map[string]interface{}{
		"cell": req.Cell,
		"name": name,
		"mark": string(req.Mark),
	}
	if sum != "" {
		ev.Extra["sha256"] = sum
	}
	return ev
}

// safeName accepts a plain file name: no separators, no dot-names, no
// control characters, and not a manifest. Machines see this name on
// the share, so keep it exactly what the cabinet shows.
func safeName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 255 {
		return false
	}
	if strings.ContainsAny(name, "/\\\x00") || strings.HasPrefix(name, ".") {
		return false
	}
	if strings.HasSuffix(name, ManifestSuffix) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func writeManifest(p string, m *Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func readManifest(p string) (*Manifest, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("otrelease: manifest %s: %w", p, err)
	}
	return &m, nil
}
