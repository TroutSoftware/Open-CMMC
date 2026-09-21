package otrelease

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
)

// Manager owns the inventory file for the running process: the web UI
// edits cells and machines through it, it validates and writes
// cells.yaml atomically, and it hot-reloads the releaser and intaker so
// new cells and machines get their directories without a restart.
//
// What it deliberately does not do is anything privileged. Rendering
// smb.conf, applying firewall rules and restarting the Samba container
// need root; a systemd path unit (config/smb/install-smb.sh installs
// cmmc-smb-apply.path) watches cells.yaml and re-runs the installer
// when the file changes. The UI reports whether that apply has caught
// up by comparing the file's mtime with render.env's.
type Manager struct {
	path     string
	etcDir   string
	mu       sync.RWMutex
	cells    *Cells
	releaser *Releaser
	intaker  *Intaker
	// SaveHook is called after a successful write with the new cells;
	// tests use it, and it is where a future in-process renderer would
	// hook in.
	SaveHook func(*Cells)
}

// NewManager wraps an already-loaded inventory.
func NewManager(path string, cells *Cells, r *Releaser, in *Intaker) *Manager {
	return &Manager{path: path, etcDir: filepath.Dir(path), cells: cells, releaser: r, intaker: in}
}

// Cells returns the current inventory (read-only view).
func (m *Manager) Cells() *Cells {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cells
}

// ErrInventoryConflict is returned when the caller's view of the file is
// stale (optimistic concurrency on mtime).
var ErrInventoryConflict = errors.New("otrelease: inventory changed since it was read")

// Status is what the UI shows about the inventory file and whether the
// privileged apply step has caught up with it.
type Status struct {
	Path      string    `json:"path"`
	Modified  time.Time `json:"modified"`
	Applied   time.Time `json:"applied"`
	UpToDate  bool      `json:"up_to_date"`
	OTAddress string    `json:"ot_address"`
	LegacyIP  string    `json:"legacy_ip,omitempty"`
}

// Status reads the file and render.env timestamps.
func (m *Manager) Status() Status {
	st := Status{Path: m.path}
	if fi, err := os.Stat(m.path); err == nil {
		st.Modified = fi.ModTime()
	}
	envPath := filepath.Join(m.etcDir, "render.env")
	if fi, err := os.Stat(envPath); err == nil {
		st.Applied = fi.ModTime()
		st.UpToDate = !st.Applied.Before(st.Modified)
	}
	if raw, err := os.ReadFile(envPath); err == nil {
		for _, line := range splitLines(string(raw)) {
			if k, v, ok := cutKV(line); ok {
				switch k {
				case "OT_IP":
					st.OTAddress = v
				case "LEGACY_IP":
					st.LegacyIP = v
				}
			}
		}
	}
	return st
}

// Save validates the proposed inventory, writes it atomically to
// cells.yaml, reloads the releaser/intaker, and emits an audit event.
// expectModified is the file mtime the caller last saw (zero to skip
// the check).
func (m *Manager) Save(ctx context.Context, proposed *Cells, expectModified time.Time, who ReleaseRequest) (*Cells, error) {
	// Round-trip through the parser: the caller's struct may carry
	// unexported state; the YAML bytes are the contract.
	raw, err := MarshalCells(proposed)
	if err != nil {
		return nil, err
	}
	cells, err := ParseCells(raw)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !expectModified.IsZero() {
		if fi, err := os.Stat(m.path); err == nil && !fi.ModTime().Equal(expectModified) {
			return nil, ErrInventoryConflict
		}
	}
	// In-place write, not rename: the file lives in a root-owned
	// directory the service user cannot create entries in. The content
	// is already validated and small; the apply unit triggers on
	// close-after-write, so it always sees the complete file.
	if err := os.WriteFile(m.path, raw, 0o640); err != nil {
		return nil, fmt.Errorf("otrelease: write inventory: %w", err)
	}
	if m.releaser != nil {
		if err := m.releaser.Reload(cells); err != nil {
			return nil, err
		}
	}
	if m.intaker != nil {
		if err := m.intaker.Reload(cells); err != nil {
			return nil, err
		}
	}
	m.cells = cells
	if m.SaveHook != nil {
		m.SaveHook(cells)
	}
	ev := audit.New(audit.ActionOTInventorySet, audit.OutcomeSuccess)
	ev.UserID = who.UserID
	ev.Username = who.ReleasedBy
	ev.ClientIP = who.ClientIP
	ev.CorrelationID = who.CorrelationID
	ev.Resource = m.path
	n := 0
	for _, c := range cells.Cells {
		n += len(c.Machines)
	}
	ev.Extra = map[string]interface{}{"cells": len(cells.Cells), "machines": n}
	audit.Emit(ctx, ev)
	return cells, nil
}

// MarshalCells renders the inventory as YAML with a short header.
func MarshalCells(c *Cells) ([]byte, error) {
	body, err := yaml.Marshal(struct {
		Cells []Cell `yaml:"cells"`
	}{Cells: c.Cells})
	if err != nil {
		return nil, err
	}
	header := "# Shop-floor inventory — managed from the Open-CMMC web UI (Settings → Shop floor).\n" +
		"# Hand edits are fine; the UI validates and rewrites this file. Schema: cmmc/otrelease/cells.go\n"
	return append([]byte(header), body...), nil
}

// Reload swaps the inventory on a Releaser, creating directories for
// new cells. Directories of removed cells are left in place (their
// contents are evidence; the expiry loop stops touching them).
func (r *Releaser) Reload(cells *Cells) error {
	for _, name := range cells.Names() {
		for _, d := range []string{filepath.Join(r.root, "out", name), filepath.Join(r.root, "state", "out", name)} {
			mode := os.FileMode(0o750)
			if filepath.Base(filepath.Dir(d)) == "out" && filepath.Base(filepath.Dir(filepath.Dir(d))) == "state" {
				mode = 0o700
			}
			if err := os.MkdirAll(d, mode); err != nil {
				return fmt.Errorf("otrelease: reload: %w", err)
			}
		}
	}
	r.mu.Lock()
	r.cells = cells
	r.mu.Unlock()
	return nil
}

// Reload swaps the inventory on an Intaker, creating return and
// quarantine directories for new cells and machines.
func (in *Intaker) Reload(cells *Cells) error {
	if err := ensureIntakeDirs(in.root, cells); err != nil {
		return err
	}
	in.cellsMu.Lock()
	in.cells = cells
	in.cellsMu.Unlock()
	return nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func cutKV(line string) (string, string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			return line[:i], line[i+1:], true
		}
	}
	return "", "", false
}
