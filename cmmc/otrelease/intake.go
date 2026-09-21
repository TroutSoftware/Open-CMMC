package otrelease

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	"github.com/filebrowser/filebrowser/v2/cmmc/scan"
)

// Intaker drains the per-machine return folders. Order of operations
// is the whole point (scope § 4, C3 of the v1.1 ISA):
//
//  1. wait until the file is stable — same size and mtime across two
//     consecutive polls AND older than the settle window. A rename
//     would not help here: an SMB writer keeps its handle on the
//     renamed inode, and Windows copies preserve the *source* mtime,
//     so neither "moved" nor "old" proves "finished";
//  2. snapshot: copy the bytes into quarantine/pending (private, not
//     exported), delete the original from the share. Every later
//     step — gate, hash, scan, cabinet write — reads this one
//     immutable copy, so what was scanned is what gets filed;
//  3. content gate (extension, size, magic, text);
//  4. AV scan, fail-closed; a scanner outage holds the snapshot in
//     pending and it is retried on the next poll;
//  5. mark first (the row for the destination path, with the cell's
//     designation — 3.8.4 inheritance), then write through the
//     decrypting cabinet Fs into the cell's return folder, never
//     overwriting; a failed mark means nothing is filed;
//  6. charge the machine's daily quota only on a successful ingest;
//  7. audit accept / reject; rejects stay in quarantine/rejected with
//     a sidecar reason for the operator.
type Intaker struct {
	root string
	// cells is swapped by Reload; cellsMu guards the pointer, PollOnce
	// snapshots it once per poll.
	cells   *Cells
	cellsMu sync.RWMutex
	// cabinet is an afero.Fs rooted at the server root, built with
	// users.UserFsBuilder so writes are envelope-encrypted (and, in
	// required mode, scanned again by EncryptingFS — belt and
	// suspenders, but the explicit scan above is what fails closed
	// with a specific audit reason).
	cabinet afero.Fs
	// serverRoot is joined onto cabinet-relative paths to form the
	// marking-store key (server-absolute).
	serverRoot string
	meta       cmmcmark.Store
	scanner    scan.Scanner
	scanMode   scan.Mode
	quota      *Quota
	// settle is how old a file's mtime must be before we take it;
	// guards against grabbing a program a controller is still writing.
	settle time.Duration
	now    func() time.Time
	logf   func(string, ...interface{})

	// seen tracks (size, mtime) per share-side path between polls for
	// the stability gate.
	seen map[string]seenEntry
}

type seenEntry struct {
	size  int64
	mtime time.Time
}

// snapshotMeta rides alongside a quarantined snapshot so a held file
// can be retried (or an operator can tell what it is) without parsing
// the file name.
type snapshotMeta struct {
	Cell    string `json:"cell"`
	Machine string `json:"machine"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
}

// IntakeOptions configures NewIntaker.
type IntakeOptions struct {
	Root       string
	Cells      *Cells
	Cabinet    afero.Fs
	ServerRoot string
	Meta       cmmcmark.Store
	Scanner    scan.Scanner
	ScanMode   scan.Mode
	Settle     time.Duration // default 5s
	Logf       func(string, ...interface{})
}

// ErrScannerUnavailable is returned when required-mode scanning cannot
// run; the file is held in quarantine, not rejected and not filed.
var ErrScannerUnavailable = errors.New("otrelease: scanner unavailable")

// NewIntaker creates return/<cell>/<machine> (0770 — the container
// writes there) and quarantine trees, and returns the poller.
func NewIntaker(o IntakeOptions) (*Intaker, error) {
	if o.Cabinet == nil || o.Meta == nil || o.Cells == nil {
		return nil, errors.New("otrelease: intake needs cabinet fs, marking store and cells")
	}
	if o.ScanMode == scan.ModeRequired && o.Scanner == nil {
		return nil, fmt.Errorf("%w: scan mode required but no scanner", ErrScannerUnavailable)
	}
	if err := ensureIntakeDirs(o.Root, o.Cells); err != nil {
		return nil, err
	}
	if o.Settle <= 0 {
		o.Settle = 5 * time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...interface{}) {}
	}
	return &Intaker{
		root: o.Root, cells: o.Cells, cabinet: o.Cabinet, serverRoot: o.ServerRoot,
		meta: o.Meta, scanner: o.Scanner, scanMode: o.ScanMode,
		quota: NewQuota(), settle: o.Settle, now: time.Now, logf: o.Logf,
		seen: map[string]seenEntry{},
	}, nil
}

// ensureIntakeDirs creates return/<cell>/<machine> (0770 — the
// container's machine uid writes there) and the quarantine trees.
// Idempotent; called at start and on every inventory reload.
func ensureIntakeDirs(root string, cells *Cells) error {
	for _, c := range cells.Cells {
		for _, m := range c.Machines {
			d := filepath.Join(root, "return", c.Name, m.Name)
			if err := os.MkdirAll(d, 0o770); err != nil {
				return fmt.Errorf("otrelease: create return dir: %w", err)
			}
			// MkdirAll honours the process umask (022 under systemd), which
			// would strip the group-write bit the container's machine uid
			// relies on. Set the mode explicitly.
			if err := os.Chmod(d, 0o770); err != nil {
				return fmt.Errorf("otrelease: chmod return dir: %w", err)
			}
		}
		if err := os.Chmod(filepath.Join(root, "return", c.Name), 0o770); err != nil {
			return fmt.Errorf("otrelease: chmod return cell dir: %w", err)
		}
		for _, sub := range []string{"pending", "rejected"} {
			if err := os.MkdirAll(filepath.Join(root, "quarantine", sub, c.Name), 0o700); err != nil {
				return fmt.Errorf("otrelease: create quarantine: %w", err)
			}
		}
	}
	return nil
}

// ReturnDir is a machine's drop folder on the share side.
func (in *Intaker) ReturnDir(cell, machine string) string {
	return filepath.Join(in.root, "return", cell, machine)
}

// Result summarises one PollOnce.
type Result struct {
	Accepted []string // "<cell>/<machine>/<name>"
	Rejected []string
	Held     []string // scanner unavailable — still in quarantine/pending
}

// PollOnce drains every return folder once, then retries snapshots
// that were held by a scanner outage.
func (in *Intaker) PollOnce(ctx context.Context) (Result, error) {
	var res Result
	live := map[string]struct{}{}
	// Snapshots created in this poll; retryHeld skips them so a file held
	// by a scanner outage is retried on the *next* poll, not twice now.
	fresh := map[string]struct{}{}
	in.cellsMu.RLock()
	cells := in.cells
	in.cellsMu.RUnlock()
	for _, cell := range cells.Cells {
		for _, m := range cell.Machines {
			entries, err := os.ReadDir(in.ReturnDir(cell.Name, m.Name))
			if err != nil {
				return res, err
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".") {
					continue
				}
				// Regular files only. A symlink planted on the share (SMB1
				// unix extensions can create one) would otherwise be
				// followed by the copy below as the service user —
				// reading another cell's plaintext or the KEK file into
				// this cell's return folder under its mark. Sockets,
				// FIFOs and devices would hang the poller.
				if !e.Type().IsRegular() {
					src := filepath.Join(in.ReturnDir(cell.Name, m.Name), e.Name())
					in.rejectForeign(ctx, &cell, &m, e.Name(), src, "not a regular file: "+e.Type().String())
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				src := filepath.Join(in.ReturnDir(cell.Name, m.Name), e.Name())
				live[src] = struct{}{}
				if !in.stable(src, info) {
					continue
				}
				delete(in.seen, src)
				pending, err := in.snapshot(&cell, &m, e.Name(), info.Size())
				if err != nil {
					in.logf("otrelease: intake snapshot %s: %v", src, err)
					continue
				}
				fresh[pending] = struct{}{}
				k, perr := in.process(ctx, &cell, &m, e.Name(), pending)
				in.classify(&res, k, perr)
			}
		}
	}
	// Forget entries whose file vanished between polls.
	for k := range in.seen {
		if _, ok := live[k]; !ok {
			delete(in.seen, k)
		}
	}
	in.retryHeld(ctx, &res, fresh, cells)
	return res, nil
}

// stable implements the two-poll stability gate.
func (in *Intaker) stable(src string, info os.FileInfo) bool {
	cur := seenEntry{size: info.Size(), mtime: info.ModTime()}
	prev, ok := in.seen[src]
	in.seen[src] = cur
	if !ok || prev != cur {
		return false
	}
	return in.now().Sub(info.ModTime()) >= in.settle
}

// rejectForeign removes a non-regular entry from the share and audits
// it; nothing is copied.
func (in *Intaker) rejectForeign(ctx context.Context, cell *Cell, m *Machine, name, src, reason string) {
	_ = os.Remove(src)
	ev := audit.New(audit.ActionOTIntakeReject, audit.OutcomeReject)
	ev.UserID = "system"
	ev.Username = "ot-intake"
	ev.Resource = path.Join(cell.ReturnPath, m.Name, name)
	ev.Reason = reason
	ev.Extra = map[string]interface{}{"cell": cell.Name, "machine": m.Name, "name": name}
	audit.Emit(ctx, ev)
}

// snapshot copies the share-side file into quarantine/pending and
// removes the original. Returns the pending path.
func (in *Intaker) snapshot(cell *Cell, m *Machine, name string, size int64) (string, error) {
	src := filepath.Join(in.ReturnDir(cell.Name, m.Name), name)
	pending := filepath.Join(in.root, "quarantine", "pending", cell.Name, randomPrefix()+"-"+m.Name+"-"+name)
	if err := copyRegularNoFollow(src, pending); err != nil {
		_ = os.Remove(pending)
		return "", err
	}
	if err := writeSnapshotMeta(pending, snapshotMeta{Cell: cell.Name, Machine: m.Name, Name: name, Size: size}); err != nil {
		_ = os.Remove(pending)
		return "", err
	}
	if err := os.Remove(src); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The copy is ours regardless; a lingering original will be
		// re-snapshotted next poll and deduplicated by name suffixing.
		in.logf("otrelease: intake: remove original %s: %v", src, err)
	}
	return pending, nil
}

// retryHeld re-processes snapshots left in pending by a scanner outage.
func (in *Intaker) retryHeld(ctx context.Context, res *Result, skip map[string]struct{}, cells *Cells) {
	for _, cell := range cells.Cells {
		dir := filepath.Join(in.root, "quarantine", "pending", cell.Name)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasSuffix(e.Name(), ".meta.json") {
				continue
			}
			pending := filepath.Join(dir, e.Name())
			if _, ok := skip[pending]; ok {
				continue
			}
			meta, err := readSnapshotMeta(pending)
			if err != nil {
				continue
			}
			c, m, ok := cells.MachineByName(meta.Machine)
			if !ok || c.Name != meta.Cell {
				continue
			}
			k, perr := in.process(ctx, c, m, meta.Name, pending)
			in.classify(res, k, perr)
		}
	}
}

func (in *Intaker) classify(res *Result, key string, err error) {
	switch {
	case err == nil:
		res.Accepted = append(res.Accepted, key)
	case errors.Is(err, ErrScannerUnavailable):
		res.Held = append(res.Held, key)
	case IsGateError(err) || isScanReject(err):
		res.Rejected = append(res.Rejected, key)
	default:
		in.logf("otrelease: intake %s: %v", key, err)
		res.Held = append(res.Held, key)
	}
}

// Run polls every interval until ctx is done.
func (in *Intaker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if r, err := in.PollOnce(ctx); err != nil {
				in.logf("otrelease: intake poll: %v", err)
			} else if len(r.Accepted)+len(r.Rejected)+len(r.Held) > 0 {
				in.logf("otrelease: intake accepted=%d rejected=%d held=%d", len(r.Accepted), len(r.Rejected), len(r.Held))
			}
		}
	}
}

// process runs gate → scan → mark → file → quota → audit on one
// immutable snapshot. Returns the result key and the outcome error.
func (in *Intaker) process(ctx context.Context, cell *Cell, m *Machine, name, pending string) (string, error) {
	key := cell.Name + "/" + m.Name + "/" + name

	// Content gate.
	size, err := statSize(pending)
	if err != nil {
		return key, err
	}
	f, err := os.Open(pending)
	if err != nil {
		return key, err
	}
	gateErr := CheckContent(cell, name, size, f)
	f.Close()
	if gateErr != nil {
		in.reject(ctx, cell, m, name, pending, gateErr.Error(), "")
		return key, gateErr
	}

	// Hash (own pass — a scanner is free to stop reading early), then
	// scan, fail-closed.
	sum, err := fileSHA256(pending)
	if err != nil {
		return key, err
	}
	verdict := scan.Result{Clean: true}
	var scanErr error
	if in.scanner != nil {
		f, err = os.Open(pending)
		if err != nil {
			return key, err
		}
		verdict, scanErr = in.scanner.Scan(ctx, f)
		f.Close()
	}
	if scanErr != nil {
		if in.scanMode == scan.ModeRequired {
			// Hold: not rejected (we don't know it's bad), not filed
			// (we don't know it's clean). Retried next poll.
			in.logf("otrelease: intake %s held — scanner error: %v", key, scanErr)
			return key, fmt.Errorf("%w: %v", ErrScannerUnavailable, scanErr)
		}
		in.logf("otrelease: intake %s scanner error in optional mode, continuing: %v", key, scanErr)
	}
	if !verdict.Clean {
		in.reject(ctx, cell, m, name, pending, "malware: "+verdict.Signature, sum)
		return key, &scan.RejectedError{Signature: verdict.Signature, Path: path.Join(cell.ReturnPath, m.Name, name)}
	}

	// Quota is a flood brake on *accepted* files; check it here so a
	// held/retried file is never charged twice, charge only after the
	// write succeeds.
	if err := in.quota.Peek(m.Name, cell.Quota()); err != nil {
		in.reject(ctx, cell, m, name, pending, err.Error(), sum)
		return key, err
	}

	// Mark first, then file. A destination row that points at a path
	// which does not exist yet is harmless; an unmarked file in the
	// cabinet is not.
	relDir := path.Join(cell.ReturnPath, m.Name)
	if err := in.cabinet.MkdirAll(relDir, 0o750); err != nil {
		return key, fmt.Errorf("cabinet mkdir: %w", err)
	}
	dest, err := in.uniqueName(relDir, name)
	if err != nil {
		return key, err
	}
	absDest := filepath.Join(in.serverRoot, filepath.FromSlash(dest))
	nowT := in.now().UTC()
	if err := in.meta.Put(&cmmcmark.FileMetadata{
		Path: absDest, Mark: cell.Mark, SHA256: sum, Source: "ot-intake:" + m.Name,
		LastScannedAt: nowT, CreatedAt: nowT, ModifiedAt: nowT,
	}); err != nil {
		return key, fmt.Errorf("marking row: %w", err)
	}
	if err := in.copyIn(pending, dest); err != nil {
		_ = in.meta.Delete(absDest)
		return key, fmt.Errorf("cabinet write: %w", err)
	}
	in.quota.Take(m.Name, cell.Quota()) //nolint:errcheck // Peek passed above
	_ = os.Remove(pending)
	_ = os.Remove(pending + ".meta.json")

	ev := audit.New(audit.ActionOTIntake, audit.OutcomeSuccess)
	ev.UserID = "system"
	ev.Username = "ot-intake"
	ev.Resource = absDest
	ev.Extra = map[string]interface{}{
		"cell": cell.Name, "machine": m.Name, "name": name, "sha256": sum,
		"mark": string(cell.Mark), "size": size,
		"matches_release": in.matchesRelease(cell.Name, name, sum),
	}
	audit.Emit(ctx, ev)
	return key, nil
}

// reject moves the quarantined file to rejected/ with a .reason sidecar
// and emits file.intake.reject.
func (in *Intaker) reject(ctx context.Context, cell *Cell, m *Machine, name, pending, reason, sum string) {
	dst := filepath.Join(in.root, "quarantine", "rejected", cell.Name, filepath.Base(pending))
	if err := os.Rename(pending, dst); err != nil {
		in.logf("otrelease: intake: move to rejected: %v", err)
	}
	_ = os.Rename(pending+".meta.json", dst+".meta.json")
	_ = os.WriteFile(dst+".reason", []byte(reason+"\n"), 0o600)
	ev := audit.New(audit.ActionOTIntakeReject, audit.OutcomeReject)
	ev.UserID = "system"
	ev.Username = "ot-intake"
	ev.Resource = path.Join(cell.ReturnPath, m.Name, name)
	ev.Reason = reason
	ev.Extra = map[string]interface{}{"cell": cell.Name, "machine": m.Name, "name": name, "quarantine": dst}
	if sum != "" {
		ev.Extra["sha256"] = sum
	}
	audit.Emit(ctx, ev)
}

// uniqueName returns relDir/name, or name-N.ext if it exists.
func (in *Intaker) uniqueName(relDir, name string) (string, error) {
	cand := path.Join(relDir, name)
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i < 10000; i++ {
		if _, err := in.cabinet.Stat(cand); errors.Is(err, os.ErrNotExist) {
			return cand, nil
		} else if err != nil {
			return "", err
		}
		cand = path.Join(relDir, fmt.Sprintf("%s-%d%s", stem, i, ext))
	}
	return "", errors.New("otrelease: too many versions")
}

func (in *Intaker) copyIn(src, destRel string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	w, err := in.cabinet.OpenFile(destRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, f); err != nil {
		w.Close()
		_ = in.cabinet.Remove(destRel)
		return err
	}
	if err := w.Close(); err != nil {
		_ = in.cabinet.Remove(destRel)
		return err
	}
	return nil
}

// matchesRelease reports whether a returned file is byte-identical to
// the currently released file of the same name in the cell (i.e. the
// operator did not edit it).
func (in *Intaker) matchesRelease(cell, name, sum string) bool {
	m, err := readManifest(filepath.Join(in.root, "state", "out", cell, name+".json"))
	return err == nil && m.SHA256 == sum
}

func randomPrefix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func isScanReject(err error) bool {
	var r *scan.RejectedError
	return errors.As(err, &r)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyRegularNoFollow copies src to dst without following a symlink at
// src and only if what it opened is a regular file — the check is on
// the opened descriptor, so a swap between the directory listing and
// the open cannot redirect it.
func copyRegularNoFollow(src, dst string) error {
	fd, err := syscall.Open(src, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	in := os.NewFile(uintptr(fd), src)
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", src)
	}
	return copyFrom(in, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return copyFrom(in, dst)
}

func copyFrom(in *os.File, dst string) error {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func writeSnapshotMeta(pending string, m snapshotMeta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return os.WriteFile(pending+".meta.json", raw, 0o600)
}

func readSnapshotMeta(pending string) (snapshotMeta, error) {
	var m snapshotMeta
	raw, err := os.ReadFile(pending + ".meta.json")
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(raw, &m)
}
