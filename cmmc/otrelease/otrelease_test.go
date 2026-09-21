package otrelease

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	"github.com/filebrowser/filebrowser/v2/cmmc/scan"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

const fixtureCells = `
cells:
  - name: cell-a
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/cell-a/return
    machines:
      - { name: cnc-a1, ip: 10.20.1.11, dialect: smb3, auth: password, model: "Haas VF-2 NGC" }
  - name: cell-itar
    mark: "CUI//SP-ITAR"
    return_path: /ITAR/NC/cell-itar/return
    pds_attested: true
    ttl_days: 2
    machines:
      - { name: cnc-i1, ip: 10.20.9.5, dialect: smb1 }
      - { name: cnc-i2, ip: 10.20.9.6, dialect: smb2 }
`

func mustCells(t *testing.T) *Cells {
	t.Helper()
	c, err := ParseCells([]byte(fixtureCells))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return c
}

// --- cells -----------------------------------------------------------

func TestParseCellsFixture(t *testing.T) {
	c := mustCells(t)
	if got := c.Names(); strings.Join(got, ",") != "cell-a,cell-itar" {
		t.Fatalf("names = %v", got)
	}
	cell, _, ok := c.MachineByName("cnc-i2")
	if !ok || cell.Name != "cell-itar" {
		t.Fatalf("MachineByName: %v %v", cell, ok)
	}
	if a, _ := c.Get("cell-a"); a.TTL() != 30*24*time.Hour || !a.EncryptShares() {
		t.Fatalf("defaults not applied: %+v", a)
	}
	if it, _ := c.Get("cell-itar"); it.TTL() != 48*time.Hour {
		t.Fatalf("ttl_days ignored")
	}
}

func TestParseCellsRejects(t *testing.T) {
	cases := map[string]string{
		"dup machine": strings.Replace(fixtureCells, "cnc-i2", "cnc-a1", 1),
		"dup ip":      strings.Replace(fixtureCells, "10.20.9.6", "10.20.1.11", 1),
		"bad mark":    strings.Replace(fixtureCells, `"CUI//BASIC"`, `"SECRET"`, 1),
		"smb1 no pds": strings.Replace(fixtureCells, "pds_attested: true", "pds_attested: false", 1),
		"bad ident":   strings.Replace(fixtureCells, "cnc-a1", "CNC_A1", 1),
		"rel path":    strings.Replace(fixtureCells, "/Operations_CUI", "Operations_CUI", 1),
		"unknown key": strings.Replace(fixtureCells, "ttl_days: 2", "ttl: 2", 1),
		"bad encrypt": strings.Replace(fixtureCells, "ttl_days: 2", "encrypt: maybe", 1),
		"none no pds": strings.Replace(fixtureCells, "auth: password, ", "", 1),
		"bad auth":    strings.Replace(fixtureCells, "auth: password", "auth: pin", 1),
	}
	for name, yml := range cases {
		if _, err := ParseCells([]byte(yml)); !errors.Is(err, ErrInvalidCells) {
			t.Errorf("%s: want ErrInvalidCells, got %v", name, err)
		}
	}
}

func TestExampleCellsFileValidates(t *testing.T) {
	p := filepath.Join("..", "..", "config", "smb", "cells.example.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Skip("example file not present yet")
	}
	if _, err := LoadCells(p); err != nil {
		t.Fatalf("cells.example.yaml: %v", err)
	}
}

func TestAcceptsMark(t *testing.T) {
	c := mustCells(t)
	a, _ := c.Get("cell-a")
	it, _ := c.Get("cell-itar")
	if a.AcceptsMark(cmmcmark.MarkITAR) {
		t.Error("BASIC cell accepted ITAR")
	}
	if !it.AcceptsMark(cmmcmark.MarkITAR) || !it.AcceptsMark(cmmcmark.MarkBasic) || !a.AcceptsMark(cmmcmark.MarkNone) {
		t.Error("expected acceptance")
	}
}

// --- release ---------------------------------------------------------

type harness struct {
	root    string
	cells   *Cells
	rel     *Releaser
	src     afero.Fs
	mem     *audit.MemoryEmitter
	clock   time.Time
	cabinet afero.Fs
	meta    *fakeMeta
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	cells := mustCells(t)
	rel, err := NewReleaser(root, cells)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{root: root, cells: cells, rel: rel, src: afero.NewMemMapFs(), mem: audit.NewMemoryEmitter(), clock: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)}
	rel.now = func() time.Time { return h.clock }
	audit.SetDefault(h.mem)
	t.Cleanup(func() { audit.SetDefault(audit.NewMemoryEmitter()) })
	_ = afero.WriteFile(h.src, "/Operations_CUI/NC/O1001.nc", []byte("%\nO1001\nG0 X0 Y0\nM30\n%\n"), 0o640)
	h.cabinet = afero.NewMemMapFs()
	h.meta = &fakeMeta{rows: map[string]*cmmcmark.FileMetadata{}}
	return h
}

func (h *harness) req(cell string, mark cmmcmark.Mark) ReleaseRequest {
	return ReleaseRequest{Fs: h.src, RelPath: "/Operations_CUI/NC/O1001.nc", AbsPath: "/srv/files/Operations_CUI/NC/O1001.nc", Cell: cell, Mark: mark, ReleasedBy: "alice", UserID: "7", ClientIP: "10.0.0.5"}
}

func (h *harness) actions() []string {
	var out []string
	for _, e := range h.mem.Events() {
		out = append(out, e.Action+":"+e.Outcome)
	}
	return out
}

func TestReleaseWritesFileAndManifestAtomically(t *testing.T) {
	h := newHarness(t)
	m, err := h.rel.Release(context.Background(), h.req("cell-a", cmmcmark.MarkBasic))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(h.root, "out", "cell-a", "O1001.nc"))
	if err != nil || !bytes.Contains(got, []byte("O1001")) {
		t.Fatalf("payload missing: %v", err)
	}
	if m.SHA256 == "" || m.Size != int64(len(got)) || m.Mark != cmmcmark.MarkBasic || m.ReleasedBy != "alice" || m.Cell != "cell-a" {
		t.Fatalf("manifest: %+v", m)
	}
	if !m.ExpiresAt.Equal(h.clock.Add(30 * 24 * time.Hour)) {
		t.Fatalf("expires: %v", m.ExpiresAt)
	}
	entries, _ := os.ReadDir(filepath.Join(h.root, "out", "cell-a"))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	list, _ := h.rel.List("cell-a")
	if len(list) != 1 || list[0].Name != "O1001.nc" {
		t.Fatalf("list: %+v", list)
	}
	if a := h.actions(); len(a) != 1 || a[0] != "file.release.ot:success" {
		t.Fatalf("audit: %v", a)
	}
	ev := h.mem.Events()[0]
	if ev.Extra["cell"] != "cell-a" || ev.Extra["sha256"] != m.SHA256 || ev.Extra["mark"] != string(cmmcmark.MarkBasic) || ev.UserID != "7" {
		t.Fatalf("audit extra: %+v", ev)
	}
}

func TestReleaseRefusesITARToBasicCell(t *testing.T) {
	h := newHarness(t)
	_, err := h.rel.Release(context.Background(), h.req("cell-a", cmmcmark.MarkITAR))
	if !errors.Is(err, ErrCellDesignation) {
		t.Fatalf("want ErrCellDesignation, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "out", "cell-a", "O1001.nc")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file was released despite refusal")
	}
	if a := h.actions(); len(a) != 1 || a[0] != "file.release.ot:reject" {
		t.Fatalf("audit: %v", a)
	}
	if _, err := h.rel.Release(context.Background(), h.req("cell-itar", cmmcmark.MarkITAR)); err != nil {
		t.Fatalf("ITAR → ITAR cell should pass: %v", err)
	}
}

func TestReleaseUnknownCellAndBadNames(t *testing.T) {
	h := newHarness(t)
	if _, err := h.rel.Release(context.Background(), h.req("nope", cmmcmark.MarkNone)); !errors.Is(err, ErrUnknownCell) {
		t.Fatalf("want ErrUnknownCell, got %v", err)
	}
	r := h.req("cell-a", cmmcmark.MarkNone)
	r.RelPath = "/Operations_CUI/NC/.hidden.nc"
	if _, err := h.rel.Release(context.Background(), r); !errors.Is(err, ErrBadName) {
		t.Fatalf("dot name: %v", err)
	}
	r.RelPath = "/Operations_CUI/NC"
	if _, err := h.rel.Release(context.Background(), r); !errors.Is(err, ErrBadName) {
		t.Fatalf("dir: %v", err)
	}
}

func TestRevokeAndExpiry(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.rel.Release(ctx, h.req("cell-a", cmmcmark.MarkBasic)); err != nil {
		t.Fatal(err)
	}
	if err := h.rel.Revoke(ctx, "cell-a", "O1001.nc", "operator", ReleaseRequest{ReleasedBy: "bob", UserID: "8"}); err != nil {
		t.Fatal(err)
	}
	if err := h.rel.Revoke(ctx, "cell-a", "O1001.nc", "again", ReleaseRequest{}); !errors.Is(err, ErrNotReleased) {
		t.Fatalf("second revoke: %v", err)
	}
	if list, _ := h.rel.List("cell-a"); len(list) != 0 {
		t.Fatalf("still listed: %+v", list)
	}

	// TTL: cell-itar has ttl_days 2; a pinned release survives.
	if _, err := h.rel.Release(ctx, h.req("cell-itar", cmmcmark.MarkITAR)); err != nil {
		t.Fatal(err)
	}
	pinned := h.req("cell-itar", cmmcmark.MarkITAR)
	pinned.Pinned = true
	pinned.RelPath = "/Operations_CUI/NC/O2002.nc"
	_ = afero.WriteFile(h.src, pinned.RelPath, []byte("O2002\n"), 0o640)
	if _, err := h.rel.Release(ctx, pinned); err != nil {
		t.Fatal(err)
	}
	h.mem.Reset()
	if gone, _ := h.rel.ExpireOnce(ctx); len(gone) != 0 {
		t.Fatalf("expired too early: %v", gone)
	}
	h.clock = h.clock.Add(49 * time.Hour)
	gone, err := h.rel.ExpireOnce(ctx)
	if err != nil || len(gone) != 1 || gone[0] != "cell-itar/O1001.nc" {
		t.Fatalf("expire: %v %v", gone, err)
	}
	ev := h.mem.Events()
	if len(ev) != 1 || ev[0].Action != audit.ActionOTReleaseRevoke || ev[0].Reason != "ttl" {
		t.Fatalf("expiry audit: %+v", ev)
	}
	if list, _ := h.rel.List("cell-itar"); len(list) != 1 || list[0].Name != "O2002.nc" {
		t.Fatalf("pinned lost: %+v", list)
	}
}

func TestReleaseReplaceKeepsPinAndAudits(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	first := h.req("cell-a", cmmcmark.MarkBasic)
	first.Pinned = true
	if _, err := h.rel.Release(ctx, first); err != nil {
		t.Fatal(err)
	}
	_ = afero.WriteFile(h.src, "/Operations_CUI/NC/O1001.nc", []byte("O1001 v2\n"), 0o640)
	h.mem.Reset()
	m, err := h.rel.Release(ctx, h.req("cell-a", cmmcmark.MarkBasic)) // not pinned in request
	if err != nil {
		t.Fatal(err)
	}
	if !m.Pinned {
		t.Fatal("pin from previous release was dropped on replace")
	}
	if ev := h.mem.Events(); len(ev) != 1 || ev[0].Extra["replaced"] != true {
		t.Fatalf("replace not audited: %+v", ev)
	}
	got, _ := os.ReadFile(filepath.Join(h.root, "out", "cell-a", "O1001.nc"))
	if string(got) != "O1001 v2\n" {
		t.Fatalf("payload not replaced: %q", got)
	}
	// TTL cap.
	long := h.req("cell-a", cmmcmark.MarkBasic)
	long.TTL = 10 * 365 * 24 * time.Hour
	m, _ = h.rel.Release(ctx, long)
	if m.ExpiresAt.Sub(h.clock) > MaxTTL {
		t.Fatalf("TTL not capped: %v", m.ExpiresAt)
	}
}

func TestManifestOnShareIsNotAuthoritative(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.rel.Release(ctx, h.req("cell-a", cmmcmark.MarkBasic)); err != nil {
		t.Fatal(err)
	}
	// Tamper with the public sidecar as a machine on the share could
	// (if the share were ever writable): List and Revoke must not care.
	pub := filepath.Join(h.root, "out", "cell-a", "O1001"+".nc"+ManifestSuffix)
	_ = os.WriteFile(pub, []byte(`{"name":"O1001.nc","cell":"cell-a","source":"/somewhere/else","pinned":true}`), 0o640)
	list, _ := h.rel.List("cell-a")
	if len(list) != 1 || list[0].Source != "/srv/files/Operations_CUI/NC/O1001.nc" || list[0].Pinned {
		t.Fatalf("List read the tampered sidecar: %+v", list)
	}
	h.clock = h.clock.Add(31 * 24 * time.Hour)
	gone, _ := h.rel.ExpireOnce(ctx)
	if len(gone) != 1 {
		t.Fatalf("tampered pin honoured: %v", gone)
	}
	// Orphan sweep: a stray file on the share with no private record.
	_ = os.WriteFile(filepath.Join(h.root, "out", "cell-a", "stray.nc"), []byte("x"), 0o640)
	gone, _ = h.rel.ExpireOnce(ctx)
	if len(gone) != 1 || !strings.Contains(gone[0], "stray.nc") {
		t.Fatalf("orphan not swept: %v", gone)
	}
}

// --- gate ------------------------------------------------------------

func TestCheckContent(t *testing.T) {
	c := mustCells(t)
	cell, _ := c.Get("cell-a")
	ok := []byte("%\nO1001 (PART A)\nG21 G90\nG0 X0. Y0.\nM30\n%\n")
	cases := []struct {
		name string
		file string
		body []byte
		size int64
		code string
	}{
		{"clean", "O1001.nc", ok, int64(len(ok)), ""},
		{"upper ext ok", "O1001.NC", ok, int64(len(ok)), ""},
		{"bad ext", "run.exe", ok, int64(len(ok)), GateExtension},
		{"too big", "O1.nc", ok, cell.MaxBytes() + 1, GateSize},
		{"mz", "O1.nc", append([]byte("MZ"), ok...), 100, GateMagic},
		{"zip", "O1.txt", append([]byte("PK\x03\x04"), ok...), 100, GateMagic},
		{"gzip", "O1.txt", []byte{0x1f, 0x8b, 0x08}, 3, GateMagic},
		{"elf", "O1.txt", []byte{0x7f, 'E', 'L', 'F', 2}, 5, GateMagic},
		{"shebang", "O1.txt", []byte("#!/bin/sh\n"), 10, GateMagic},
		{"binary", "O1.nc", bytes.Repeat([]byte{0x01, 0x02, 'a'}, 100), 300, GateBinary},
		{"nul", "O1.nc", []byte("O1\x00G0"), 5, GateBinary},
		{"utf8 ok", "O1.txt", []byte("Ø 12.5 mm — T1\n"), 20, ""},
		{"esc tolerated", "O1.txt", []byte("\x1bO1\nG0\n"), 7, ""},
		{"bad name", "../O1.nc", ok, 10, GateName},
	}
	for _, tc := range cases {
		err := CheckContent(cell, tc.file, tc.size, bytes.NewReader(tc.body))
		if tc.code == "" {
			if err != nil {
				t.Errorf("%s: unexpected %v", tc.name, err)
			}
			continue
		}
		var g *GateError
		if !errors.As(err, &g) || g.Code != tc.code {
			t.Errorf("%s: want %s, got %v", tc.name, tc.code, err)
		}
	}
}

func TestQuota(t *testing.T) {
	q := NewQuota()
	day := time.Date(2026, 9, 18, 23, 0, 0, 0, time.UTC)
	q.now = func() time.Time { return day }
	for i := 0; i < 3; i++ {
		if err := q.Take("m1", 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Take("m1", 3); err == nil || !IsGateError(err) {
		t.Fatalf("want quota error, got %v", err)
	}
	if err := q.Take("m2", 3); err != nil {
		t.Fatal("per-machine isolation broken")
	}
	day = day.Add(2 * time.Hour) // next UTC day
	if err := q.Take("m1", 3); err != nil {
		t.Fatal("day rollover did not reset")
	}
}

// --- intake ----------------------------------------------------------

type fakeMeta struct {
	rows map[string]*cmmcmark.FileMetadata
}

func (f *fakeMeta) Get(p string) (*cmmcmark.FileMetadata, error) {
	if r, ok := f.rows[p]; ok {
		return r, nil
	}
	return nil, fberrors.ErrNotExist
}
func (f *fakeMeta) GetEffective(p string) (*cmmcmark.FileMetadata, error) { return f.Get(p) }
func (f *fakeMeta) HasCUIDescendants(string) (bool, error)                { return false, nil }
func (f *fakeMeta) Put(md *cmmcmark.FileMetadata) error                   { f.rows[md.Path] = md; return nil }
func (f *fakeMeta) Delete(p string) error                                 { delete(f.rows, p); return nil }
func (f *fakeMeta) Rename(a, b string) error                              { f.rows[b] = f.rows[a]; delete(f.rows, a); return nil }
func (f *fakeMeta) Copy(a, b, _ string) error                             { f.rows[b] = f.rows[a]; return nil }
func (f *fakeMeta) GetMany([]string) (map[string]*cmmcmark.FileMetadata, error) {
	return f.rows, nil
}
func (f *fakeMeta) DeleteByOwnerID(uint) error { return nil }
func (f *fakeMeta) GetManyEffective([]string) (map[string]*cmmcmark.FileMetadata, error) {
	return f.rows, nil
}

type fakeScanner struct {
	verdict scan.Result
	err     error
	calls   int
}

func (s *fakeScanner) Scan(_ context.Context, r io.Reader) (scan.Result, error) {
	s.calls++
	_, _ = io.Copy(io.Discard, r)
	return s.verdict, s.err
}

func newIntake(t *testing.T, h *harness, sc scan.Scanner, mode scan.Mode) *Intaker {
	t.Helper()
	in, err := NewIntaker(IntakeOptions{Root: h.root, Cells: h.cells, Cabinet: h.cabinet, ServerRoot: "/srv/files", Meta: h.meta, Scanner: sc, ScanMode: mode, Settle: time.Nanosecond, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// poll runs PollOnce twice: the first pass records (size, mtime), the
// second finds them unchanged and ingests. Results of both are merged.
func poll(t *testing.T, in *Intaker) Result {
	t.Helper()
	var merged Result
	for i := 0; i < 2; i++ {
		r, err := in.PollOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		merged.Accepted = append(merged.Accepted, r.Accepted...)
		merged.Rejected = append(merged.Rejected, r.Rejected...)
		merged.Held = append(merged.Held, r.Held...)
	}
	return merged
}

func drop(t *testing.T, in *Intaker, cell, machine, name string, body []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(in.ReturnDir(cell, machine), name), body, 0o660); err != nil {
		t.Fatal(err)
	}
}

func TestIntakeAcceptsAndMarks(t *testing.T) {
	h := newHarness(t)
	sc := &fakeScanner{verdict: scan.Result{Clean: true}}
	in := newIntake(t, h, sc, scan.ModeRequired)
	ctx := context.Background()
	// Release first so matches_release can be computed.
	if _, err := h.rel.Release(ctx, h.req("cell-a", cmmcmark.MarkBasic)); err != nil {
		t.Fatal(err)
	}
	released, _ := afero.ReadFile(h.src, "/Operations_CUI/NC/O1001.nc")
	drop(t, in, "cell-a", "cnc-a1", "O1001.nc", released)
	drop(t, in, "cell-a", "cnc-a1", "O1001-edited.nc", append(released, []byte("(EDITED)\n")...))
	h.mem.Reset()

	res := poll(t, in)
	if len(res.Accepted) != 2 || len(res.Rejected) != 0 || len(res.Held) != 0 {
		t.Fatalf("res=%+v", res)
	}
	if sc.calls != 2 {
		t.Fatalf("scanner calls = %d", sc.calls)
	}
	// Filed through the cabinet Fs, under return_path/<machine>.
	got, err := afero.ReadFile(h.cabinet, "/Operations_CUI/NC/cell-a/return/cnc-a1/O1001.nc")
	if err != nil || !bytes.Equal(got, released) {
		t.Fatalf("cabinet copy: %v", err)
	}
	// Marked with the cell designation, keyed on the server-absolute path.
	row := h.meta.rows["/srv/files/Operations_CUI/NC/cell-a/return/cnc-a1/O1001.nc"]
	if row == nil || row.Mark != cmmcmark.MarkBasic || row.SHA256 == "" || !strings.HasPrefix(row.Source, "ot-intake:") {
		t.Fatalf("marking row: %+v", row)
	}
	// Share side is empty; quarantine/pending is empty.
	if entries, _ := os.ReadDir(in.ReturnDir("cell-a", "cnc-a1")); len(entries) != 0 {
		t.Fatal("return dir not drained")
	}
	if entries, _ := os.ReadDir(filepath.Join(h.root, "quarantine", "pending", "cell-a")); len(entries) != 0 {
		t.Fatal("pending not cleaned")
	}
	// Audit: two accepts, matches_release true for the unmodified one.
	var matched, unmatched int
	for _, e := range h.mem.Events() {
		if e.Action != audit.ActionOTIntake {
			t.Fatalf("unexpected event %s", e.Action)
		}
		if e.Extra["matches_release"] == true {
			matched++
		} else {
			unmatched++
		}
	}
	if matched != 1 || unmatched != 1 {
		t.Fatalf("matches_release: matched=%d unmatched=%d", matched, unmatched)
	}
}

func TestIntakeNeverOverwrites(t *testing.T) {
	h := newHarness(t)
	in := newIntake(t, h, &fakeScanner{verdict: scan.Result{Clean: true}}, scan.ModeRequired)
	for i := 0; i < 3; i++ {
		drop(t, in, "cell-a", "cnc-a1", "O1.nc", []byte("O1 v"+string(rune('0'+i))+"\n"))
		if r := poll(t, in); len(r.Accepted) != 1 {
			t.Fatalf("round %d: %+v", i, r)
		}
	}
	for _, want := range []string{"O1.nc", "O1-1.nc", "O1-2.nc"} {
		if _, err := h.cabinet.Stat("/Operations_CUI/NC/cell-a/return/cnc-a1/" + want); err != nil {
			t.Fatalf("missing %s", want)
		}
	}
}

func TestIntakeRejectsGateAndMalware(t *testing.T) {
	h := newHarness(t)
	sc := &fakeScanner{verdict: scan.Result{Clean: false, Signature: "Eicar-Test-Signature"}}
	in := newIntake(t, h, sc, scan.ModeRequired)
	drop(t, in, "cell-a", "cnc-a1", "tool.exe", []byte("MZ...."))
	drop(t, in, "cell-a", "cnc-a1", "O9.nc", []byte("O9 G0\n"))
	res := poll(t, in)
	if len(res.Rejected) != 2 || len(res.Accepted) != 0 {
		t.Fatalf("res=%+v", res)
	}
	if sc.calls != 1 {
		t.Fatalf("scanner should run only for the gate-passing file; calls=%d", sc.calls)
	}
	rej, _ := os.ReadDir(filepath.Join(h.root, "quarantine", "rejected", "cell-a"))
	var files, reasons, metas int
	for _, e := range rej {
		switch {
		case strings.HasSuffix(e.Name(), ".reason"):
			reasons++
		case strings.HasSuffix(e.Name(), ".meta.json"):
			metas++
		default:
			files++
		}
	}
	if files != 2 || reasons != 2 || metas != 2 {
		t.Fatalf("rejected dir: files=%d reasons=%d metas=%d", files, reasons, metas)
	}
	var reject int
	for _, e := range h.mem.Events() {
		if e.Action == audit.ActionOTIntakeReject && e.Reason != "" {
			reject++
		}
	}
	if reject != 2 {
		t.Fatalf("reject events = %d", reject)
	}
	if _, err := h.cabinet.Stat("/Operations_CUI/NC/cell-a/return/cnc-a1/O9.nc"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("malware filed into cabinet")
	}
}

func TestIntakeQuotaChargedOnlyOnSuccess(t *testing.T) {
	h := newHarness(t)
	h.cells.Cells[0].DailyQuotaPerMachine = 1
	sc := &fakeScanner{verdict: scan.Result{Clean: false, Signature: "X"}}
	in := newIntake(t, h, sc, scan.ModeRequired)
	drop(t, in, "cell-a", "cnc-a1", "bad.nc", []byte("bad\n"))
	if r := poll(t, in); len(r.Rejected) != 1 {
		t.Fatalf("%+v", r)
	}
	sc.verdict = scan.Result{Clean: true}
	drop(t, in, "cell-a", "cnc-a1", "good.nc", []byte("good\n"))
	if r := poll(t, in); len(r.Accepted) != 1 {
		t.Fatalf("reject consumed quota: %+v", r)
	}
}

func TestIntakeHoldsWhenScannerDownInRequiredMode(t *testing.T) {
	h := newHarness(t)
	sc := &fakeScanner{err: errors.New("clamd: connection refused")}
	in := newIntake(t, h, sc, scan.ModeRequired)
	drop(t, in, "cell-a", "cnc-a1", "O5.nc", []byte("O5\n"))
	res := poll(t, in)
	if len(res.Held) < 1 || len(res.Rejected) != 0 || len(res.Accepted) != 0 {
		t.Fatalf("res=%+v", res)
	}
	pending, _ := os.ReadDir(filepath.Join(h.root, "quarantine", "pending", "cell-a"))
	if len(pending) != 2 { // snapshot + .meta.json
		t.Fatalf("held file should stay in pending; got %d entries", len(pending))
	}
	if _, err := h.cabinet.Stat("/Operations_CUI/NC/cell-a/return/cnc-a1/O5.nc"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unscanned file filed into cabinet")
	}
	// Scanner recovers → the held snapshot is retried and filed, and
	// the return dir was already drained (no re-snapshot).
	sc.err = nil
	sc.verdict = scan.Result{Clean: true}
	r2, _ := in.PollOnce(context.Background())
	if len(r2.Accepted) != 1 || len(r2.Held) != 0 {
		t.Fatalf("retry: %+v", r2)
	}
	if _, err := h.cabinet.Stat("/Operations_CUI/NC/cell-a/return/cnc-a1/O5.nc"); err != nil {
		t.Fatal("retried file not filed")
	}
	if pending, _ = os.ReadDir(filepath.Join(h.root, "quarantine", "pending", "cell-a")); len(pending) != 0 {
		t.Fatalf("pending not cleaned after retry: %d", len(pending))
	}
	if _, err := NewIntaker(IntakeOptions{Root: h.root, Cells: h.cells, Cabinet: h.cabinet, Meta: h.meta, ScanMode: scan.ModeRequired}); !errors.Is(err, ErrScannerUnavailable) {
		t.Fatalf("required mode without scanner must refuse: %v", err)
	}
}

func TestIntakeQuotaAndSettle(t *testing.T) {
	h := newHarness(t)
	h.cells.Cells[0].DailyQuotaPerMachine = 1
	in := newIntake(t, h, &fakeScanner{verdict: scan.Result{Clean: true}}, scan.ModeOptional)
	drop(t, in, "cell-a", "cnc-a1", "A.nc", []byte("A\n"))
	drop(t, in, "cell-a", "cnc-a1", "B.nc", []byte("B\n"))
	res := poll(t, in)
	if len(res.Accepted) != 1 || len(res.Rejected) != 1 {
		t.Fatalf("quota: %+v", res)
	}
	// A file younger than the settle window is left alone even when
	// stable across polls.
	in.settle = time.Hour
	drop(t, in, "cell-a", "cnc-a1", "C.nc", []byte("C\n"))
	res = poll(t, in)
	if len(res.Accepted)+len(res.Rejected)+len(res.Held) != 0 {
		t.Fatalf("settle window ignored: %+v", res)
	}
	// A file still growing between polls is left alone.
	in.settle = time.Nanosecond
	drop(t, in, "cell-a", "cnc-a1", "D.nc", []byte("D1\n"))
	_, _ = in.PollOnce(context.Background())
	drop(t, in, "cell-a", "cnc-a1", "D.nc", []byte("D1\nD2\n"))
	r, _ := in.PollOnce(context.Background())
	if len(r.Accepted)+len(r.Rejected)+len(r.Held) != 0 {
		t.Fatalf("growing file ingested: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(in.ReturnDir("cell-a", "cnc-a1"), "D.nc")); err != nil {
		t.Fatal("growing file removed from share")
	}
}

// --- config ----------------------------------------------------------

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv(EnvMode, "")
	if c, err := LoadConfigFromEnv(); err != nil || c.Mode != ModeDisabled {
		t.Fatalf("unset: %+v %v", c, err)
	}
	t.Setenv(EnvMode, "required")
	t.Setenv(EnvCells, filepath.Join(t.TempDir(), "missing.yaml"))
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("required without cells file must fail")
	}
	p := filepath.Join(t.TempDir(), "cells.yaml")
	_ = os.WriteFile(p, []byte(fixtureCells), 0o600)
	t.Setenv(EnvCells, p)
	t.Setenv(EnvPoll, "30")
	c, err := LoadConfigFromEnv()
	if err != nil || c.Mode != ModeRequired || c.PollInterval != 30*time.Second || c.Root != DefaultRoot {
		t.Fatalf("required: %+v %v", c, err)
	}
	t.Setenv(EnvPoll, "1")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("poll < 5 must fail")
	}
	t.Setenv(EnvPoll, "")
	t.Setenv(EnvMode, "optional")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("optional is not a mode")
	}
}

func TestIntakeRefusesSymlinksAndNonRegular(t *testing.T) {
	h := newHarness(t)
	in := newIntake(t, h, &fakeScanner{verdict: scan.Result{Clean: true}}, scan.ModeRequired)
	// A "machine" plants a symlink to a file the service user can read.
	secret := filepath.Join(h.root, "secret.txt")
	_ = os.WriteFile(secret, []byte("KEK-ish material\n"), 0o600)
	link := filepath.Join(in.ReturnDir("cell-a", "cnc-a1"), "grab.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	res := poll(t, in)
	if len(res.Accepted) != 0 {
		t.Fatalf("symlink was ingested: %+v", res)
	}
	if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("symlink left on the share")
	}
	if _, err := h.cabinet.Stat("/Operations_CUI/NC/cell-a/return/cnc-a1/grab.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("symlink target reached the cabinet")
	}
	var rejected bool
	for _, e := range h.mem.Events() {
		if e.Action == audit.ActionOTIntakeReject && strings.Contains(e.Reason, "not a regular file") {
			rejected = true
		}
	}
	if !rejected {
		t.Fatal("no reject audit event for the symlink")
	}
	// copyRegularNoFollow itself refuses a symlink even if handed one.
	_ = os.Symlink(secret, link)
	if err := copyRegularNoFollow(link, filepath.Join(h.root, "out.txt")); err == nil {
		t.Fatal("O_NOFOLLOW copy followed a symlink")
	}
}

func TestManagerSaveReloads(t *testing.T) {
	h := newHarness(t)
	in := newIntake(t, h, &fakeScanner{verdict: scan.Result{Clean: true}}, scan.ModeRequired)
	p := filepath.Join(h.root, "cells.yaml")
	_ = os.WriteFile(p, []byte(fixtureCells), 0o640)
	m := NewManager(p, h.cells, h.rel, in)
	proposed := &Cells{Cells: append([]Cell(nil), h.cells.Cells...)}
	proposed.Cells[0].Machines = append(proposed.Cells[0].Machines, Machine{Name: "cnc-a9", IP: "10.20.1.99", Dialect: DialectSMB3, Auth: AuthPassword})
	proposed.Cells = append(proposed.Cells, Cell{Name: "cell-new", Mark: cmmcmark.MarkBasic, ReturnPath: "/Operations_CUI/NC/cell-new/return", PDSAttested: true, Machines: []Machine{{Name: "cnc-n1", IP: "10.20.5.1", Dialect: DialectSMB2}}})
	saved, err := m.Save(context.Background(), proposed, time.Time{}, ReleaseRequest{ReleasedBy: "dana", UserID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Cells) != 3 {
		t.Fatalf("cells = %d", len(saved.Cells))
	}
	for _, d := range []string{filepath.Join(h.root, "return", "cell-a", "cnc-a9"), filepath.Join(h.root, "return", "cell-new", "cnc-n1"), filepath.Join(h.root, "out", "cell-new"), filepath.Join(h.root, "state", "out", "cell-new")} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			t.Fatalf("missing dir after reload: %s", d)
		}
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "cnc-a9") || !strings.Contains(string(raw), "cell-new") {
		t.Fatalf("file not rewritten:\n%s", raw)
	}
	if _, err := ParseCells(raw); err != nil {
		t.Fatalf("written file does not parse: %v", err)
	}
	// The releaser sees the new cell; an invalid proposal changes nothing.
	if _, ok := h.rel.cellsSnapshot().Get("cell-new"); !ok {
		t.Fatal("releaser not reloaded")
	}
	bad, _ := ParseCells(raw) // fresh copy; slices in saved must not be mutated
	bad.Cells[0].Machines[0].IP = "10.20.5.1" // duplicate of cnc-n1
	if _, err := m.Save(context.Background(), bad, time.Time{}, ReleaseRequest{}); !errors.Is(err, ErrInvalidCells) {
		t.Fatalf("invalid save accepted: %v", err)
	}
	if len(m.Cells().Cells) != 3 {
		t.Fatal("invalid save changed state")
	}
	// Stale-mtime conflict.
	fresh, _ := ParseCells(raw)
	if _, err := m.Save(context.Background(), fresh, time.Unix(1, 0), ReleaseRequest{}); !errors.Is(err, ErrInventoryConflict) {
		t.Fatalf("stale write accepted: %v", err)
	}
	// Audit.
	var n int
	for _, e := range h.mem.Events() {
		if e.Action == audit.ActionOTInventorySet {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("inventory audit events = %d", n)
	}
}
