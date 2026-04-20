package cabinet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

// fakeStore is a minimal in-memory cmmcmark.Store just for the seed
// path — Seed only calls Get + Put.
type fakeStore struct {
	rows map[string]*cmmcmark.FileMetadata
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: map[string]*cmmcmark.FileMetadata{}}
}
func (f *fakeStore) Get(p string) (*cmmcmark.FileMetadata, error) {
	if v, ok := f.rows[p]; ok {
		return v, nil
	}
	return nil, fberrors.ErrNotExist
}
func (f *fakeStore) GetEffective(p string) (*cmmcmark.FileMetadata, error) {
	return f.Get(p)
}
func (f *fakeStore) HasCUIDescendants(p string) (bool, error) {
	prefix := strings.TrimSuffix(p, "/") + "/"
	for k, v := range f.rows {
		if strings.HasPrefix(k, prefix) && v.Mark.IsCUI() {
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeStore) Put(md *cmmcmark.FileMetadata) error {
	f.rows[md.Path] = md
	return nil
}
func (f *fakeStore) Delete(p string) error                    { delete(f.rows, p); return nil }
func (f *fakeStore) Rename(_, _ string) error                 { return nil }
func (f *fakeStore) Copy(_, _, _ string) error                { return nil }
func (f *fakeStore) DeleteByOwnerID(_ uint) error             { return nil }
func (f *fakeStore) GetMany(_ []string) (map[string]*cmmcmark.FileMetadata, error) {
	return nil, nil
}
func (f *fakeStore) GetManyEffective(_ []string) (map[string]*cmmcmark.FileMetadata, error) {
	return nil, nil
}

func TestSeed_CreatesDirsAndMarks(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()

	dirs, marks, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if dirs != len(DefaultLayout) {
		t.Errorf("dirs created = %d, want %d", dirs, len(DefaultLayout))
	}
	// Count CUI rows in DefaultLayout — that's how many marks we
	// expect to be seeded (non-CUI folders don't get a row).
	wantMarks := 0
	for _, f := range DefaultLayout {
		if f.Mark.IsCUI() {
			wantMarks++
		}
	}
	if marks != wantMarks {
		t.Errorf("marks written = %d, want %d", marks, wantMarks)
	}

	// Every expected dir exists on disk.
	for _, f := range DefaultLayout {
		if _, err := os.Stat(filepath.Join(root, f.Name)); err != nil {
			t.Errorf("dir %q not created: %v", f.Name, err)
		}
	}
	// Every CUI folder has a marking row.
	for _, f := range DefaultLayout {
		if !f.Mark.IsCUI() {
			continue
		}
		got, err := store.Get(filepath.Join(root, f.Name))
		if err != nil {
			t.Errorf("no row for %q: %v", f.Name, err)
			continue
		}
		if got.Mark != f.Mark {
			t.Errorf("%s mark = %q, want %q", f.Name, got.Mark, f.Mark)
		}
		if got.Source != "cabinet:bootstrap" {
			t.Errorf("%s source = %q, want bootstrap annotation", f.Name, got.Source)
		}
	}
}

func TestSeed_Idempotent(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()

	// First run — seeds everything.
	_, _, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// Second run — zero new dirs, zero new marks.
	dirs, marks, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if dirs != 0 || marks != 0 {
		t.Errorf("re-seed wrote dirs=%d marks=%d, want 0/0", dirs, marks)
	}
}

func TestSeed_PreservesOperatorCustomization(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()

	// Seed once.
	_, _, _ = Seed(root, store, DefaultLayout)
	// Operator upgrades one folder's classification after seed.
	engPath := filepath.Join(root, "Engineering_CUI")
	store.rows[engPath].Mark = cmmcmark.MarkITAR
	store.rows[engPath].Source = "admin:7"
	store.rows[engPath].ModifiedAt = time.Now()

	// Re-run Seed. Operator's change MUST survive.
	_, _, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	got := store.rows[engPath]
	if got.Mark != cmmcmark.MarkITAR {
		t.Errorf("operator customization overwritten: mark = %q", got.Mark)
	}
	if got.Source != "admin:7" {
		t.Errorf("operator Source overwritten: %q", got.Source)
	}
}

func TestSeed_EmptyRootRejected(t *testing.T) {
	if _, _, err := Seed("", newFakeStore(), DefaultLayout); err == nil {
		t.Error("empty root should error")
	}
}

func TestSeed_NilStoreStillCreatesDirs(t *testing.T) {
	root := t.TempDir()
	// A deployment that turned off the bolt backend for some
	// reason should still get its folder tree on disk.
	dirs, marks, err := Seed(root, nil, DefaultLayout)
	if err != nil {
		t.Fatalf("seed with nil store: %v", err)
	}
	if dirs != len(DefaultLayout) {
		t.Errorf("dirs = %d, want %d", dirs, len(DefaultLayout))
	}
	if marks != 0 {
		t.Errorf("marks = %d, want 0 (no store to write to)", marks)
	}
}

func TestGroupRules_AdminSeesEverything(t *testing.T) {
	rules := GroupRules(
		[]string{"filebrowser-admins", "compliance"},
		[]string{"filebrowser-admins"},
		DefaultLayout,
	)
	if rules != nil {
		t.Errorf("admin must have nil rules; got %+v", rules)
	}
}

func TestGroupRules_EngineerDeniedOtherDrawers(t *testing.T) {
	rules := GroupRules(
		[]string{"engineering"},
		[]string{"filebrowser-admins"},
		DefaultLayout,
	)
	// Engineer must SEE Engineering, Engineering_CUI.
	// Engineer must NOT SEE Sales, Sales_CUI, Operations,
	// Operations_CUI, Management, ITAR.
	mustDeny := map[string]bool{
		"/Sales": true, "/Sales_CUI": true,
		"/Operations": true, "/Operations_CUI": true,
		"/Management": true, "/ITAR": true,
	}
	mustAllow := map[string]bool{
		"/Engineering": true, "/Engineering_CUI": true,
	}
	gotDenies := map[string]bool{}
	for _, r := range rules {
		if r.Allow {
			t.Errorf("unexpected allow-rule: %+v", r)
		}
		gotDenies[r.Path] = true
	}
	for p := range mustDeny {
		if !gotDenies[p] {
			t.Errorf("expected deny rule for %q", p)
		}
	}
	for p := range mustAllow {
		if gotDenies[p] {
			t.Errorf("unexpected deny rule on allowed path %q", p)
		}
	}
}

func TestGroupRules_UserInMultipleGroupsGetsUnion(t *testing.T) {
	// A user in both engineering and sales should see both drawer
	// pairs — rule list excludes both sets.
	rules := GroupRules(
		[]string{"engineering", "sales"},
		[]string{"filebrowser-admins"},
		DefaultLayout,
	)
	for _, r := range rules {
		if r.Path == "/Engineering" || r.Path == "/Sales" ||
			r.Path == "/Engineering_CUI" || r.Path == "/Sales_CUI" {
			t.Errorf("user in both groups should see %q, got deny", r.Path)
		}
	}
}

func TestGroupRules_EmptyGroups_DeniesEveryGroupOwnedFolder(t *testing.T) {
	// An unaffiliated user (no group membership) gets deny rules for
	// every group-owned folder in DefaultLayout. The starter layout
	// no longer has an "everyone" Public drawer; a bare-metal user
	// sees nothing until admin adds them to a group.
	rules := GroupRules([]string{}, []string{"filebrowser-admins"}, DefaultLayout)
	if len(rules) == 0 {
		t.Errorf("expected deny rules for all group-owned folders, got 0")
	}
	for _, r := range rules {
		if r.Allow {
			t.Errorf("unaffiliated user should not have any allow rule: %+v", r)
		}
	}
}

// Compile-time guard: fakeStore must satisfy cmmcmark.Store. Catches
// any drift in the interface.
var _ cmmcmark.Store = (*fakeStore)(nil)

var _ error = errors.New("compile-time ref to errors package")

// TestSeed_PreservesOperatorDeclassify pins the hazard called out
// by the review agent: if an admin deletes a folder-level mark row
// to declassify the drawer, a subsequent Seed must NOT rewrite it.
// Without the seed marker this reverted on every restart — a
// CMMC 3.8.3 operator-intent failure.
func TestSeed_PreservesOperatorDeclassify(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()

	// First boot: seeds everything.
	_, _, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// Admin declassifies Engineering_CUI.
	engPath := filepath.Join(root, "Engineering_CUI")
	delete(store.rows, engPath)
	if _, err := store.Get(engPath); err == nil {
		t.Fatal("precondition: row should be gone after delete")
	}

	// Second boot MUST NOT rewrite the row.
	_, marks, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if marks != 0 {
		t.Errorf("reboot wrote %d marks; operator declassify was reverted", marks)
	}
	if _, err := store.Get(engPath); err == nil {
		t.Errorf("Engineering_CUI row resurrected after declassify")
	}
}

// TestSeed_MarkerPlantedOnFirstBoot pins the marker-is-present
// invariant so a regression to the old "Get-missing-means-rewrite"
// behavior fails fast.
func TestSeed_MarkerPlantedOnFirstBoot(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()
	if _, _, err := Seed(root, store, DefaultLayout); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.Get(seedMarkerPath); err != nil {
		t.Errorf("seed marker not planted: %v", err)
	}
}

// TestSeed_CrashRecovery — if Seed fails partway through (e.g.,
// store Put returns an error), the marker must NOT be written so
// the next boot retries. We can't easily inject a mid-flight error
// with the fake store; approximate via a "marker missing → rewrites"
// observation. If the marker is absent at boot time, the second
// run must still go through the mark-write phase.
func TestSeed_MarkerMissing_RewritesMarks(t *testing.T) {
	root := t.TempDir()
	store := newFakeStore()
	if _, _, err := Seed(root, store, DefaultLayout); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// Simulate a crash-after-marks-before-marker: delete the marker.
	delete(store.rows, seedMarkerPath)
	// Also clear one row to show it gets rewritten.
	engPath := filepath.Join(root, "Engineering_CUI")
	delete(store.rows, engPath)

	_, marks, err := Seed(root, store, DefaultLayout)
	if err != nil {
		t.Fatalf("retry seed: %v", err)
	}
	if marks == 0 {
		t.Error("marker-missing retry should rewrite marks")
	}
	if _, err := store.Get(engPath); err != nil {
		t.Errorf("Engineering_CUI not re-seeded after marker loss: %v", err)
	}
}

// TestGroupRules_AdminCheck_CaseInsensitive pins the case-folding
// fix: a Keycloak rename from "filebrowser-admins" to
// "Filebrowser-Admins" must not silently demote admins.
func TestGroupRules_AdminCheck_CaseInsensitive(t *testing.T) {
	// adminGroups config uses lowercase; user's token carries mixed case.
	rules := GroupRules(
		[]string{"Filebrowser-Admins"},
		[]string{"filebrowser-admins"},
		DefaultLayout,
	)
	if rules != nil {
		t.Errorf("mixed-case admin-group should still be admin; got %+v", rules)
	}
	// Inverse: config mixed-case, user lowercase.
	rules = GroupRules(
		[]string{"filebrowser-admins"},
		[]string{"Filebrowser-Admins"},
		DefaultLayout,
	)
	if rules != nil {
		t.Errorf("inverse-case admin-group should still be admin; got %+v", rules)
	}
}
