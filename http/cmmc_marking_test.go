package fbhttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asdine/storm/v3"
	"github.com/spf13/afero"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	"github.com/filebrowser/filebrowser/v2/files"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	boltstore "github.com/filebrowser/filebrowser/v2/storage/bolt"
	"github.com/filebrowser/filebrowser/v2/users"
)

func newOIDCSettings() *settings.Settings {
	return &settings.Settings{AuthMethod: fbAuth.MethodOIDCAuth, Key: []byte("test-key-16byt")}
}
func newJSONSettings() *settings.Settings {
	return &settings.Settings{AuthMethod: fbAuth.MethodJSONAuth, Key: []byte("test-key-16byt")}
}

// newTestData builds a *data whose user has a real afero.BasePathFs
// rooted at a tempdir, so FullPath resolves to stable absolute paths.
func newTestData(t *testing.T, admin bool) *data {
	t.Helper()
	dir := t.TempDir()
	db, err := storm.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	scopeRoot := filepath.Join(dir, "srv", "alice")
	if err := afero.NewOsFs().MkdirAll(scopeRoot, 0o755); err != nil {
		t.Fatalf("mkscope: %v", err)
	}
	u := &users.User{
		ID:    42,
		Scope: ".",
		Perm:  users.Permissions{Admin: admin},
		Fs:    afero.NewBasePathFs(afero.NewOsFs(), scopeRoot),
	}
	return &data{
		store: &storage.Storage{
			FileMetadata: boltstore.NewMarkingBackend(db),
			GroupPerms:   boltstore.NewGroupPermBackend(db),
			FolderACLs:   boltstore.NewFolderACLBackend(db),
		},
		user: u,
	}
}

func TestAbsPathForUser(t *testing.T) {
	d := newTestData(t, false)
	// Resolve a known-good path to capture the scope prefix FullPath uses,
	// so remaining assertions don't have to hard-code tempdir paths.
	scopePrefix, err := absPathForUser(d, "/")
	if err != nil {
		t.Fatalf("baseline resolve: %v", err)
	}
	// Round-trip cases: leading-slash and bare-name must resolve to the
	// same path; every result must sit under the user's scope.
	good := []string{"/foo.pdf", "foo.pdf", "/a/b/c.pdf"}
	for _, in := range good {
		got, err := absPathForUser(d, in)
		if err != nil {
			t.Errorf("in=%q unexpected err: %v", in, err)
			continue
		}
		if !strings.HasPrefix(got, scopePrefix) {
			t.Errorf("in=%q got %q, not under scope %q", in, got, scopePrefix)
		}
	}
	if first, _ := absPathForUser(d, "/foo.pdf"); first != d.user.FullPath("/foo.pdf") {
		t.Errorf("absPathForUser must equal user.FullPath for same input")
	}
	// Error cases.
	for _, bad := range []string{"", "../../../etc/passwd", "/a/../../b"} {
		if _, err := absPathForUser(d, bad); err == nil {
			t.Errorf("in=%q wanted error", bad)
		}
	}
}

func TestMarkingGetFn_MissingRow_ReturnsEmptyMark(t *testing.T) {
	d := newTestData(t, true)
	req := httptest.NewRequest("GET", "/api/cmmc/marking?path=/missing.pdf", nil)
	rec := httptest.NewRecorder()
	status, err := markingGetFn(rec, req, d)
	if err != nil || status != 0 {
		t.Fatalf("status=%d err=%v", status, err)
	}
	var body map[string]interface{}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["mark"] != "" {
		t.Errorf("expected empty mark, got %v", body["mark"])
	}
}

func TestMarkingGetFn_RoundTripAfterPut(t *testing.T) {
	d := newTestData(t, true)
	// Seed via PUT.
	putReq := httptest.NewRequest("PUT", "/api/cmmc/marking",
		bytes.NewReader([]byte(`{"path":"/doc.pdf","mark":"CUI//BASIC"}`)))
	putRec := httptest.NewRecorder()
	if status, err := markingPutFn(putRec, putReq, d); err != nil || status != 0 {
		t.Fatalf("put status=%d err=%v", status, err)
	}
	// GET.
	getReq := httptest.NewRequest("GET", "/api/cmmc/marking?path=/doc.pdf", nil)
	getRec := httptest.NewRecorder()
	if status, err := markingGetFn(getRec, getReq, d); err != nil || status != 0 {
		t.Fatalf("get status=%d err=%v", status, err)
	}
	var body map[string]interface{}
	_ = json.NewDecoder(getRec.Body).Decode(&body)
	if body["mark"] != string(cmmcmark.MarkBasic) {
		t.Errorf("got mark=%v want %q", body["mark"], cmmcmark.MarkBasic)
	}
	if body["source"] != "admin:42" {
		t.Errorf("got source=%v want admin:42", body["source"])
	}
}

func TestMarkingPutFn_UnknownMark_Rejected(t *testing.T) {
	d := newTestData(t, true)
	req := httptest.NewRequest("PUT", "/api/cmmc/marking",
		bytes.NewReader([]byte(`{"path":"/doc.pdf","mark":"CUI//MADE-UP"}`)))
	rec := httptest.NewRecorder()
	status, err := markingPutFn(rec, req, d)
	if status != http.StatusBadRequest {
		t.Errorf("status=%d want 400, err=%v", status, err)
	}
}

func TestMarkingPutFn_EmptyMark_ClearsRow(t *testing.T) {
	d := newTestData(t, true)
	// Seed a row at the path the handler will compute.
	abs, err := absPathForUser(d, "/doc.pdf")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := d.store.FileMetadata.Put(&cmmcmark.FileMetadata{
		Path: abs,
		Mark: cmmcmark.MarkBasic,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// PUT with empty mark + reason clears. Reason is mandatory on
	// declassify per CMMC 3.8.3.
	req := httptest.NewRequest("PUT", "/api/cmmc/marking",
		bytes.NewReader([]byte(`{"path":"/doc.pdf","mark":"","reason":"marked in error"}`)))
	rec := httptest.NewRecorder()
	if status, err := markingPutFn(rec, req, d); err != nil || status != 0 {
		t.Fatalf("clear status=%d err=%v", status, err)
	}
	// Row is gone.
	getReq := httptest.NewRequest("GET", "/api/cmmc/marking?path=/doc.pdf", nil)
	getRec := httptest.NewRecorder()
	_, _ = markingGetFn(getRec, getReq, d)
	var body map[string]interface{}
	_ = json.NewDecoder(getRec.Body).Decode(&body)
	if body["mark"] != "" {
		t.Errorf("row not cleared; mark=%v", body["mark"])
	}
}

func TestMarkingPutFn_PathEscape_Rejected(t *testing.T) {
	d := newTestData(t, true)
	req := httptest.NewRequest("PUT", "/api/cmmc/marking",
		bytes.NewReader([]byte(`{"path":"../../../etc/passwd","mark":"CUI//BASIC"}`)))
	rec := httptest.NewRecorder()
	status, _ := markingPutFn(rec, req, d)
	if status != http.StatusBadRequest {
		t.Errorf("path escape not rejected; status=%d", status)
	}
}

func TestMarkingCatalogFn_ReturnsStarterSet(t *testing.T) {
	d := newTestData(t, false)
	req := httptest.NewRequest("GET", "/api/cmmc/marking/catalog", nil)
	rec := httptest.NewRecorder()
	if status, err := markingCatalogFn(rec, req, d); err != nil || status != 0 {
		t.Fatalf("status=%d err=%v", status, err)
	}
	var body struct{ Marks []string }
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Marks) < 6 {
		t.Errorf("expected at least 6 marks, got %d", len(body.Marks))
	}
}

// TestAttachMarksToListing_PopulatesChildMarks exercises the directory
// listing enrichment path that pins the CuiBadge feature. A regression
// here looks like "all files unmarked in the UI" even though they are
// CUI in the store — a CMMC 3.8.4 observability failure.
func TestAttachMarksToListing_PopulatesChildMarks(t *testing.T) {
	d := newTestData(t, true)

	// Seed two marked children in the user's scope.
	a, _ := absPathForUser(d, "/a.pdf")
	b, _ := absPathForUser(d, "/b.pdf")
	if err := d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: a, Mark: cmmcmark.MarkBasic, OwnerID: 42}); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if err := d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: b, Mark: cmmcmark.MarkITAR, OwnerID: 42}); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	// Minimal FileInfo graph — mirror what resourceGetHandler passes in.
	file := &files.FileInfo{
		Path: "/", IsDir: true,
		Listing: &files.Listing{Items: []*files.FileInfo{
			{Path: "/a.pdf", Name: "a.pdf"},
			{Path: "/b.pdf", Name: "b.pdf"},
			{Path: "/c.pdf", Name: "c.pdf"}, // no mark in store
		}},
	}

	attachMarksToListing(d, file)

	marks := map[string]string{}
	for _, it := range file.Items {
		marks[it.Name] = it.Mark
	}
	if marks["a.pdf"] != string(cmmcmark.MarkBasic) {
		t.Errorf("a.pdf mark = %q, want %q", marks["a.pdf"], cmmcmark.MarkBasic)
	}
	if marks["b.pdf"] != string(cmmcmark.MarkITAR) {
		t.Errorf("b.pdf mark = %q, want %q", marks["b.pdf"], cmmcmark.MarkITAR)
	}
	if marks["c.pdf"] != "" {
		t.Errorf("c.pdf mark = %q, want empty (no row)", marks["c.pdf"])
	}
}

// TestAttachMarksToListing_NoStore_IsNoop — a deployment that hasn't
// wired the marking backend must still render listings cleanly, not
// panic. Defensive; this also covers the first-boot window.
func TestAttachMarksToListing_NoStore_IsNoop(t *testing.T) {
	d := newTestData(t, true)
	d.store.FileMetadata = nil
	file := &files.FileInfo{
		Path: "/", IsDir: true,
		Listing: &files.Listing{Items: []*files.FileInfo{{Name: "x.pdf"}}},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked with nil store: %v", r)
		}
	}()
	attachMarksToListing(d, file)
	if file.Items[0].Mark != "" {
		t.Errorf("no store → mark should stay empty, got %q", file.Items[0].Mark)
	}
}

// --- C.4 folder-inheritance + move-rule + declassify-gate tests ---

// TestMarkingPutFn_Declassify_RefusesFolderWithCUIDescendants — the
// containment rule: unmarking a folder that still has CUI files
// underneath must 409. Otherwise a one-click downgrade leaks every
// nested CUI artifact.
func TestMarkingPutFn_Declassify_RefusesFolderWithCUIDescendants(t *testing.T) {
	d := newTestData(t, true)
	folderAbs, _ := absPathForUser(d, "/Engineering_CUI")
	fileAbs, _ := absPathForUser(d, "/Engineering_CUI/drawing.pdf")
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: folderAbs, Mark: cmmcmark.MarkBasic})
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: fileAbs, Mark: cmmcmark.MarkBasic})

	req := httptest.NewRequest("PUT", "/api/cmmc/marking",
		bytes.NewReader([]byte(`{"path":"/Engineering_CUI","mark":""}`)))
	rec := httptest.NewRecorder()
	status, err := markingPutFn(rec, req, d)
	if status != http.StatusConflict {
		t.Errorf("declassify with CUI descendants should 409; got %d err=%v", status, err)
	}
	// Folder row must survive — the refusal is the whole point.
	if _, err := d.store.FileMetadata.Get(folderAbs); err != nil {
		t.Errorf("folder row lost after failed declassify: %v", err)
	}
}

// TestMarkingPutFn_Declassify_AllowsEmptyUncontrolledFolder — the
// opposite side: a folder with no CUI descendants can be declassified
// freely (admin might have marked it by mistake, or moved everything).
func TestMarkingPutFn_Declassify_AllowsEmptyUncontrolledFolder(t *testing.T) {
	d := newTestData(t, true)
	folderAbs, _ := absPathForUser(d, "/Draft_CUI")
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: folderAbs, Mark: cmmcmark.MarkBasic})

	req := httptest.NewRequest("PUT", "/api/cmmc/marking",
		bytes.NewReader([]byte(`{"path":"/Draft_CUI","mark":"","reason":"folder emptied; decontrol approved"}`)))
	rec := httptest.NewRecorder()
	status, err := markingPutFn(rec, req, d)
	if err != nil || status != 0 {
		t.Errorf("empty folder declassify failed: status=%d err=%v", status, err)
	}
}

// TestMarkingPutFn_Declassify_RequiresReason — declassification must
// record a reason per CMMC 3.8.3 / DoDI 5200.48. An empty or
// whitespace-only reason field returns 400 so the operator can't
// accidentally produce an undocumented decontrol event.
func TestMarkingPutFn_Declassify_RequiresReason(t *testing.T) {
	d := newTestData(t, true)
	abs, _ := absPathForUser(d, "/stray.pdf")
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: abs, Mark: cmmcmark.MarkBasic})

	cases := []struct {
		name string
		body string
	}{
		{"reason missing", `{"path":"/stray.pdf","mark":""}`},
		{"reason empty", `{"path":"/stray.pdf","mark":"","reason":""}`},
		{"reason whitespace", `{"path":"/stray.pdf","mark":"","reason":"   \t  "}`},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/api/cmmc/marking", bytes.NewReader([]byte(c.body)))
			rec := httptest.NewRecorder()
			status, err := markingPutFn(rec, req, d)
			if status != http.StatusBadRequest {
				t.Errorf("status=%d, want 400 (err=%v)", status, err)
			}
		})
	}
}

// TestCuiMarkFor_UsesInheritanceFromParent — the hot-path enforcement
// lookup must see folder-level classification, not just file rows.
// A file uploaded into /Engineering_CUI/ with no explicit row must
// still read as CUI//BASIC.
func TestCuiMarkFor_UsesInheritanceFromParent(t *testing.T) {
	d := newTestData(t, false)
	parentAbs, _ := absPathForUser(d, "/Engineering_CUI")
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: parentAbs, Mark: cmmcmark.MarkBasic})

	mark, err := cuiMarkFor(d, "/Engineering_CUI/drawing.pdf")
	if err != nil {
		t.Fatalf("cuiMarkFor: %v", err)
	}
	if mark != cmmcmark.MarkBasic {
		t.Errorf("inheritance failed; got %q, want %q", mark, cmmcmark.MarkBasic)
	}
}

// TestEnforceCUIMoveRule_BlocksCUIToUncontrolled — the canonical
// prevention: CUI file cannot move to a non-CUI folder.
func TestEnforceCUIMoveRule_BlocksCUIToUncontrolled(t *testing.T) {
	d := newTestData(t, true)
	srcAbs, _ := absPathForUser(d, "/Engineering_CUI/drawing.pdf")
	engAbs, _ := absPathForUser(d, "/Engineering_CUI")
	// Source is CUI via inheritance from parent folder.
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: engAbs, Mark: cmmcmark.MarkBasic})
	_ = srcAbs // srcAbs used via the user-relative path in the rule

	r := httptest.NewRequest("PATCH", "/api/resources/foo", nil)
	status, reason := enforceCUIMoveRule(r, d, "/Engineering_CUI/drawing.pdf", "/Public/drawing.pdf")
	if status != http.StatusForbidden {
		t.Errorf("move CUI → Public must 403; got status=%d reason=%q", status, reason)
	}
	if reason == "" {
		t.Errorf("reason should be populated for audit trail")
	}
}

// TestEnforceCUIMoveRule_AllowsCUIToCUI — moves between two CUI
// folders pass (same restriction level or upgrade).
func TestEnforceCUIMoveRule_AllowsCUIToCUI(t *testing.T) {
	d := newTestData(t, true)
	engAbs, _ := absPathForUser(d, "/Engineering_CUI")
	itarAbs, _ := absPathForUser(d, "/ITAR")
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: engAbs, Mark: cmmcmark.MarkBasic})
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: itarAbs, Mark: cmmcmark.MarkITAR})

	r := httptest.NewRequest("PATCH", "/api/resources/foo", nil)
	status, _ := enforceCUIMoveRule(r, d, "/Engineering_CUI/drawing.pdf", "/ITAR/drawing.pdf")
	if status != 0 {
		t.Errorf("move CUI → CUI must pass; got status=%d", status)
	}
}

// TestEnforceCUIMoveRule_AllowsUncontrolledToAnywhere — a non-CUI
// file moving anywhere is not our concern. Pass.
func TestEnforceCUIMoveRule_AllowsUncontrolledToAnywhere(t *testing.T) {
	d := newTestData(t, true)
	r := httptest.NewRequest("PATCH", "/api/resources/foo", nil)
	status, _ := enforceCUIMoveRule(r, d, "/Public/foo.txt", "/Public/bar.txt")
	if status != 0 {
		t.Errorf("uncontrolled → uncontrolled must pass; got status=%d", status)
	}
}
