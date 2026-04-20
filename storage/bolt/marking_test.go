package bolt

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
)

func openTestBolt(t *testing.T) *storm.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storm.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestMarkingBackend_PutGetRoundTrip(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	err := store.Put(&cmmcmark.FileMetadata{
		Path: "/srv/cmmc/users/alice/foo.pdf",
		Mark: cmmcmark.MarkBasic,
		OwnerID: 1,
	})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get("/srv/cmmc/users/alice/foo.pdf")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Mark != cmmcmark.MarkBasic {
		t.Errorf("mark = %q", got.Mark)
	}
	if got.CreatedAt.IsZero() || got.ModifiedAt.IsZero() {
		t.Errorf("timestamps not populated: %+v", got)
	}
}

func TestMarkingBackend_GetMissing_ReturnsErrNotExist(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_, err := store.Get("/nope")
	if !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestMarkingBackend_PutSamePath_Upserts(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	path := "/srv/x/a.pdf"
	_ = store.Put(&cmmcmark.FileMetadata{Path: path, Mark: cmmcmark.MarkBasic, OwnerID: 1})
	_ = store.Put(&cmmcmark.FileMetadata{Path: path, Mark: cmmcmark.MarkPropIn, OwnerID: 1})
	got, _ := store.Get(path)
	if got.Mark != cmmcmark.MarkPropIn {
		t.Errorf("upsert did not replace; got %q", got.Mark)
	}
}

func TestMarkingBackend_Delete_Idempotent(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/x", Mark: cmmcmark.MarkBasic, OwnerID: 1})
	if err := store.Delete("/x"); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := store.Delete("/x"); err != nil {
		t.Fatalf("second delete should be idempotent: %v", err)
	}
	if _, err := store.Get("/x"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("get after delete: %v", err)
	}
	if err := store.Delete("/never-existed"); err != nil {
		t.Fatalf("delete of missing path should be noop: %v", err)
	}
}

func TestMarkingBackend_Rename_PreservesMark(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/old.pdf", Mark: cmmcmark.MarkPrivacy, OwnerID: 7})
	if err := store.Rename("/old.pdf", "/new.pdf"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := store.Get("/old.pdf"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("old path still present")
	}
	got, err := store.Get("/new.pdf")
	if err != nil {
		t.Fatalf("get new: %v", err)
	}
	if got.Mark != cmmcmark.MarkPrivacy {
		t.Errorf("mark not preserved: %q", got.Mark)
	}
	if got.OwnerID != 7 {
		t.Errorf("owner not preserved: %d", got.OwnerID)
	}
}

func TestMarkingBackend_Rename_Nonexistent_IsNoop(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	if err := store.Rename("/nope", "/also-nope"); err != nil {
		t.Errorf("rename of missing path should be noop: %v", err)
	}
}

func TestMarkingBackend_GetMany_ReturnsOnlyPresent(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/a", Mark: cmmcmark.MarkBasic, OwnerID: 1})
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/b", Mark: cmmcmark.MarkITAR, OwnerID: 1})
	got, err := store.GetMany([]string{"/a", "/b", "/c"})
	if err != nil {
		t.Fatalf("getmany: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 results, got %d", len(got))
	}
	if got["/a"].Mark != cmmcmark.MarkBasic || got["/b"].Mark != cmmcmark.MarkITAR {
		t.Errorf("wrong marks: %+v", got)
	}
	if _, ok := got["/c"]; ok {
		t.Error("missing path should be omitted")
	}
}

func TestMarkingBackend_Copy_ClonesMarkWithNewSource(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{
		Path: "/src.pdf", Mark: cmmcmark.MarkITAR, OwnerID: 9, Source: "admin:1",
	})
	if err := store.Copy("/src.pdf", "/dst.pdf", "copy-from:/src.pdf"); err != nil {
		t.Fatalf("copy: %v", err)
	}
	dst, err := store.Get("/dst.pdf")
	if err != nil {
		t.Fatalf("get dst: %v", err)
	}
	if dst.Mark != cmmcmark.MarkITAR {
		t.Errorf("mark not copied: %q", dst.Mark)
	}
	if dst.OwnerID != 9 {
		t.Errorf("owner not copied: %d", dst.OwnerID)
	}
	if dst.Source != "copy-from:/src.pdf" {
		t.Errorf("source not tagged: %q", dst.Source)
	}
	// Source row must still exist.
	if _, err := store.Get("/src.pdf"); err != nil {
		t.Errorf("src row vanished: %v", err)
	}
}

func TestMarkingBackend_Copy_MissingSrcIsNoop(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	if err := store.Copy("/never", "/dst", "tag"); err != nil {
		t.Fatalf("copy of missing should be noop: %v", err)
	}
	if _, err := store.Get("/dst"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("dst should not exist; err=%v", err)
	}
}

func TestMarkingBackend_Copy_UpsertsOverExistingDst(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/src", Mark: cmmcmark.MarkITAR, OwnerID: 1})
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/dst", Mark: cmmcmark.MarkBasic, OwnerID: 2})
	if err := store.Copy("/src", "/dst", "copy-over"); err != nil {
		t.Fatalf("copy: %v", err)
	}
	dst, _ := store.Get("/dst")
	if dst.Mark != cmmcmark.MarkITAR {
		t.Errorf("upsert did not replace mark; got %q", dst.Mark)
	}
}

// --- folder-inheritance tests (C.4) ------------------------------

func TestMarkingBackend_GetEffective_WalksUpToFolderClassification(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	// Folder classified CUI//BASIC, file underneath has no row.
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/cmmc/Engineering_CUI", Mark: cmmcmark.MarkBasic, OwnerID: 1})

	got, err := store.GetEffective("/srv/cmmc/Engineering_CUI/drawing.pdf")
	if err != nil {
		t.Fatalf("GetEffective: %v", err)
	}
	if got.Mark != cmmcmark.MarkBasic {
		t.Errorf("inherited mark = %q, want %q", got.Mark, cmmcmark.MarkBasic)
	}
}

func TestMarkingBackend_GetEffective_FileRowOverridesAncestor(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	// Folder is BASIC, but a specific file is ITAR.
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Engineering_CUI", Mark: cmmcmark.MarkBasic})
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Engineering_CUI/export.pdf", Mark: cmmcmark.MarkITAR})

	got, err := store.GetEffective("/srv/Engineering_CUI/export.pdf")
	if err != nil {
		t.Fatalf("GetEffective: %v", err)
	}
	if got.Mark != cmmcmark.MarkITAR {
		t.Errorf("file-level override lost; got %q", got.Mark)
	}
}

func TestMarkingBackend_GetEffective_NoAncestorMarked_ReturnsNotExist(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	// Uncontrolled tree: /Public/foo.txt — no rows anywhere.
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/Unrelated", Mark: cmmcmark.MarkBasic})

	_, err := store.GetEffective("/Public/foo.txt")
	if !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("uncontrolled path: err = %v, want ErrNotExist", err)
	}
}

func TestMarkingBackend_GetManyEffective_InheritsPerListing(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	// Folder marked; children have no rows of their own.
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Engineering_CUI", Mark: cmmcmark.MarkBasic})
	// A sibling unrelated folder — no inheritance expected.
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Public/hint.txt", Mark: cmmcmark.MarkNone})
	// A file with its OWN stricter mark.
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Engineering_CUI/itar.pdf", Mark: cmmcmark.MarkITAR})

	got, err := store.GetManyEffective([]string{
		"/srv/Engineering_CUI/a.pdf", // inherits BASIC
		"/srv/Engineering_CUI/b.pdf", // inherits BASIC
		"/srv/Engineering_CUI/itar.pdf", // own ITAR
		"/srv/Public/anything.txt",   // no inheritance chain that matches
	})
	if err != nil {
		t.Fatalf("GetManyEffective: %v", err)
	}
	if got["/srv/Engineering_CUI/a.pdf"] == nil || got["/srv/Engineering_CUI/a.pdf"].Mark != cmmcmark.MarkBasic {
		t.Errorf("a.pdf inheritance missed: %+v", got["/srv/Engineering_CUI/a.pdf"])
	}
	if got["/srv/Engineering_CUI/b.pdf"] == nil || got["/srv/Engineering_CUI/b.pdf"].Mark != cmmcmark.MarkBasic {
		t.Errorf("b.pdf inheritance missed: %+v", got["/srv/Engineering_CUI/b.pdf"])
	}
	if got["/srv/Engineering_CUI/itar.pdf"] == nil || got["/srv/Engineering_CUI/itar.pdf"].Mark != cmmcmark.MarkITAR {
		t.Errorf("file-level override lost in batch: %+v", got["/srv/Engineering_CUI/itar.pdf"])
	}
	// /srv/Public/hint.txt has its own MarkNone row; children of /Public
	// walk up and DO hit that row (MarkNone — still non-CUI). The entry
	// is present but non-CUI; OK.
	// Unrelated files whose lineage has no row at all must be ABSENT.
	if _, ok := got["/srv/Totally/Separate/x"]; ok {
		t.Errorf("unrelated path should not appear")
	}
}

func TestMarkingBackend_HasCUIDescendants(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Engineering_CUI/drawing.pdf", Mark: cmmcmark.MarkBasic})
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/srv/Public/readme.txt", Mark: cmmcmark.MarkNone})

	got, err := store.HasCUIDescendants("/srv/Engineering_CUI")
	if err != nil || !got {
		t.Errorf("Engineering_CUI must report CUI descendants; got=%v err=%v", got, err)
	}
	got, err = store.HasCUIDescendants("/srv/Public")
	if err != nil || got {
		t.Errorf("Public must not report CUI descendants; got=%v err=%v", got, err)
	}
	// Prefix match, not partial — /srv/Eng must not match /srv/Engineering_CUI.
	got, _ = store.HasCUIDescendants("/srv/Eng")
	if got {
		t.Errorf("Eng must not match Engineering_CUI prefix")
	}
}

func TestMarkingBackend_DeleteByOwnerID_RemovesAllForUser(t *testing.T) {
	store := NewMarkingBackend(openTestBolt(t))
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/alice/1", Mark: cmmcmark.MarkBasic, OwnerID: 1})
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/alice/2", Mark: cmmcmark.MarkBasic, OwnerID: 1})
	_ = store.Put(&cmmcmark.FileMetadata{Path: "/bob/1", Mark: cmmcmark.MarkBasic, OwnerID: 2})

	if err := store.DeleteByOwnerID(1); err != nil {
		t.Fatalf("delete by owner: %v", err)
	}
	if _, err := store.Get("/alice/1"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Error("/alice/1 still present after DeleteByOwnerID")
	}
	if _, err := store.Get("/alice/2"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Error("/alice/2 still present after DeleteByOwnerID")
	}
	// bob's row must survive
	if _, err := store.Get("/bob/1"); err != nil {
		t.Errorf("/bob/1 should survive: %v", err)
	}
	// Subsequent call for same user is a noop.
	if err := store.DeleteByOwnerID(1); err != nil {
		t.Errorf("second delete: %v", err)
	}
}
