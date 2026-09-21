package fbhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"

	"github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
	"github.com/filebrowser/filebrowser/v2/cmmc/otrelease"
	"github.com/filebrowser/filebrowser/v2/rules"
	"github.com/filebrowser/filebrowser/v2/settings"
)

const otTestCells = `
cells:
  - name: cell-a
    mark: "CUI//BASIC"
    return_path: /Operations_CUI/NC/cell-a/return
    machines:
      - { name: cnc-a1, ip: 10.20.1.11, dialect: smb3, auth: password }
`

// otTestSetup installs a releaser rooted in a temp dir and drops one
// file in the user's scope. Returns the data and the out dir.
func otTestSetup(t *testing.T, admin bool) (*data, string) {
	t.Helper()
	d := newTestData(t, admin)
	d.server = &settings.Server{Root: strings.TrimSuffix(d.user.FullPath("/"), "/")}
	d.settings = &settings.Settings{}
	cells, err := otrelease.ParseCells([]byte(otTestCells))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	rel, err := otrelease.NewReleaser(root, cells)
	if err != nil {
		t.Fatal(err)
	}
	SetOTRelease(rel, otrelease.NewManager(filepath.Join(root, "cells.yaml"), cells, rel, nil))
	t.Cleanup(func() { SetOTRelease(nil, nil) })
	if err := d.user.Fs.MkdirAll("/Operations_CUI/NC", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := afero.WriteFile(d.user.Fs, "/Operations_CUI/NC/O1001.nc", []byte("O1001\nM30\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	audit.SetDefault(audit.NewMemoryEmitter())
	return d, filepath.Join(root, "out", "cell-a")
}

func otPost(t *testing.T, d *data, body string) (int, *httptest.ResponseRecorder) {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/cmmc/ot/release", strings.NewReader(body))
	w := httptest.NewRecorder()
	status, _ := otReleaseFn(w, r, d)
	return status, w
}

func TestOTHandlers_DisabledReturn503(t *testing.T) {
	SetOTRelease(nil, nil)
	d := newTestData(t, true)
	r := httptest.NewRequest("GET", "/api/cmmc/ot/cells", nil)
	w := httptest.NewRecorder()
	if status, _ := otCellsFn(w, r, d); status != http.StatusServiceUnavailable {
		t.Fatalf("cells status = %d", status)
	}
	if status, _ := otPost(t, d, `{"path":"/x","cell":"cell-a"}`); status != http.StatusServiceUnavailable {
		t.Fatalf("release status = %d", status)
	}
}

func TestOTRelease_AdminHappyPath(t *testing.T) {
	d, out := otTestSetup(t, true)
	status, w := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a","ttl_days":3,"pinned":true}`)
	if status != 0 {
		t.Fatalf("status = %d body=%s", status, w.Body.String())
	}
	var m otrelease.Manifest
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil || m.Name != "O1001.nc" || !m.Pinned || m.Cell != "cell-a" {
		t.Fatalf("manifest: %+v %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(out, "O1001.nc")); err != nil {
		t.Fatal("payload not on share")
	}
	if !strings.HasSuffix(m.Source, "/Operations_CUI/NC/O1001.nc") {
		t.Fatalf("source = %s", m.Source)
	}

	// Listing and revoke.
	r := httptest.NewRequest("GET", "/api/cmmc/ot/released?cell=cell-a", nil)
	rw := httptest.NewRecorder()
	if s, _ := otReleasedFn(rw, r, d); s != 0 || !strings.Contains(rw.Body.String(), "O1001.nc") || strings.Contains(rw.Body.String(), d.server.Root) {
		t.Fatalf("list must show the file with a user-relative path only: %d %s", s, rw.Body.String())
	}
	r = httptest.NewRequest("DELETE", "/api/cmmc/ot/release", strings.NewReader(`{"cell":"cell-a","name":"O1001.nc"}`))
	rw = httptest.NewRecorder()
	if s, _ := otRevokeFn(rw, r, d); s != http.StatusNoContent {
		t.Fatalf("revoke: %d", s)
	}
	if _, err := os.Stat(filepath.Join(out, "O1001.nc")); !os.IsNotExist(err) {
		t.Fatal("payload still on share after revoke")
	}
}

func TestOTRelease_NonAdminNeedsACLGrant(t *testing.T) {
	d, _ := otTestSetup(t, false)
	d.user.Username = "alice"
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != http.StatusForbidden {
		t.Fatalf("no grant: status = %d, want 403", status)
	}
	// Grant read+release on the parent folder.
	acl := &folderacl.FolderACL{Path: "/Operations_CUI", Entries: []folderacl.Entry{{Kind: folderacl.KindUser, ID: "alice", Perms: folderacl.Perms{Read: true, Release: true}}}}
	if err := d.store.FolderACLs.Put(acl); err != nil {
		t.Fatal(err)
	}
	if status, w := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != 0 {
		t.Fatalf("with grant: status = %d body=%s", status, w.Body.String())
	}
	// Read-only grant is not enough.
	acl.Entries[0].Perms.Release = false
	_ = d.store.FolderACLs.Put(acl)
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != http.StatusForbidden {
		t.Fatalf("read-only grant: status = %d, want 403", status)
	}
}

func TestOTRelease_StatusMapping(t *testing.T) {
	d, _ := otTestSetup(t, true)
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"nope"}`); status != http.StatusNotFound {
		t.Fatalf("unknown cell: %d", status)
	}
	// Mark the folder ITAR → BASIC cell must refuse with 409.
	_ = d.store.FileMetadata.Put(&cmmcmark.FileMetadata{Path: d.user.FullPath("/Operations_CUI"), Mark: cmmcmark.MarkITAR})
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != http.StatusConflict {
		t.Fatalf("designation: %d, want 409", status)
	}
	if status, _ := otPost(t, d, `{"path":"/../etc/passwd","cell":"cell-a"}`); status != http.StatusBadRequest {
		t.Fatalf("traversal: %d, want 400", status)
	}
	if status, _ := otPost(t, d, `not json`); status != http.StatusBadRequest {
		t.Fatalf("bad json: %d", status)
	}
}

func TestOTCells_ListsForAnyUser(t *testing.T) {
	d, _ := otTestSetup(t, false)
	r := httptest.NewRequest("GET", "/api/cmmc/ot/cells", nil)
	w := httptest.NewRecorder()
	if s, _ := otCellsFn(w, r, d); s != 0 {
		t.Fatalf("status %d", s)
	}
	var cells []otCellView
	if err := json.Unmarshal(w.Body.Bytes(), &cells); err != nil || len(cells) != 1 || cells[0].Name != "cell-a" || cells[0].Machines != 1 || cells[0].TTLDays != 30 {
		t.Fatalf("cells: %+v %v", cells, err)
	}
}

func TestOTRelease_PinAdminOnlyAndTTLBounds(t *testing.T) {
	d, _ := otTestSetup(t, false)
	d.user.Username = "alice"
	acl := &folderacl.FolderACL{Path: "/Operations_CUI", Entries: []folderacl.Entry{{Kind: folderacl.KindUser, ID: "alice", Perms: folderacl.Perms{Read: true, Release: true}}}}
	_ = d.store.FolderACLs.Put(acl)
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a","pinned":true}`); status != http.StatusForbidden {
		t.Fatalf("non-admin pin: %d, want 403", status)
	}
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a","ttl_days":4000}`); status != http.StatusBadRequest {
		t.Fatalf("ttl 4000: %d, want 400", status)
	}
	if status, w := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a","ttl_days":7}`); status != 0 {
		t.Fatalf("ttl 7: %d %s", status, w.Body.String())
	}
}

func TestOTReleased_HiddenWithoutReadAccess(t *testing.T) {
	d, _ := otTestSetup(t, true)
	if status, w := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != 0 {
		t.Fatalf("release: %d %s", status, w.Body.String())
	}
	// A non-admin with a rule denying the folder sees an empty list.
	d.user.Perm.Admin = false
	d.user.Rules = []rules.Rule{{Regex: false, Allow: false, Path: "/Operations_CUI"}}
	r := httptest.NewRequest("GET", "/api/cmmc/ot/released?cell=cell-a", nil)
	w := httptest.NewRecorder()
	if s, _ := otReleasedFn(w, r, d); s != 0 || strings.Contains(w.Body.String(), "O1001") {
		t.Fatalf("hidden entry leaked: %d %s", s, w.Body.String())
	}
}

func TestOTRelease_SameNameFromOtherSourceNeedsAdmin(t *testing.T) {
	d, _ := otTestSetup(t, true)
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != 0 {
		t.Fatal("admin release")
	}
	_ = d.user.Fs.MkdirAll("/Operations_CUI/Other", 0o755)
	_ = afero.WriteFile(d.user.Fs, "/Operations_CUI/Other/O1001.nc", []byte("different\n"), 0o640)
	d.user.Perm.Admin = false
	d.user.Username = "alice"
	_ = d.store.FolderACLs.Put(&folderacl.FolderACL{Path: "/Operations_CUI", Entries: []folderacl.Entry{{Kind: folderacl.KindUser, ID: "alice", Perms: folderacl.Perms{Read: true, Release: true}}}})
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/Other/O1001.nc","cell":"cell-a"}`); status != http.StatusConflict {
		t.Fatalf("grant holder replacing another source: %d, want 409", status)
	}
	if status, _ := otPost(t, d, `{"path":"/Operations_CUI/NC/O1001.nc","cell":"cell-a"}`); status != 0 {
		t.Fatalf("grant holder refreshing the same source: %d", status)
	}
}

func TestOTInventory_AdminRoundTrip(t *testing.T) {
	d, _ := otTestSetup(t, true)
	r := httptest.NewRequest("GET", "/api/cmmc/ot/inventory", nil)
	w := httptest.NewRecorder()
	if s, _ := otInventoryGetFn(w, r, d); s != 0 {
		t.Fatalf("get: %d", s)
	}
	var inv otInventoryView
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil || len(inv.Cells) != 1 {
		t.Fatalf("inventory: %v %s", err, w.Body.String())
	}
	inv.Cells[0].Machines = append(inv.Cells[0].Machines, otrelease.Machine{Name: "cnc-a2", IP: "10.20.1.12", Dialect: otrelease.DialectSMB3, Auth: otrelease.AuthPassword})
	body, _ := json.Marshal(otInventoryPut{Cells: inv.Cells})
	r = httptest.NewRequest("PUT", "/api/cmmc/ot/inventory", strings.NewReader(string(body)))
	w = httptest.NewRecorder()
	if s, err := otInventoryPutFn(w, r, d); s != 0 {
		t.Fatalf("put: %d %v", s, err)
	}
	if len(otManager.Cells().Cells[0].Machines) != 2 {
		t.Fatal("inventory not reloaded")
	}
	// Invalid inventory → 422, nothing changes.
	inv.Cells[0].Machines[1].IP = "10.20.1.11"
	body, _ = json.Marshal(otInventoryPut{Cells: inv.Cells})
	r = httptest.NewRequest("PUT", "/api/cmmc/ot/inventory", strings.NewReader(string(body)))
	w = httptest.NewRecorder()
	if s, _ := otInventoryPutFn(w, r, d); s != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate IP accepted: %d", s)
	}
}
