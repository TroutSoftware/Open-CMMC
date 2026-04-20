package fbhttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/asdine/storm/v3"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
	"github.com/filebrowser/filebrowser/v2/storage"
	boltstore "github.com/filebrowser/filebrowser/v2/storage/bolt"
	"github.com/filebrowser/filebrowser/v2/users"
)

func newGroupsTestData(t *testing.T) *data {
	t.Helper()
	dir := t.TempDir()
	db, err := storm.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &data{
		store: &storage.Storage{
			GroupPerms: boltstore.NewGroupPermBackend(db),
		},
		user: &users.User{ID: 1, Username: "dana", Perm: users.Permissions{Admin: true}},
	}
}

func TestGroupsListFn_EmptyReturnsRolesCatalog(t *testing.T) {
	d := newGroupsTestData(t)
	req := httptest.NewRequest("GET", "/api/cmmc/groups", nil)
	rec := httptest.NewRecorder()
	if status, err := groupsListFn(rec, req, d); err != nil || status != 0 {
		t.Fatalf("status=%d err=%v", status, err)
	}
	var body struct {
		Groups []map[string]interface{} `json:"groups"`
		Roles  []string                 `json:"roles"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if len(body.Groups) != 0 {
		t.Errorf("expected 0 groups, got %d", len(body.Groups))
	}
	// The role catalog must come back even when no groups are
	// configured — SPA needs it to populate the dropdown.
	if len(body.Roles) < 4 {
		t.Errorf("expected >= 4 roles, got %d", len(body.Roles))
	}
}

func TestGroupsPutFn_RoundTripAndLabel(t *testing.T) {
	d := newGroupsTestData(t)
	req := httptest.NewRequest("PUT", "/api/cmmc/groups",
		bytes.NewReader([]byte(`{"group":"engineering","role":"contributor"}`)))
	rec := httptest.NewRecorder()
	if status, err := groupsPutFn(rec, req, d); err != nil || status != 0 {
		t.Fatalf("put status=%d err=%v", status, err)
	}

	// GET back.
	getReq := httptest.NewRequest("GET", "/api/cmmc/groups", nil)
	getRec := httptest.NewRecorder()
	_, _ = groupsListFn(getRec, getReq, d)
	var body struct {
		Groups []map[string]interface{} `json:"groups"`
	}
	_ = json.NewDecoder(getRec.Body).Decode(&body)
	if len(body.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(body.Groups))
	}
	g := body.Groups[0]
	if g["group"] != "engineering" {
		t.Errorf("group = %v", g["group"])
	}
	if g["role"] != "contributor" {
		t.Errorf("role = %v", g["role"])
	}
	if g["label"] != "Contributor" {
		t.Errorf("label = %v (SPA needs the rendered form)", g["label"])
	}
}

func TestGroupsPutFn_UnknownRole_Rejected(t *testing.T) {
	d := newGroupsTestData(t)
	req := httptest.NewRequest("PUT", "/api/cmmc/groups",
		bytes.NewReader([]byte(`{"group":"engineering","role":"super-saiyan"}`)))
	rec := httptest.NewRecorder()
	status, _ := groupsPutFn(rec, req, d)
	if status != http.StatusBadRequest {
		t.Errorf("unknown role must 400; got %d", status)
	}
}

func TestGroupsPutFn_EmptyRole_ClearsRow(t *testing.T) {
	d := newGroupsTestData(t)
	// Seed.
	_ = d.store.GroupPerms.Put(&authz.GroupPermission{
		GroupName: "engineering", Role: authz.RoleViewer,
	})
	req := httptest.NewRequest("PUT", "/api/cmmc/groups",
		bytes.NewReader([]byte(`{"group":"engineering","role":""}`)))
	rec := httptest.NewRecorder()
	if status, err := groupsPutFn(rec, req, d); err != nil || status != 0 {
		t.Fatalf("clear status=%d err=%v", status, err)
	}
	// Row gone.
	rows, _ := d.store.GroupPerms.List()
	if len(rows) != 0 {
		t.Errorf("row not cleared: %+v", rows)
	}
}

func TestGroupsPutFn_MissingGroup_Rejected(t *testing.T) {
	d := newGroupsTestData(t)
	req := httptest.NewRequest("PUT", "/api/cmmc/groups",
		bytes.NewReader([]byte(`{"group":"","role":"viewer"}`)))
	rec := httptest.NewRecorder()
	status, _ := groupsPutFn(rec, req, d)
	if status != http.StatusBadRequest {
		t.Errorf("missing group must 400; got %d", status)
	}
}

func TestGroupsDeleteFn_RoundTrip(t *testing.T) {
	d := newGroupsTestData(t)
	_ = d.store.GroupPerms.Put(&authz.GroupPermission{
		GroupName: "sales", Role: authz.RoleViewer,
	})
	req := httptest.NewRequest("DELETE", "/sales", nil)
	req.URL.Path = "/sales" // matches PathPrefix handler contract
	rec := httptest.NewRecorder()
	if status, err := groupsDeleteFn(rec, req, d); err != nil || status != 0 {
		t.Fatalf("delete status=%d err=%v", status, err)
	}
	rows, _ := d.store.GroupPerms.List()
	if len(rows) != 0 {
		t.Errorf("row still present: %+v", rows)
	}
}
