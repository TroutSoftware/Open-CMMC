package authz

import (
	"testing"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/users"
)

// TestApplyRole pins the role→perm mapping. The matrix is the product
// contract users and auditors read first; a silent change here would
// be a CMMC finding.
func TestApplyRole(t *testing.T) {
	cases := []struct {
		role    RolePreset
		wantDl  bool
		wantMod bool
		wantDel bool
		wantShr bool
		wantAdm bool
	}{
		{RoleNone, false, false, false, false, false},
		{RoleViewer, true, false, false, false, false},
		{RoleContributor, true, true, false, false, false},
		{RoleCollaborator, true, true, true, true, false},
		{RoleAdmin, true, true, true, true, true},
	}
	for _, c := range cases {
		got := ApplyRole(c.role)
		if got.Download != c.wantDl {
			t.Errorf("%s Download=%v want %v", c.role, got.Download, c.wantDl)
		}
		if got.Modify != c.wantMod {
			t.Errorf("%s Modify=%v want %v", c.role, got.Modify, c.wantMod)
		}
		if got.Delete != c.wantDel {
			t.Errorf("%s Delete=%v want %v", c.role, got.Delete, c.wantDel)
		}
		if got.Share != c.wantShr {
			t.Errorf("%s Share=%v want %v", c.role, got.Share, c.wantShr)
		}
		if got.Admin != c.wantAdm {
			t.Errorf("%s Admin=%v want %v", c.role, got.Admin, c.wantAdm)
		}
		// Execute must NEVER be granted by any role — see ApplyRole doc.
		if got.Execute {
			t.Errorf("%s Execute=true, must always be false (shell-exec incompatible with CMMC)", c.role)
		}
	}
}

func TestMergePerms_Union(t *testing.T) {
	a := users.Permissions{Download: true}
	b := users.Permissions{Modify: true}
	m := MergePerms(a, b)
	if !m.Download || !m.Modify {
		t.Errorf("union lost a bit: %+v", m)
	}
	// Idempotent.
	if MergePerms(a, a) != a {
		t.Errorf("merge with self != self: %+v", MergePerms(a, a))
	}
	// Admin is OR.
	if !MergePerms(users.Permissions{}, users.Permissions{Admin: true}).Admin {
		t.Errorf("Admin bit lost in union")
	}
}

func TestRoleLabel_CoversAll(t *testing.T) {
	// Every AllRoles() entry must have a non-empty label. A missing
	// label would render as blank in the SPA dropdown.
	for _, r := range AllRoles() {
		if RoleLabel(r) == "" {
			t.Errorf("role %q has empty label", r)
		}
	}
}

// fakeStore is a minimal in-memory Store for tests.
type fakeStore struct {
	rows map[string]*GroupPermission
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]*GroupPermission{}} }
func (f *fakeStore) Get(g string) (*GroupPermission, error) {
	if v, ok := f.rows[g]; ok {
		return v, nil
	}
	return nil, fberrors.ErrNotExist
}
func (f *fakeStore) Put(gp *GroupPermission) error { f.rows[gp.GroupName] = gp; return nil }
func (f *fakeStore) Delete(g string) error         { delete(f.rows, g); return nil }
func (f *fakeStore) List() ([]*GroupPermission, error) {
	out := make([]*GroupPermission, 0, len(f.rows))
	for _, v := range f.rows {
		out = append(out, v)
	}
	return out, nil
}

func TestSeedDefaultGroupPerms_OnlyOnEmpty(t *testing.T) {
	store := newFakeStore()
	n, err := SeedDefaultGroupPerms(store)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if n < 5 {
		t.Errorf("expected >= 5 seeded rows, got %d", n)
	}
	// Second call is a no-op.
	n2, err := SeedDefaultGroupPerms(store)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if n2 != 0 {
		t.Errorf("re-run wrote %d rows, want 0", n2)
	}
	// filebrowser-admins must end up as Admin.
	gp, err := store.Get("filebrowser-admins")
	if err != nil || gp.Role != RoleAdmin {
		t.Errorf("filebrowser-admins should be Admin, got %q (err %v)", gp.Role, err)
	}
	// sales must end up as Viewer (no CUI access).
	gp, err = store.Get("sales")
	if err != nil || gp.Role != RoleViewer {
		t.Errorf("sales should be Viewer, got %q", gp.Role)
	}
}

func TestSeedDefaultGroupPerms_NilStore_NoError(t *testing.T) {
	n, err := SeedDefaultGroupPerms(nil)
	if err != nil || n != 0 {
		t.Errorf("nil store: got n=%d err=%v, want 0/nil", n, err)
	}
}
