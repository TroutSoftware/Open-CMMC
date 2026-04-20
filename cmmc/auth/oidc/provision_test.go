package oidc

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// fakeStore is a minimal in-memory users.Store for provisioning tests.
// It covers only the methods ProvisionOrFetch/createOIDCUser touch.
type fakeStore struct {
	mu      sync.Mutex
	byName  map[string]*users.User
	nextID  uint
	saves   int
	updates int
}

func newFakeStore() *fakeStore {
	return &fakeStore{byName: map[string]*users.User{}, nextID: 1}
}

func (f *fakeStore) Get(_ string, id interface{}) (*users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch v := id.(type) {
	case string:
		u, ok := f.byName[v]
		if !ok {
			return nil, fberrors.ErrNotExist
		}
		return u, nil
	case uint:
		for _, u := range f.byName {
			if u.ID == v {
				return u, nil
			}
		}
		return nil, fberrors.ErrNotExist
	default:
		return nil, fberrors.ErrInvalidDataType
	}
}

func (f *fakeStore) Gets(_ string) ([]*users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*users.User, 0, len(f.byName))
	for _, u := range f.byName {
		out = append(out, u)
	}
	return out, nil
}

func (f *fakeStore) Save(u *users.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.byName[u.Username]; exists {
		return fberrors.ErrExist
	}
	u.ID = f.nextID
	f.nextID++
	f.byName[u.Username] = u
	f.saves++
	return nil
}

func (f *fakeStore) Update(u *users.User, _ ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byName[u.Username] = u
	f.updates++
	return nil
}

func (f *fakeStore) Delete(id interface{}) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name, ok := id.(string); ok {
		delete(f.byName, name)
	}
	return nil
}

func (f *fakeStore) LastUpdate(_ uint) int64 { return 0 }

// testSettingsAndServer returns a minimal settings + server pointing at a
// tmp dir so createOIDCUser's MakeUserDir has somewhere to write.
func testSettingsAndServer(t *testing.T) (*settings.Settings, *settings.Server) {
	t.Helper()
	dir := t.TempDir()
	// MakeUserDir needs the server root to exist.
	if err := os.MkdirAll(filepath.Join(dir, "filebrowser"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	set := &settings.Settings{
		Key:                   []byte("0123456789abcdef0123456789abcdef"),
		Defaults:              settings.UserDefaults{Scope: "."},
		MinimumPasswordLength: settings.DefaultMinimumPasswordLength,
	}
	srv := &settings.Server{Root: dir}
	return set, srv
}

// Tests for the deprecated ProvisionOrFetch (username-keyed) were
// removed with the function itself in the trim-1 cleanup. Equivalent
// coverage for the subject-keyed entry point (the only production
// caller) lives in subject_test.go — new-user creation, admin
// derivation, concurrency serialization, collision refusal, etc.

// fakeAuthzStore is a minimal authz.Store for provisioning tests.
type fakeAuthzStore struct {
	rows map[string]*authz.GroupPermission
}

func newFakeAuthzStore() *fakeAuthzStore {
	return &fakeAuthzStore{rows: map[string]*authz.GroupPermission{}}
}
func (f *fakeAuthzStore) Get(g string) (*authz.GroupPermission, error) {
	if v, ok := f.rows[g]; ok {
		return v, nil
	}
	return nil, fberrors.ErrNotExist
}
func (f *fakeAuthzStore) Put(gp *authz.GroupPermission) error {
	f.rows[gp.GroupName] = gp
	return nil
}
func (f *fakeAuthzStore) Delete(g string) error { delete(f.rows, g); return nil }
func (f *fakeAuthzStore) List() ([]*authz.GroupPermission, error) {
	out := make([]*authz.GroupPermission, 0, len(f.rows))
	for _, v := range f.rows {
		out = append(out, v)
	}
	return out, nil
}

// TestComputeEffectivePerms pins the group→role union contract.
// Every scenario here corresponds to a real deployment pattern.
func TestComputeEffectivePerms_UnionOfGroups(t *testing.T) {
	store := newFakeAuthzStore()
	_ = store.Put(&authz.GroupPermission{GroupName: "engineering", Role: authz.RoleContributor})
	_ = store.Put(&authz.GroupPermission{GroupName: "quality", Role: authz.RoleCollaborator})

	// User in both groups gets the superset.
	got := ComputeEffectivePerms([]string{"engineering", "quality"}, store, nil, false)
	if !got.Download || !got.Modify || !got.Delete || !got.Share {
		t.Errorf("union lost bits: %+v", got)
	}
	if got.Admin {
		t.Errorf("Admin must not be set without admin group membership")
	}
}

// TestComputeEffectivePerms_AdminGroupWins — the FB_OIDC_ADMIN_GROUPS
// convention must still produce full Admin perms regardless of what
// group_perms says.
func TestComputeEffectivePerms_AdminGroupWins(t *testing.T) {
	store := newFakeAuthzStore()
	// Only Viewer configured for the admin group — shouldn't matter.
	_ = store.Put(&authz.GroupPermission{GroupName: "filebrowser-admins", Role: authz.RoleViewer})

	got := ComputeEffectivePerms(
		[]string{"engineering", "filebrowser-admins"},
		store,
		[]string{"filebrowser-admins"},
		false,
	)
	if !got.Admin {
		t.Errorf("admin group membership must promote to Admin role")
	}
	if !got.Modify || !got.Delete || !got.Share {
		t.Errorf("Admin preset should grant everything: %+v", got)
	}
}

// TestComputeEffectivePerms_NilStore_UsesLegacyFallback pins the
// backward-compat branch so a deployment that hasn't run Phase 1
// migration still gets reasonable perms.
func TestComputeEffectivePerms_NilStore_UsesLegacyFallback(t *testing.T) {
	got := ComputeEffectivePerms([]string{"engineering"}, nil, nil, true)
	if !got.Admin {
		t.Errorf("legacy fallback with isAdmin=true must set Admin")
	}
	got = ComputeEffectivePerms([]string{"engineering"}, nil, nil, false)
	if got.Admin {
		t.Errorf("legacy fallback with isAdmin=false must not be Admin")
	}
	// Non-admin legacy: Download + Create + Modify so users can work.
	if !got.Download || !got.Create || !got.Modify {
		t.Errorf("legacy non-admin fallback must grant at least read+upload+modify: %+v", got)
	}
}

// TestComputeEffectivePerms_UnknownGroup_NoPerms — a user in a group
// with no configured role gets nothing from that group. Safe default.
func TestComputeEffectivePerms_UnknownGroup_NoPerms(t *testing.T) {
	store := newFakeAuthzStore()
	got := ComputeEffectivePerms([]string{"unknown"}, store, nil, false)
	if got.Download || got.Modify || got.Admin {
		t.Errorf("unknown group should grant nothing; got %+v", got)
	}
}
