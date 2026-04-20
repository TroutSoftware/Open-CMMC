package oidc

import (
	"errors"
	"sync"
	"testing"

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/users"
)

// --- in-memory IdentityStore for tests -----------------------------------

type fakeIDStore struct {
	mu       sync.Mutex
	byKey    map[string]*Identity
	nextID   uint
	optInULP bool // toggle to test the fallback path in anyIdentityForUser
}

func newFakeIDStore() *fakeIDStore {
	return &fakeIDStore{byKey: map[string]*Identity{}, nextID: 1, optInULP: true}
}

func (f *fakeIDStore) Get(key string) (*Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.byKey[key]; ok {
		return v, nil
	}
	return nil, fberrors.ErrNotExist
}
func (f *fakeIDStore) Put(id *Identity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.byKey[id.IssSubKey]; ok {
		id.ID = existing.ID
	} else {
		id.ID = f.nextID
		f.nextID++
	}
	f.byKey[id.IssSubKey] = id
	return nil
}
func (f *fakeIDStore) DeleteByUserID(userID uint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.byKey {
		if v.UserID == userID {
			delete(f.byKey, k)
		}
	}
	return nil
}
func (f *fakeIDStore) HasUserID(userID uint) (bool, error) {
	if !f.optInULP {
		panic("HasUserID called when optInULP=false")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.byKey {
		if v.UserID == userID {
			return true, nil
		}
	}
	return false, nil
}

// noULPStore is an IdentityStore that does NOT implement userLookup,
// used to test the collision-check fallback path.
type noULPStore struct {
	inner *fakeIDStore
}

func (n *noULPStore) Get(key string) (*Identity, error)   { return n.inner.Get(key) }
func (n *noULPStore) Put(id *Identity) error              { return n.inner.Put(id) }
func (n *noULPStore) DeleteByUserID(userID uint) error    { return n.inner.DeleteByUserID(userID) }

// --- IdentityStore surface tests -----------------------------------------

func TestIdentityStore_RoundTrip(t *testing.T) {
	s := newFakeIDStore()
	key := IssSubKey("https://idp.example.mil/", "alice-sub-123")
	err := s.Put(&Identity{IssSubKey: key, UserID: 42})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Get(key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != 42 {
		t.Errorf("UserID = %d, want 42", got.UserID)
	}
	if got.IssSubKey != key {
		t.Errorf("IssSubKey mismatch")
	}
}

func TestIdentityStore_GetMissing_ReturnsErrNotExist(t *testing.T) {
	s := newFakeIDStore()
	_, err := s.Get(IssSubKey("iss", "sub"))
	if !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestIdentityStore_Put_UpdatesExisting(t *testing.T) {
	s := newFakeIDStore()
	key := IssSubKey("iss", "sub")
	_ = s.Put(&Identity{IssSubKey: key, UserID: 1})
	firstID := s.byKey[key].ID
	_ = s.Put(&Identity{IssSubKey: key, UserID: 2})
	got := s.byKey[key]
	if got.UserID != 2 {
		t.Errorf("UserID = %d, want 2 (update semantics)", got.UserID)
	}
	if got.ID != firstID {
		t.Errorf("primary key should not change on update: got %d want %d", got.ID, firstID)
	}
}

func TestIdentityStore_DeleteByUserID(t *testing.T) {
	s := newFakeIDStore()
	_ = s.Put(&Identity{IssSubKey: "k1", UserID: 1})
	_ = s.Put(&Identity{IssSubKey: "k2", UserID: 1})
	_ = s.Put(&Identity{IssSubKey: "k3", UserID: 2})
	if err := s.DeleteByUserID(1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get("k1"); !errors.Is(err, fberrors.ErrNotExist) {
		t.Errorf("k1 should be gone")
	}
	if _, err := s.Get("k3"); err != nil {
		t.Errorf("k3 (different user) must survive: %v", err)
	}
}

// --- Subject-based provisioning tests ------------------------------------

const testIssuer = "https://login.microsoftonline.us/tenant-id/v2.0"

func TestProvisionBySubject_NewUser_WritesMapping(t *testing.T) {
	ids := newFakeIDStore()
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)

	u, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "sub-1", Username: "alice", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if u.Username != "alice" {
		t.Errorf("username = %q", u.Username)
	}
	// Mapping written for (iss, sub).
	mapped, err := ids.Get(IssSubKey(testIssuer, "sub-1"))
	if err != nil {
		t.Fatalf("mapping not written: %v", err)
	}
	if mapped.UserID != u.ID {
		t.Errorf("mapped UserID=%d, want %d", mapped.UserID, u.ID)
	}
}

func TestProvisionBySubject_SecondLogin_UsesMapping(t *testing.T) {
	ids := newFakeIDStore()
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)

	// First login creates user and mapping.
	_, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "s", Username: "bob", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	savesAfterFirst := userStore.saves

	// Second login for same (iss, sub) — should NOT create a new user.
	u, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "s", Username: "bob", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if userStore.saves != savesAfterFirst {
		t.Errorf("second login created new user (saves %d → %d)", savesAfterFirst, userStore.saves)
	}
	if u.Username != "bob" {
		t.Errorf("username = %q", u.Username)
	}
}

func TestProvisionBySubject_SecondLogin_AttackerRenames_DoesNotTakeOverAdmin(t *testing.T) {
	// Scenario: alice is the real admin (sub=alice-stable). bob is a
	// non-admin user. bob rewrites his preferred_username to "alice" at
	// the IdP. Without subject-based identity, bob would be routed to
	// alice's row and inherit admin. With subject-based identity, the
	// collision is rejected.
	ids := newFakeIDStore()
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)

	// Seed: alice logs in legitimately, gets admin.
	_, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "alice-stable", Username: "alice", IsAdmin: true,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("alice seed: %v", err)
	}

	// Attack: bob logs in with a different subject but claims username=alice.
	_, err = ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "bob-stable", Username: "alice", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if !errors.Is(err, ErrUsernameCollision) {
		t.Fatalf("expected ErrUsernameCollision, got: %v", err)
	}
	// Alice's user row is untouched.
	alice, _ := userStore.Get("", "alice")
	if !alice.Perm.Admin {
		t.Errorf("alice must still be admin after attempted collision")
	}
}

func TestProvisionBySubject_BackfillExistingUser(t *testing.T) {
	// Legacy user created without the mapping layer (e.g., under the
	// earlier prototype). First OIDC login after deploy should backfill
	// the (iss, sub) mapping without creating a duplicate user.
	ids := newFakeIDStore()
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)

	// Seed a legacy user directly in the user store — no mapping is
	// written. Simulates a row carried over from a pre-subject-
	// mapping deploy.
	if err := userStore.Save(&users.User{
		Username:     "legacy-user",
		LockPassword: true,
	}); err != nil {
		t.Fatalf("legacy seed: %v", err)
	}
	if len(ids.byKey) != 0 {
		t.Fatalf("precondition: legacy seed must not write mapping")
	}
	savesAfterSeed := userStore.saves

	// OIDC login for the same username with a real subject.
	u, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "legacy-sub", Username: "legacy-user", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("backfill login: %v", err)
	}
	// No new user created.
	if userStore.saves != savesAfterSeed {
		t.Errorf("backfill should not create new user; saves went %d → %d", savesAfterSeed, userStore.saves)
	}
	if u.Username != "legacy-user" {
		t.Errorf("username = %q", u.Username)
	}
	// Mapping was written.
	mapped, err := ids.Get(IssSubKey(testIssuer, "legacy-sub"))
	if err != nil {
		t.Fatalf("mapping not backfilled: %v", err)
	}
	if mapped.UserID != u.ID {
		t.Errorf("backfill UserID mismatch: got %d want %d", mapped.UserID, u.ID)
	}
}

func TestProvisionBySubject_AdminSyncOnMappedLookup(t *testing.T) {
	ids := newFakeIDStore()
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)

	// First login: non-admin.
	_, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "s", Username: "u", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	updatesBefore := userStore.updates

	// Second login: IdP now says this user is admin.
	u, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{
		Subject: "s", Username: "u", IsAdmin: true,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if !u.Perm.Admin {
		t.Errorf("admin flag not synced on mapped lookup")
	}
	if userStore.updates != updatesBefore+1 {
		t.Errorf("expected exactly one Update for admin promotion, got delta %d", userStore.updates-updatesBefore)
	}
}

func TestProvisionBySubject_EmptySubjectRejected(t *testing.T) {
	ids := newFakeIDStore()
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)
	_, err := ProvisionOrFetchBySubject(ids, userStore, nil, &VerifiedSession{Username: "u"}, testIssuer, nil, set, srv)
	if err == nil {
		t.Fatalf("empty subject must be rejected")
	}
}

func TestProvisionBySubject_NoUserLookupExtension_SkipsCollisionCheck(t *testing.T) {
	// Store that does NOT implement userLookup. The collision check
	// degrades gracefully — it cannot detect the attack at this layer,
	// but the underlying unique constraint at Put time is the ultimate
	// guarantee. This test pins the fallback behavior so we notice if
	// someone removes the type-assertion.
	inner := newFakeIDStore()
	store := &noULPStore{inner: inner}
	userStore := newFakeStore()
	set, srv := testSettingsAndServer(t)

	_, err := ProvisionOrFetchBySubject(store, userStore, nil, &VerifiedSession{
		Subject: "s1", Username: "u", IsAdmin: false,
	}, testIssuer, nil, set, srv)
	if err != nil {
		t.Fatalf("without userLookup should still work: %v", err)
	}
}
