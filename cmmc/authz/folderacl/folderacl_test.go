package folderacl

import (
	"errors"
	"strings"
	"testing"
)

// fakeStore is an in-memory Store for tests. Keyed on normalized
// path; WalkAncestors walks from the leaf up.
type fakeStore struct {
	rows map[string]*FolderACL
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: map[string]*FolderACL{}}
}

func (f *fakeStore) Get(p string) (*FolderACL, error) {
	if a, ok := f.rows[p]; ok {
		return a, nil
	}
	return nil, ErrNotExist
}
func (f *fakeStore) Put(a *FolderACL) error {
	if err := a.Validate(); err != nil {
		return err
	}
	n, _ := NormalizePath(a.Path)
	a.Path = n
	f.rows[n] = a
	return nil
}
func (f *fakeStore) Delete(p string) error {
	delete(f.rows, p)
	return nil
}
func (f *fakeStore) List() ([]*FolderACL, error) {
	out := make([]*FolderACL, 0, len(f.rows))
	for _, a := range f.rows {
		out = append(out, a)
	}
	return out, nil
}
func (f *fakeStore) WalkAncestors(p string, fn func(*FolderACL) bool) error {
	cur := p
	for {
		if a, ok := f.rows[cur]; ok {
			if !fn(a) {
				return nil
			}
		}
		if cur == "/" {
			return nil
		}
		// Parent.
		i := strings.LastIndex(cur, "/")
		if i <= 0 {
			cur = "/"
		} else {
			cur = cur[:i]
		}
	}
}

// --- NormalizePath tests -----------------------------------------

func TestNormalizePath_AddsLeadingSlash(t *testing.T) {
	got, ok := NormalizePath("Engineering")
	if !ok || got != "/Engineering" {
		t.Errorf("got %q ok=%v, want /Engineering true", got, ok)
	}
}

func TestNormalizePath_StripsTrailingSlash(t *testing.T) {
	got, _ := NormalizePath("/Engineering/")
	if got != "/Engineering" {
		t.Errorf("got %q, want /Engineering", got)
	}
}

func TestNormalizePath_Root(t *testing.T) {
	got, ok := NormalizePath("/")
	if !ok || got != "/" {
		t.Errorf("got %q ok=%v, want '/' true", got, ok)
	}
}

func TestNormalizePath_RejectsEmpty(t *testing.T) {
	if _, ok := NormalizePath(""); ok {
		t.Error("empty path must be rejected")
	}
}

func TestNormalizePath_CollapsesDotDot(t *testing.T) {
	got, ok := NormalizePath("/a/../b")
	if !ok || got != "/b" {
		t.Errorf("got %q ok=%v, want /b true", got, ok)
	}
}

func TestNormalizePath_RejectsEscapingDotDot(t *testing.T) {
	// path.Clean collapses /.. to / so traversal can't escape
	// the root. Pin that behavior so a Clean regression caught.
	got, ok := NormalizePath("/..")
	if !ok || got != "/" {
		t.Errorf("/.. collapses to / root: got %q ok=%v", got, ok)
	}
	got, ok = NormalizePath("/a/../../b")
	if !ok || got != "/b" {
		t.Errorf("traversal-at-depth collapses: got %q ok=%v", got, ok)
	}
}

// --- Validate tests ----------------------------------------------

func TestValidate_HappyPath(t *testing.T) {
	a := &FolderACL{Path: "/a", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Read: true}},
		{Kind: KindUser, ID: "alice", Perms: Perms{Read: true, Write: true}},
	}}
	if err := a.Validate(); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestValidate_UnknownKind(t *testing.T) {
	a := &FolderACL{Path: "/a", Entries: []Entry{
		{Kind: Kind("role"), ID: "x"},
	}}
	if err := a.Validate(); err == nil {
		t.Error("unknown kind must fail validation")
	}
}

func TestValidate_EmptyID(t *testing.T) {
	a := &FolderACL{Path: "/a", Entries: []Entry{
		{Kind: KindGroup, ID: ""},
	}}
	if err := a.Validate(); err == nil {
		t.Error("empty id must fail validation")
	}
}

func TestValidate_DuplicatePrincipal(t *testing.T) {
	a := &FolderACL{Path: "/a", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Read: true}},
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Write: true}},
	}}
	if err := a.Validate(); err == nil {
		t.Error("duplicate same-kind-same-id must fail")
	}
}

func TestValidate_SameIDDifferentKinds(t *testing.T) {
	// Group "alice" and user "alice" are distinct principals; no
	// collision even with identical IDs.
	a := &FolderACL{Path: "/a", Entries: []Entry{
		{Kind: KindGroup, ID: "alice", Perms: Perms{Read: true}},
		{Kind: KindUser, ID: "alice", Perms: Perms{Write: true}},
	}}
	if err := a.Validate(); err != nil {
		t.Errorf("group+user with same id must be allowed: %v", err)
	}
}

func TestValidate_InvalidPath(t *testing.T) {
	a := &FolderACL{Path: ""}
	if err := a.Validate(); err == nil {
		t.Error("empty path must fail validation")
	}
}

// --- Evaluator tests ---------------------------------------------

func TestEvaluate_AdminBypassesEmptyStore(t *testing.T) {
	s := newFakeStore()
	d, err := Evaluate(s, Principal{IsAdmin: true}, "/any", ActionWrite)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !d.Allowed {
		t.Error("admin must be allowed regardless of ACL presence")
	}
	if d.NoMatch {
		t.Error("admin decision should not be NoMatch")
	}
}

func TestEvaluate_NoACL_NoMatch_FallsThrough(t *testing.T) {
	s := newFakeStore()
	d, _ := Evaluate(s, Principal{Username: "alice", Groups: []string{"engineering"}}, "/Unmapped", ActionRead)
	if !d.NoMatch {
		t.Error("no ACL anywhere → NoMatch must be true")
	}
	if d.Allowed {
		t.Error("no ACL anywhere → Allowed must be false")
	}
}

func TestEvaluate_GroupGrant_AtLeafPath(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Read: true, Write: true}},
	}})
	d, _ := Evaluate(s, Principal{Username: "alice", Groups: []string{"engineering"}}, "/Engineering", ActionWrite)
	if !d.Allowed {
		t.Error("group-granted write must be allowed")
	}
	if d.MatchedPath != "/Engineering" {
		t.Errorf("MatchedPath = %q", d.MatchedPath)
	}
}

func TestEvaluate_InheritsFromAncestor(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Read: true}},
	}})
	// Deep child; no explicit ACL. Should inherit from /Engineering.
	d, _ := Evaluate(s, Principal{Groups: []string{"engineering"}}, "/Engineering/rev-B/part-14", ActionRead)
	if !d.Allowed {
		t.Error("child path must inherit ancestor ACL")
	}
	if d.MatchedPath != "/Engineering" {
		t.Errorf("MatchedPath = %q, want /Engineering", d.MatchedPath)
	}
}

func TestEvaluate_NearestWins_DenyOverridesAncestorGrant(t *testing.T) {
	s := newFakeStore()
	// Ancestor grants read.
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Read: true}},
	}})
	// Child overrides with an empty-perms entry — deny.
	_ = s.Put(&FolderACL{Path: "/Engineering/Secret", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{}},
	}})
	d, _ := Evaluate(s, Principal{Groups: []string{"engineering"}}, "/Engineering/Secret", ActionRead)
	if d.Allowed {
		t.Error("nearest ACL's deny must override ancestor grant")
	}
	if d.MatchedPath != "/Engineering/Secret" {
		t.Errorf("MatchedPath = %q", d.MatchedPath)
	}
}

func TestEvaluate_UserEntryTrumpsGroup_AtSameLevel(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindGroup, ID: "engineering", Perms: Perms{Read: true, Write: true}},
		// Specific user denied.
		{Kind: KindUser, ID: "alice", Perms: Perms{}},
	}})
	d, _ := Evaluate(s, Principal{Username: "alice", Groups: []string{"engineering"}}, "/Engineering", ActionWrite)
	if d.Allowed {
		t.Error("specific user deny at same ACL must override group grant")
	}
}

func TestEvaluate_NonPrincipalEntryIgnored(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindGroup, ID: "sales", Perms: Perms{Read: true}},
	}})
	d, _ := Evaluate(s, Principal{Groups: []string{"engineering"}}, "/Engineering", ActionRead)
	if !d.NoMatch {
		t.Error("ACL exists but names a different principal → NoMatch")
	}
}

func TestEvaluate_UnknownAction_ReturnsDeny(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/a", Entries: []Entry{
		{Kind: KindGroup, ID: "x", Perms: Perms{Read: true, Write: true, Share: true}},
	}})
	d, _ := Evaluate(s, Principal{Groups: []string{"x"}}, "/a", Action("hack"))
	if d.Allowed {
		t.Error("unknown action must not be allowed")
	}
}

func TestEvaluate_InvalidPath_FallsThrough(t *testing.T) {
	// Empty / malformed paths come from upstream share handlers
	// probing without a concrete target. Evaluator has nothing to
	// say; return NoMatch so the caller's existing decision stands.
	s := newFakeStore()
	d, _ := Evaluate(s, Principal{IsAdmin: false}, "", ActionRead)
	if !d.NoMatch {
		t.Error("invalid path should return NoMatch (evaluator declines to decide)")
	}
	if d.Allowed {
		t.Error("invalid path must not be allowed independently")
	}
}

// Case-insensitive principal matching: an admin entering "Alice" or
// "Engineering" in the UI must still match the OIDC-asserted "alice"
// / "engineering". The reverse case (principal cased differently
// than the stored entry) is the more common IdP shape but the
// helper should handle both symmetrically.
func TestEvaluate_PrincipalMatch_IsCaseInsensitive_User(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindUser, ID: "Alice", Perms: Perms{Read: true}},
	}})
	d, _ := Evaluate(s, Principal{Username: "alice"}, "/Engineering", ActionRead)
	if !d.Allowed {
		t.Error("username match must be case-insensitive")
	}
}

func TestEvaluate_PrincipalMatch_IsCaseInsensitive_Group(t *testing.T) {
	s := newFakeStore()
	_ = s.Put(&FolderACL{Path: "/Engineering", Entries: []Entry{
		{Kind: KindGroup, ID: "Engineering", Perms: Perms{Read: true}},
	}})
	d, _ := Evaluate(s, Principal{Groups: []string{"engineering"}}, "/Engineering", ActionRead)
	if !d.Allowed {
		t.Error("group match must be case-insensitive")
	}
}

func TestEvaluate_StoreError_Propagates(t *testing.T) {
	s := &errorStore{err: errors.New("boom")}
	_, err := Evaluate(s, Principal{}, "/a", ActionRead)
	if err == nil {
		t.Error("store error must propagate")
	}
}

type errorStore struct{ err error }

func (e *errorStore) Get(string) (*FolderACL, error)           { return nil, e.err }
func (e *errorStore) Put(*FolderACL) error                     { return e.err }
func (e *errorStore) Delete(string) error                      { return e.err }
func (e *errorStore) List() ([]*FolderACL, error)              { return nil, e.err }
func (e *errorStore) WalkAncestors(string, func(*FolderACL) bool) error {
	return e.err
}
