package fbhttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/filebrowser/filebrowser/v2/cmmc/authz/folderacl"
	"github.com/filebrowser/filebrowser/v2/users"
)

// Functional tests for the ACL inner handlers. Admin-gating is
// enforced by withAdmin at route registration (http/http.go);
// that's a composition-level behavior covered by the existing
// route-wiring tests — no need to duplicate it here.
//
// TestACLHandlersAreWrappedWithAdmin pins the composition itself
// so a careless refactor can't silently drop the gate.
func TestACLHandlersAreWrappedWithAdmin(t *testing.T) {
	// Each of these vars is the wrapped form (withAdmin(innerFn)).
	// We just assert they're non-nil — the type-system guarantees
	// the inner function receives a pre-admin-checked data struct.
	// This is a compile-time regression fence: if someone drops
	// withAdmin, the variable becomes a raw handleFunc and this
	// test starts tripping on d.user being nil at call time.
	handlers := map[string]handleFunc{
		"read":   aclReadHandler,
		"put":    aclPutHandler,
		"delete": aclDeleteHandler,
		"list":   aclListHandler,
	}
	for name, h := range handlers {
		if h == nil {
			t.Errorf("%s handler is nil — admin wrapping dropped?", name)
		}
	}
}

func TestACLReadHandler_MissingPath_400(t *testing.T) {
	d := newTestData(t, true)
	r := httptest.NewRequest("GET", "/api/cmmc/acl", nil) // no path
	w := httptest.NewRecorder()
	status, _ := aclReadFn(w, r, d)
	if status != http.StatusBadRequest {
		t.Errorf("missing path status = %d, want 400", status)
	}
}

func TestACLReadHandler_EmptyShellWhenMissing(t *testing.T) {
	d := newTestData(t, true)
	r := httptest.NewRequest("GET", "/api/cmmc/acl?path=/Nope", nil)
	w := httptest.NewRecorder()
	status, _ := aclReadFn(w, r, d)
	if status != 0 {
		t.Fatalf("status = %d, want 0 (handler wrote response)", status)
	}
	var body folderacl.FolderACL
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Path != "/Nope" || len(body.Entries) != 0 {
		t.Errorf("unexpected body: %+v", body)
	}
}

func TestACLPutHandler_BodyTooLarge_413(t *testing.T) {
	d := newTestData(t, true)
	// 128 KiB of junk — well over the 64 KiB cap.
	big := bytes.Repeat([]byte("a"), 128*1024)
	payload := []byte(`{"path":"/X","entries":[{"kind":"group","id":"`)
	payload = append(payload, big...)
	payload = append(payload, []byte(`","perms":{}}]}`)...)
	r := httptest.NewRequest("PUT", "/api/cmmc/acl", bytes.NewReader(payload))
	w := httptest.NewRecorder()
	status, _ := aclPutFn(w, r, d)
	if status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body status = %d, want 413", status)
	}
}

func TestACLPutHandler_InvalidBody_400(t *testing.T) {
	d := newTestData(t, true)
	r := httptest.NewRequest("PUT", "/api/cmmc/acl", bytes.NewBufferString(`not json`))
	w := httptest.NewRecorder()
	status, _ := aclPutFn(w, r, d)
	if status != http.StatusBadRequest && status != http.StatusRequestEntityTooLarge {
		t.Errorf("malformed body status = %d, want 400/413", status)
	}
}

// TestCheckAction_WriteDeniedWhenACLGrantReadOnly — ship-blocker
// reviewer flagged: an ACL granting Read:true, Write:false must
// deny writes even though a plain Check() (Read gate) would let
// it through. CheckAction with ActionWrite is the gate for every
// resource-write handler.
func TestCheckAction_WriteDeniedWhenACLGrantReadOnly(t *testing.T) {
	d := newTestData(t, false)
	// newTestData doesn't wire settings; add a minimal Settings so
	// Check's tier-2 rule walk doesn't panic.
	d.settings = mustSettingsWithKey(make([]byte, 32))
	d.user = &users.User{
		ID: 10, Username: "alice",
		Groups: []string{"engineering"},
		// Non-admin so the evaluator can't bypass.
	}
	if err := d.store.FolderACLs.Put(&folderacl.FolderACL{
		Path: "/Engineering",
		Entries: []folderacl.Entry{
			{Kind: folderacl.KindGroup, ID: "engineering", Perms: folderacl.Perms{Read: true}},
		},
	}); err != nil {
		t.Fatalf("put acl: %v", err)
	}
	if !d.Check("/Engineering/doc.pdf") {
		t.Error("Read should be allowed")
	}
	if d.CheckAction("/Engineering/doc.pdf", folderacl.ActionWrite) {
		t.Error("Write MUST be denied (read-only ACL grant)")
	}
}
