package fbhttp

import (
	"net/http/httptest"
	"testing"

	cmmcmark "github.com/filebrowser/filebrowser/v2/cmmc/marking"
)

// Marking-enforcement helpers — the higher-level handler wiring is
// exercised via the SharePost / Raw / Patch integration paths; here
// we pin the pure helpers so downstream handlers can trust them.

func TestCUIMarkFor_NoStore_ReturnsNone(t *testing.T) {
	d := newTestData(t, false)
	d.store.FileMetadata = nil
	mark, err := cuiMarkFor(d, "/a.pdf")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if mark != cmmcmark.MarkNone {
		t.Errorf("got %q want MarkNone", mark)
	}
}

func TestCUIMarkFor_MissingRow_ReturnsNone(t *testing.T) {
	d := newTestData(t, false)
	mark, err := cuiMarkFor(d, "/never-seen.pdf")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if mark != cmmcmark.MarkNone {
		t.Errorf("got %q want MarkNone", mark)
	}
}

func TestCUIMarkFor_RoundTrip(t *testing.T) {
	d := newTestData(t, true)
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
	mark, err := cuiMarkFor(d, "/doc.pdf")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if mark != cmmcmark.MarkBasic {
		t.Errorf("got %q want %q", mark, cmmcmark.MarkBasic)
	}
}

// emitCUIAccessReject must not panic when d.user is nil — the public
// share handler runs before the withUser-loaded user might be set
// in edge cases; the audit emitter should degrade gracefully.
func TestEmitCUIAccessReject_NilUserSafe(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panicked: %v", rec)
		}
	}()
	r := httptest.NewRequest("POST", "/api/share/a.pdf", nil)
	d := &data{}
	emitCUIAccessReject(r, d, cmmcmark.MarkBasic, 403, "test")
}

// enforceCUIRead behavior — these pin the single choke point every
// read-path handler relies on. The gate must be tight by default
// (public CUI → 403; authed CUI without MFA → 401) and transparent
// for non-CUI.

func seedCUI(t *testing.T, d *data, relPath string) {
	t.Helper()
	abs, err := absPathForUser(d, relPath)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := d.store.FileMetadata.Put(&cmmcmark.FileMetadata{
		Path: abs, Mark: cmmcmark.MarkBasic, OwnerID: 1,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestEnforceCUIRead_NonCUI_PassesThrough(t *testing.T) {
	d := newTestData(t, false)
	r := httptest.NewRequest("GET", "/api/raw/x.pdf", nil)
	if s := enforceCUIRead(r, d, "/x.pdf", "test", false); s != 0 {
		t.Errorf("non-CUI blocked; status=%d", s)
	}
}

func TestEnforceCUIRead_Public_CUI_Blocks403(t *testing.T) {
	d := newTestData(t, false)
	seedCUI(t, d, "/x.pdf")
	r := httptest.NewRequest("GET", "/api/public/dl/xxx/x.pdf", nil)
	if s := enforceCUIRead(r, d, "/x.pdf", "test", true); s != 403 {
		t.Errorf("public CUI not hard-403; status=%d", s)
	}
}

func TestEnforceCUIRead_Authed_CUI_NoMFA_Blocks401(t *testing.T) {
	d := newTestData(t, false)
	// default AuthMethod is MethodOIDCAuth only when explicitly set;
	// populate settings so hasFreshMFA takes the OIDC branch.
	d.settings = newOIDCSettings()
	seedCUI(t, d, "/x.pdf")
	r := httptest.NewRequest("GET", "/api/raw/x.pdf", nil)
	if s := enforceCUIRead(r, d, "/x.pdf", "test", false); s != 401 {
		t.Errorf("CUI without fresh MFA not 401; status=%d", s)
	}
}

func TestEnforceCUIRead_NonOIDC_CUI_Passes(t *testing.T) {
	// Non-OIDC AuthMethods (json/proxy/hook/none) don't emit MFA
	// claims; hasFreshMFA returns true by design. This test pins
	// that behavior so a refactor doesn't silently change it.
	d := newTestData(t, false)
	d.settings = newJSONSettings()
	seedCUI(t, d, "/x.pdf")
	r := httptest.NewRequest("GET", "/api/raw/x.pdf", nil)
	if s := enforceCUIRead(r, d, "/x.pdf", "test", false); s != 0 {
		t.Errorf("non-OIDC CUI unexpectedly blocked; status=%d", s)
	}
}
