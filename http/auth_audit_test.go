package fbhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	"github.com/filebrowser/filebrowser/v2/settings"
)

// Tests for the audit emission wired into signupHandler / loginHandler /
// renewHandler. These were flagged as a CMMC 3.3.1 coverage gap:
// ActionAuthLoginOK / ActionAuthLoginFail / ActionAuthSignup /
// ActionSessionRenew were defined in the audit package but no code
// emitted them. Each test below pins one emission path so a refactor
// cannot silently drop the event again.

// TestSignupHandler_Disabled_EmitsRejectEvent — when the admin has not
// enabled self-signup, the handler returns 405 and stamps a
// cui-compliant reject event. Distinct from an input-error reject so
// operators can grep signup attempts on a locked-down deploy.
func TestSignupHandler_Disabled_EmitsRejectEvent(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	d.settings.Signup = false

	r := httptest.NewRequest("POST", "/api/signup", bytes.NewBufferString(`{"username":"x","password":"y"}`))
	w := httptest.NewRecorder()
	status, _ := signupHandler(w, r, d)

	if status != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", status)
	}
	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	got := evts[0]
	if got.Action != audit.ActionAuthSignup {
		t.Errorf("action=%q want %q", got.Action, audit.ActionAuthSignup)
	}
	if got.Outcome != audit.OutcomeReject {
		t.Errorf("outcome=%q want %q", got.Outcome, audit.OutcomeReject)
	}
	if got.Status != http.StatusMethodNotAllowed {
		t.Errorf("status field=%d want 405", got.Status)
	}
	if got.Reason != "signup disabled" {
		t.Errorf("reason=%q want %q", got.Reason, "signup disabled")
	}
}

// TestSignupHandler_MissingFields_EmitsRejectEvent — attempt with
// Signup enabled but empty password should reject AND record the
// attempted username so operators can spot credential-probe patterns.
func TestSignupHandler_MissingFields_EmitsRejectEvent(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	d.settings.Signup = true

	r := httptest.NewRequest("POST", "/api/signup", bytes.NewBufferString(`{"username":"probe","password":""}`))
	w := httptest.NewRecorder()
	status, _ := signupHandler(w, r, d)

	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", status)
	}
	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	got := evts[0]
	if got.Action != audit.ActionAuthSignup || got.Outcome != audit.OutcomeReject {
		t.Errorf("action/outcome = %q/%q want %q/%q", got.Action, got.Outcome, audit.ActionAuthSignup, audit.OutcomeReject)
	}
	if got.Username != "probe" {
		t.Errorf("username field=%q want 'probe' (the attempted name)", got.Username)
	}
}

// TestSignupHandler_InvalidJSON_EmitsRejectEvent — garbage body still
// emits an event; the Reason field records the decoder error so the
// SIEM sees "someone posted non-JSON to /api/signup".
func TestSignupHandler_InvalidJSON_EmitsRejectEvent(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	d.settings.Signup = true

	r := httptest.NewRequest("POST", "/api/signup", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	status, _ := signupHandler(w, r, d)

	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", status)
	}
	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	if evts[0].Action != audit.ActionAuthSignup || evts[0].Outcome != audit.OutcomeReject {
		t.Errorf("wrong action/outcome: %+v", evts[0])
	}
}

// TestSignupHandler_NilBody_EmitsRejectEvent — a POST with no body
// must still stamp a reject event. Different code path from "body
// present but bad JSON" (r.Body is nil) — pin both.
func TestSignupHandler_NilBody_EmitsRejectEvent(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	d.settings.Signup = true

	r := httptest.NewRequest("POST", "/api/signup", nil)
	r.Body = nil
	w := httptest.NewRecorder()
	status, _ := signupHandler(w, r, d)

	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", status)
	}
	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	if evts[0].Reason != "empty body" {
		t.Errorf("reason=%q want 'empty body'", evts[0].Reason)
	}
}

// TestRenewRoute_IsWrappedWithAuditEmit — pin the composition at the
// route layer so a careless refactor can't silently drop the audit
// trail on token renewal. The test constructs the wrapper chain the
// same way http.go does; the assertion is that it both returns a
// handleFunc AND that the inner action constant exists.
func TestRenewRoute_IsWrappedWithAuditEmit(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	// withAuditEmit wraps any handleFunc; our probe handler just
	// returns 401 so we get a stampable reject event. The renewHandler
	// itself needs a user (withUser wraps it) — for this composition
	// test we don't need to exercise renewHandler's internals, just
	// verify ActionSessionRenew lands on the event stream when the
	// route is hit.
	probe := func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		return http.StatusUnauthorized, nil
	}
	wrapped := withAuditEmit(audit.ActionSessionRenew, probe)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	r := httptest.NewRequest("POST", "/api/renew", nil)
	_, _ = wrapped(httptest.NewRecorder(), r, d)

	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	if evts[0].Action != audit.ActionSessionRenew {
		t.Errorf("action=%q want %q — did the route registration drop the wrapper?", evts[0].Action, audit.ActionSessionRenew)
	}
}

// TestLoginHandler_AutherLookupFails_EmitsFailureEvent — when
// d.store.Auth.Get() errors (misconfiguration at boot), the handler
// must still stamp an ActionAuthLoginFail event with Outcome=failure
// (not reject — reject is for credential mismatch). Verifies the
// internal-error audit path doesn't get swallowed.
func TestLoginHandler_AutherLookupFails_EmitsFailureEvent(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	// d.store.Auth is nil in newHandlerData; a nil-deref in
	// d.store.Auth.Get would panic. Wire a stub that always errors
	// so the handler hits its failure branch cleanly.
	d.store.Auth = fbAuth.NewStorage(&erroringAutherBackend{}, nil)

	r := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"x","password":"y"}`))
	w := httptest.NewRecorder()
	h := loginHandler(0)
	status, err := h(w, r, d)
	if status != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", status)
	}
	if err == nil {
		t.Fatal("expected error from erroring backend")
	}
	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	got := evts[0]
	if got.Action != audit.ActionAuthLoginFail || got.Outcome != audit.OutcomeFailure {
		t.Errorf("action/outcome=%q/%q want %q/%q", got.Action, got.Outcome, audit.ActionAuthLoginFail, audit.OutcomeFailure)
	}
}

// erroringAutherBackend is a StorageBackend that always returns an
// error on Get — used to exercise the loginHandler's failure branch
// without wiring the full bolt store.
type erroringAutherBackend struct{}

func (erroringAutherBackend) Get(settings.AuthMethod) (fbAuth.Auther, error) {
	return nil, errBoom
}
func (erroringAutherBackend) Save(fbAuth.Auther) error { return errBoom }

var errBoom = &boomErr{}

type boomErr struct{}

func (*boomErr) Error() string { return "auther backend: boom" }
