package fbhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	session "github.com/filebrowser/filebrowser/v2/cmmc/auth/session"
	"github.com/filebrowser/filebrowser/v2/users"
)

// mintSession is a test helper that produces a session JWT using the
// same key the data struct is configured with.
func mintTestSession(t *testing.T, key []byte, mfaAt time.Time) string {
	t.Helper()
	signed, _, err := session.Mint(&users.User{ID: 1, Username: "alice"}, key, session.MintOptions{
		TTL:   time.Hour,
		MFAAt: mfaAt,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return signed
}

// okHandler is the "inner" handler withFreshMFA wraps. Returns 0 so
// the handle() wrapper treats it as "response already written" — easier
// to assert on directly.
var fmOkHandler handleFunc = func(w http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("admin op ok"))
	return 0, nil
}

func TestWithFreshMFA_PassThroughWhenNotOIDC(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	status, _ := withFreshMFA(fmOkHandler)(w, r, d)
	if status != 0 || w.Code != http.StatusOK {
		t.Errorf("json auth should pass through; got status=%d code=%d", status, w.Code)
	}
}

func TestWithFreshMFA_OIDCRejectsNoToken(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	status, _ := withFreshMFA(fmOkHandler)(w, r, d)
	if status != http.StatusUnauthorized {
		t.Errorf("OIDC + no token should 401; got %d", status)
	}
}

func TestWithFreshMFA_OIDCRejectsMissingMFAClaim(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	// Mint a session WITHOUT MFAAt (zero time).
	tok := mintTestSession(t, d.settings.Key, time.Time{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	r.Header.Set("X-Auth", tok)
	status, _ := withFreshMFA(fmOkHandler)(w, r, d)
	if status != http.StatusUnauthorized {
		t.Errorf("missing MFAAt claim should 401 (fail-closed); got %d", status)
	}
}

func TestWithFreshMFA_OIDCRejectsStaleMFA(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	tok := mintTestSession(t, d.settings.Key, time.Now().Add(-30*time.Minute))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	r.Header.Set("X-Auth", tok)
	status, _ := withFreshMFA(fmOkHandler)(w, r, d)
	if status != http.StatusUnauthorized {
		t.Errorf("stale MFA should 401; got %d", status)
	}
}

func TestWithFreshMFA_OIDCPassesOnFreshMFA(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	tok := mintTestSession(t, d.settings.Key, time.Now().Add(-5*time.Minute))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	r.Header.Set("X-Auth", tok)
	status, _ := withFreshMFA(fmOkHandler)(w, r, d)
	if status != 0 || w.Code != http.StatusOK {
		t.Errorf("fresh MFA should pass; got status=%d code=%d", status, w.Code)
	}
}

func TestWithFreshMFA_OIDCRejectsWrongKey(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	// Sign with a different key than d.settings.Key.
	tok := mintTestSession(t, []byte("wrong-key-padding-to-minimum-length"), time.Now())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	r.Header.Set("X-Auth", tok)
	status, _ := withFreshMFA(fmOkHandler)(w, r, d)
	if status != http.StatusUnauthorized {
		t.Errorf("bad signature should 401; got %d", status)
	}
}

// TestWithFreshMFA_EmitsRejectAuditEvent proves that every reject
// branch actually emits an authz.priv.reject audit event with the
// expected reason. If a future refactor drops the emit call, the SIEM
// loses visibility into the rejection — this test stops that silently.
func TestWithFreshMFA_EmitsRejectAuditEvent(t *testing.T) {
	// Swap the package default for an in-memory sink.
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	cases := []struct {
		name       string
		buildReq   func(t *testing.T, d *data) *http.Request
		wantReason string
	}{
		{
			name: "no token",
			buildReq: func(_ *testing.T, _ *data) *http.Request {
				return httptest.NewRequest(http.MethodPost, "/api/users", nil)
			},
			wantReason: "no session token",
		},
		{
			name: "invalid token",
			buildReq: func(_ *testing.T, _ *data) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
				r.Header.Set("X-Auth", "not.a.jwt")
				return r
			},
			wantReason: "invalid session token",
		},
		{
			name: "stale MFA",
			buildReq: func(t *testing.T, d *data) *http.Request {
				tok := mintTestSession(t, d.settings.Key, time.Now().Add(-time.Hour))
				r := httptest.NewRequest(http.MethodPost, "/api/users", nil)
				r.Header.Set("X-Auth", tok)
				return r
			},
			wantReason: "stale MFA",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			mem.Reset()
			d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
			w := httptest.NewRecorder()
			r := c.buildReq(t, d)
			status, _ := withFreshMFA(fmOkHandler)(w, r, d)
			if status != http.StatusUnauthorized {
				t.Errorf("status=%d, want 401", status)
			}
			evts := mem.Events()
			if len(evts) != 1 {
				t.Fatalf("expected 1 audit event, got %d", len(evts))
			}
			got := evts[0]
			if got.Action != audit.ActionAuthzPrivReject {
				t.Errorf("action=%q, want %q", got.Action, audit.ActionAuthzPrivReject)
			}
			if got.Outcome != audit.OutcomeReject {
				t.Errorf("outcome=%q, want %q", got.Outcome, audit.OutcomeReject)
			}
			if got.Reason != c.wantReason {
				t.Errorf("reason=%q, want %q", got.Reason, c.wantReason)
			}
			if got.Resource != "/api/users" {
				t.Errorf("resource=%q", got.Resource)
			}
			if got.Status != http.StatusUnauthorized {
				t.Errorf("status field=%d", got.Status)
			}
		})
	}
}

func TestSetFreshMFAThreshold(t *testing.T) {
	orig := getFreshMFAThreshold()
	defer SetFreshMFAThreshold(orig)

	SetFreshMFAThreshold(5 * time.Minute)
	if getFreshMFAThreshold() != 5*time.Minute {
		t.Errorf("threshold not applied: %v", getFreshMFAThreshold())
	}
	// Zero or negative should be ignored (don't let a bad env wipe the default).
	SetFreshMFAThreshold(0)
	if getFreshMFAThreshold() != 5*time.Minute {
		t.Errorf("zero override should have been rejected; got %v", getFreshMFAThreshold())
	}
	SetFreshMFAThreshold(-1 * time.Hour)
	if getFreshMFAThreshold() != 5*time.Minute {
		t.Errorf("negative override should have been rejected; got %v", getFreshMFAThreshold())
	}
}
