package fbhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/users"
)

// Outcome derivation matrix for withAuditEmit. Each row asserts the
// mapping from handler return to the emitted audit event's outcome
// and status fields.
func TestWithAuditEmit_OutcomeMatrix(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	cases := []struct {
		name        string
		handlerRet  func() (int, error)
		wantOutcome string
		wantStatus  int
	}{
		{"200 success", func() (int, error) { return 200, nil }, audit.OutcomeSuccess, 200},
		{"304 success", func() (int, error) { return 304, nil }, audit.OutcomeSuccess, 304},
		{"0 (already written) success", func() (int, error) { return 0, nil }, audit.OutcomeSuccess, 0},
		{"401 reject", func() (int, error) { return 401, nil }, audit.OutcomeReject, 401},
		{"403 reject", func() (int, error) { return 403, nil }, audit.OutcomeReject, 403},
		{"404 reject", func() (int, error) { return 404, nil }, audit.OutcomeReject, 404},
		{"500 failure", func() (int, error) { return 500, nil }, audit.OutcomeFailure, 500},
		{"err-only failure", func() (int, error) { return 0, errors.New("boom") }, audit.OutcomeFailure, 0},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			mem.Reset()
			d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
			d.user = &users.User{ID: 7, Username: "alice"}
			inner := func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
				return c.handlerRet()
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/test", nil)

			status, _ := withAuditEmit("user.create", inner)(w, r, d)
			if status != c.wantStatus {
				t.Errorf("status=%d, want %d", status, c.wantStatus)
			}
			evts := mem.Events()
			if len(evts) != 1 {
				t.Fatalf("expected 1 event, got %d", len(evts))
			}
			got := evts[0]
			if got.Outcome != c.wantOutcome {
				t.Errorf("outcome=%q, want %q", got.Outcome, c.wantOutcome)
			}
			if got.Status != c.wantStatus {
				t.Errorf("status field=%d, want %d", got.Status, c.wantStatus)
			}
			if got.Action != "user.create" {
				t.Errorf("action=%q", got.Action)
			}
			if got.UserID != "7" || got.Username != "alice" {
				t.Errorf("identity fields wrong: id=%q name=%q", got.UserID, got.Username)
			}
			if got.Resource != "/api/test" {
				t.Errorf("resource=%q", got.Resource)
			}
		})
	}
}

// TestWithAuditEmit_CorrelationIDThreaded ensures the wrapper picks up
// the correlation id written by CorrelationMiddleware further up the
// chain. If this breaks, SIEM join-by-correlation stops working.
func TestWithAuditEmit_CorrelationIDThreaded(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	inner := func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) { return 200, nil }
	r := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	r = r.WithContext(audit.WithCorrelationID(r.Context(), "corr-xyz-123"))

	_, _ = withAuditEmit("user.create", inner)(httptest.NewRecorder(), r, d)
	evts := mem.Events()
	if len(evts) != 1 || evts[0].CorrelationID != "corr-xyz-123" {
		t.Errorf("correlation id not threaded; got %+v", evts)
	}
}

// TestWithAuditEmit_NilUser handles the pre-withUser case (e.g.,
// unauthenticated requests that still pass through the wrapper). The
// event should still fire; identity fields stay empty.
func TestWithAuditEmit_NilUser(t *testing.T) {
	orig := audit.Default()
	mem := audit.NewMemoryEmitter()
	audit.SetDefault(mem)
	defer audit.SetDefault(orig)

	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	d.user = nil
	inner := func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) { return 401, nil }
	r := httptest.NewRequest(http.MethodPost, "/api/x", nil)
	_, _ = withAuditEmit("authz.priv.reject", inner)(httptest.NewRecorder(), r, d)
	evts := mem.Events()
	if len(evts) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evts))
	}
	if evts[0].UserID != "" || evts[0].Username != "" {
		t.Errorf("nil user should leave identity empty; got id=%q name=%q", evts[0].UserID, evts[0].Username)
	}
}
