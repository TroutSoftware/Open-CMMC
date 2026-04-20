package fbhttp

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
)

// TestSecurityHeaders_SetOnEveryResponse pins the CMMC-mandated set of
// response security headers. Every HTTP response the router produces
// must carry this bundle; the gorilla/mux middleware we install at
// http/http.go does that unconditionally. Dropping any one of these
// is an SSP regression (3.13.8 / 3.13.13 / 3.13.15 / 3.14.x).
//
// We hit /health because it does not route through the static handler,
// so the assetsFS content is never read — the fstest.MapFS fixture is
// a placeholder to satisfy fs.Sub. If NewHandler ever starts reading
// index.html at construction time (CSP nonce injection, say), this
// test will need a real asset body.
func TestSecurityHeaders_SetOnEveryResponse(t *testing.T) {
	_, fake, _ := newHandlerData(t, settings.AuthMethod("json"))
	assetsFS, _ := fs.Sub(fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte{}},
	}, ".")
	srv := &settings.Server{Root: "/tmp", Address: "127.0.0.1", Port: "0"}
	handler, err := NewHandler(nil, nil, nil, seedStorage(fake), srv, assetsFS)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// Hit the /health endpoint — unauthenticated, always reachable.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	want := map[string]string{
		"Content-Security-Policy":   `default-src 'self'; style-src 'unsafe-inline';`,
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
	}
	for h, wantValue := range want {
		got := rec.Header().Get(h)
		if got != wantValue {
			t.Errorf("header %q = %q, want %q", h, got, wantValue)
		}
	}
}

// seedStorage builds a storage.Storage with the minimum wiring the
// router needs. Non-OIDC stores (Settings/Share/Auth) aren't touched
// by /health, so we can leave them nil.
func seedStorage(users *fakeUserStore) *storage.Storage {
	return &storage.Storage{
		Users:          users,
		OIDCIdentities: newFakeIdentityStore(),
	}
}
