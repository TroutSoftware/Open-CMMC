package fbhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/filebrowser/filebrowser/v2/settings"
)

// TestLogoutHandler_RequiresAuth — logoutHandler sits behind
// withUser so an unauthenticated POST cannot force-log-out another
// user nor serve as a CSRF vector.
func TestLogoutHandler_RequiresAuth(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/logout", nil)
	w := httptest.NewRecorder()
	// No X-Auth header, no cookie → withUser rejects with 401.
	d := &data{settings: &settings.Settings{Key: make([]byte, 32)}}
	status, _ := logoutHandler(w, r, d)
	if status != http.StatusUnauthorized {
		t.Errorf("unauthenticated logout got status=%d, want 401", status)
	}
}

// TestExtractor_XAuthHeader_AllMethods — primary channel for XHR.
func TestExtractor_XAuthHeader_AllMethods(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/x", nil)
			r.Header.Set("X-Auth", jwt)
			got, err := (&extractor{}).ExtractToken(r)
			if err != nil || got != jwt {
				t.Errorf("got %q err %v", got, err)
			}
		})
	}
}

// TestExtractor_Cookie_AllMethods — the HttpOnly cookie must work on
// every method so the SPA can POST /api/renew with only the cookie
// (no X-Auth available on cold reload).
func TestExtractor_Cookie_AllMethods(t *testing.T) {
	jwt := "aaa.bbb.ccc"
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/x", nil)
			r.AddCookie(&http.Cookie{Name: "auth", Value: jwt})
			got, err := (&extractor{}).ExtractToken(r)
			if err != nil || got != jwt {
				t.Errorf("got %q err %v", got, err)
			}
		})
	}
}

// TestExtractor_XAuthPrefersOverCookie — header wins when both are
// present, matching upstream's ordering.
func TestExtractor_XAuthPrefersOverCookie(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set("X-Auth", "header.header.header")
	r.AddCookie(&http.Cookie{Name: "auth", Value: "cookie.cookie.cookie"})
	got, _ := (&extractor{}).ExtractToken(r)
	if got != "header.header.header" {
		t.Errorf("header must win: got %q", got)
	}
}

// TestExtractor_NoToken_Error — neither header nor cookie → error.
func TestExtractor_NoToken_Error(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	if _, err := (&extractor{}).ExtractToken(r); err == nil {
		t.Error("expected ErrNoTokenInRequest")
	}
}

// TestExtractor_MalformedToken_Rejected — basic-auth-looking or
// wrong-shape values are rejected (dot-count check).
func TestExtractor_MalformedToken_Rejected(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	r.Header.Set("X-Auth", "not-a-jwt")
	r.AddCookie(&http.Cookie{Name: "auth", Value: "also-not-a-jwt"})
	if _, err := (&extractor{}).ExtractToken(r); err == nil {
		t.Error("expected malformed rejection")
	}
}
