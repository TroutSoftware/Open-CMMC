package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/filebrowser/filebrowser/v2/users"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newTestUser() *users.User {
	return &users.User{ID: 42, Username: "alice", Perm: users.Permissions{Admin: false, Download: true}}
}

// --- Mint / round-trip ----------------------------------------------------

func TestMint_ProducesParsableHS256(t *testing.T) {
	signed, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: time.Hour, MFAAt: time.Now()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if strings.Count(signed, ".") != 2 {
		t.Fatalf("token shape not JWT: %q", signed)
	}
	var c Claims
	tok, err := jwt.ParseWithClaims(signed, &c, func(_ *jwt.Token) (interface{}, error) { return testKey, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		t.Fatalf("parse: err=%v valid=%v", err, tok != nil && tok.Valid)
	}
	if c.User.Username != "alice" {
		t.Errorf("User.Username = %q", c.User.Username)
	}
	if c.User.ID != 42 {
		t.Errorf("User.ID = %d", c.User.ID)
	}
	if c.JTI == "" {
		t.Errorf("JTI missing")
	}
	if c.MFAAt == 0 {
		t.Errorf("MFAAt missing despite MintOptions.MFAAt set")
	}
}

func TestMint_JTI_IsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		signed, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: time.Hour})
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		var c Claims
		_, _ = jwt.ParseWithClaims(signed, &c, func(_ *jwt.Token) (interface{}, error) { return testKey, nil },
			jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
		if _, dup := seen[c.JTI]; dup {
			t.Fatalf("JTI collision at iter %d", i)
		}
		seen[c.JTI] = struct{}{}
	}
}

func TestMint_RequireMFAAt_RejectsZero(t *testing.T) {
	_, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: time.Hour, RequireMFAAt: true})
	if err == nil {
		t.Fatalf("RequireMFAAt=true with zero MFAAt must error")
	}
}

func TestMint_RequireMFAAt_AcceptsNonZero(t *testing.T) {
	_, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: time.Hour, RequireMFAAt: true, MFAAt: time.Now()})
	if err != nil {
		t.Fatalf("RequireMFAAt=true with non-zero MFAAt should succeed: %v", err)
	}
}

func TestMint_TTL_MustBePositive(t *testing.T) {
	_, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: 0})
	if err == nil {
		t.Fatalf("TTL=0 must error")
	}
}

// --- RequiresFreshMFA middleware -----------------------------------------

func mintWithMFA(t *testing.T, mfaAt time.Time) string {
	t.Helper()
	signed, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: time.Hour, MFAAt: mfaAt})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return signed
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

func keyLookup(_ *http.Request) ([]byte, error) { return testKey, nil }

func TestRequiresFreshMFA_PassesWhenRecent(t *testing.T) {
	tok := mintWithMFA(t, time.Now().Add(-5*time.Minute))
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("code=%d, want 200 (fresh MFA should pass)", w.Code)
	}
}

func TestRequiresFreshMFA_RejectsStale(t *testing.T) {
	tok := mintWithMFA(t, time.Now().Add(-30*time.Minute))
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: tok})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want 401 (stale MFA)", w.Code)
	}
}

func TestRequiresFreshMFA_RejectsMissingClaim(t *testing.T) {
	// Mint WITHOUT MFAAt.
	signed, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: signed})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want 401 (missing MFA claim = fail-closed)", w.Code)
	}
}

func TestRequiresFreshMFA_RejectsNoToken(t *testing.T) {
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want 401 (no token)", w.Code)
	}
}

func TestRequiresFreshMFA_RejectsWrongSignature(t *testing.T) {
	// Mint with a different key → signature fails with the middleware's key.
	wrongKey := []byte("11111111aaaaaaaabbbbbbbbcccccccc")
	signed, _, err := Mint(newTestUser(), wrongKey, MintOptions{TTL: time.Hour, MFAAt: time.Now()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: signed})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want 401 (bad signature)", w.Code)
	}
}

func TestRequiresFreshMFA_AcceptsXAuthHeader(t *testing.T) {
	tok := mintWithMFA(t, time.Now())
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodPost, "/protected", nil)
	r.Header.Set("X-Auth", tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("code=%d, want 200 (X-Auth header should work)", w.Code)
	}
}

func TestRequiresFreshMFA_RejectsExpiredToken(t *testing.T) {
	// Mint with a very short TTL and let it expire.
	signed, _, err := Mint(newTestUser(), testKey, MintOptions{TTL: 1 * time.Millisecond, MFAAt: time.Now()})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	h := RequiresFreshMFA(DefaultFreshMFAThreshold, keyLookup, okHandler)
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: signed})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code=%d, want 401 (expired)", w.Code)
	}
}

// --- Claims helpers -------------------------------------------------------

func TestClaims_ToUser(t *testing.T) {
	c := Claims{User: UserInfo{ID: 7, Username: "u", Perm: users.Permissions{Admin: true}}}
	u := c.ToUser()
	if u.ID != 7 || u.Username != "u" || !u.Perm.Admin {
		t.Errorf("ToUser did not round-trip: %+v", u)
	}
}

func TestIsFreshMFA(t *testing.T) {
	threshold := 10 * time.Minute
	cases := []struct {
		name  string
		claim *Claims
		want  bool
	}{
		{"nil claims", nil, false},
		{"zero mfaAt", &Claims{MFAAt: 0}, false},
		{"just now", &Claims{MFAAt: time.Now().Unix()}, true},
		{"5 min ago", &Claims{MFAAt: time.Now().Add(-5 * time.Minute).Unix()}, true},
		{"just inside threshold", &Claims{MFAAt: time.Now().Add(-threshold + time.Second).Unix()}, true},
		{"over threshold", &Claims{MFAAt: time.Now().Add(-11 * time.Minute).Unix()}, false},
		{"1 hour ago", &Claims{MFAAt: time.Now().Add(-time.Hour).Unix()}, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := IsFreshMFA(c.claim, threshold); got != c.want {
				t.Errorf("IsFreshMFA(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestUserInfoFromUser_RoundTrips(t *testing.T) {
	u := &users.User{ID: 3, Username: "x", Perm: users.Permissions{Download: true}, Locale: "en"}
	ui := UserInfoFromUser(u)
	if ui.ID != 3 || ui.Username != "x" || !ui.Perm.Download || ui.Locale != "en" {
		t.Errorf("UserInfoFromUser dropped fields: %+v", ui)
	}
}
