package fbhttp

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/settings"
)

// TestPrintToken_CarriesForwardMFAAt — regression pin for the
// root cause of the classify-folder 401: /api/renew used to mint
// a JWT without cmmc_mfa_at, so withFreshMFA on the very next
// privileged request (PUT /api/cmmc/marking) failed-closed. This
// test drives printToken with a context that already carries the
// MFA timestamp (stashed by withUser on the incoming request) and
// asserts the resulting token retains it.
func TestPrintToken_CarriesForwardMFAAt(t *testing.T) {
	d := newTestData(t, true)
	// newTestData doesn't wire settings.Key. Give it a 32+ byte one
	// so sessionSigningKey derivation works.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	d.settings = mustSettingsWithKey(key)

	mfaAt := time.Now().Add(-5 * time.Minute).Unix() // 5 min ago (fresh)

	// Simulate the state withUser would have set — jti + mfaAt on
	// the request context.
	r := httptest.NewRequest("POST", "/api/renew", nil)
	ctx := withJTI(r.Context(), "test-jti-123")
	ctx = withMFAAt(ctx, mfaAt)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	if _, err := printToken(w, r, d, d.user, time.Hour); err != nil {
		t.Fatalf("printToken: %v", err)
	}

	signed := w.Body.String()
	if signed == "" || strings.Count(signed, ".") != 2 {
		t.Fatalf("printToken did not write a signed JWT: %q", signed)
	}

	// Parse the minted JWT and confirm cmmc_mfa_at + jti survived.
	var tk authToken
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if _, err := parser.ParseWithClaims(signed, &tk, func(_ *jwt.Token) (interface{}, error) {
		return sessionSigningKey(d.settings), nil
	}); err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if tk.CmmcMFAAt != mfaAt {
		t.Errorf("cmmc_mfa_at dropped by printToken: got %d, want %d", tk.CmmcMFAAt, mfaAt)
	}
	if tk.ID != "test-jti-123" {
		t.Errorf("jti dropped by printToken: got %q", tk.ID)
	}
}

// TestPrintToken_EmptyContextGeneratesFreshJTI_NoMFAAt — the
// native-login path (POST /api/login): no prior context, no MFA
// happened, so the minted JWT has a fresh jti and cmmc_mfa_at=0.
// Privileged handlers then refuse with 401 — correct posture.
func TestPrintToken_EmptyContextGeneratesFreshJTI_NoMFAAt(t *testing.T) {
	d := newTestData(t, false)
	key := make([]byte, 32)
	d.settings = mustSettingsWithKey(key)

	r := httptest.NewRequest("POST", "/api/login", nil)
	w := httptest.NewRecorder()
	if _, err := printToken(w, r, d, d.user, time.Hour); err != nil {
		t.Fatalf("printToken: %v", err)
	}

	var tk authToken
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	_, err := parser.ParseWithClaims(w.Body.String(), &tk, func(_ *jwt.Token) (interface{}, error) {
		return sessionSigningKey(d.settings), nil
	})
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	if tk.ID == "" {
		t.Error("native-login printToken must still generate a jti")
	}
	if tk.CmmcMFAAt != 0 {
		t.Errorf("native login must NOT claim MFA: cmmc_mfa_at=%d", tk.CmmcMFAAt)
	}
}

// TestMFAAtContextRoundTrip — pin the two helpers.
func TestMFAAtContextRoundTrip(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	// Unset → 0.
	if got := mfaAtFromContext(r.Context()); got != 0 {
		t.Errorf("default mfaAt = %d, want 0", got)
	}
	// Zero input → context unchanged.
	r = r.WithContext(withMFAAt(r.Context(), 0))
	if got := mfaAtFromContext(r.Context()); got != 0 {
		t.Errorf("zero-value write still produced %d", got)
	}
	// Real value round-trips.
	now := time.Now().Unix()
	r = r.WithContext(withMFAAt(r.Context(), now))
	if got := mfaAtFromContext(r.Context()); got != now {
		t.Errorf("round-trip: got %d, want %d", got, now)
	}
}

// mustSettingsWithKey returns a *settings.Settings with a known key
// and the OIDC auth method so downstream handlers behave as they
// would in production.
func mustSettingsWithKey(key []byte) *settings.Settings {
	return &settings.Settings{
		AuthMethod: fbAuth.MethodOIDCAuth,
		Key:        key,
	}
}
