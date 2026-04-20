package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// mockIdPConfig configures the token the mock /token endpoint returns.
type mockIdPConfig struct {
	key      *rsa.PrivateKey
	clientID string
	claims   map[string]interface{}
}

// newFullMockIdP is a more complete version of newTestIssuer that also
// serves /token so we can exercise ExchangeAndVerify end-to-end.
func newFullMockIdP(t *testing.T, cfg *mockIdPConfig) (issuer string, shutdown func()) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	issuer = srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                   issuer,
			"authorization_endpoint":   issuer + "/authorize",
			"token_endpoint":           issuer + "/token",
			"jwks_uri":                 issuer + "/jwks",
			"response_types_supported": []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := jose.JSONWebKey{Key: &cfg.key.PublicKey, KeyID: "test-1", Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Minimal validation: must be POST, must contain code and code_verifier.
		_ = r.ParseForm()
		if r.Method != http.MethodPost || r.FormValue("code") == "" || r.FormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request"})
			return
		}
		claims := make(map[string]interface{}, len(cfg.claims))
		for k, v := range cfg.claims {
			claims[k] = v
		}
		// Baseline claims — caller can override.
		if _, ok := claims["iss"]; !ok {
			claims["iss"] = issuer
		}
		if _, ok := claims["aud"]; !ok {
			claims["aud"] = cfg.clientID
		}
		if _, ok := claims["iat"]; !ok {
			claims["iat"] = time.Now().Unix()
		}
		if _, ok := claims["exp"]; !ok {
			claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
		}
		idToken := signIDToken(t, cfg.key, jose.RS256, claims)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
			"expires_in":   300,
		})
	})
	return issuer, srv.Close
}

// initWithCtx initializes the singleton against a test issuer using the
// TLS-trusting context.
func initWithCtx(t *testing.T, issuer, clientID string) {
	t.Helper()
	resetSingleton()
	cfg := Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: "secret",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
		UsernameClaim: "preferred_username",
		GroupsClaim:   "groups",
		AdminGroups:   []string{"cmmc-admins"},
		MFAClaim:      "amr",
	}
	if err := InitProvider(testCtx(), cfg); err != nil {
		t.Fatalf("InitProvider: %v", err)
	}
}

func TestBuildAuthorizeRequest_IncludesPKCEStateNonce(t *testing.T) {
	key := newTestKey(t)
	issuer, shutdown := newFullMockIdP(t, &mockIdPConfig{key: key, clientID: "cid"})
	defer shutdown()
	initWithCtx(t, issuer, "cid")

	// Empty redirectURI → falls back to the Config's static value
	// (the single-origin legacy path these tests cover).
	authURL, cookieValue, err := BuildAuthorizeRequest([]byte("0123456789abcdef0123456789abcdef"), "")
	if err != nil {
		t.Fatalf("BuildAuthorizeRequest: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	q := u.Query()
	for _, want := range []string{"code_challenge", "code_challenge_method", "state", "nonce", "client_id", "redirect_uri", "scope", "response_type"} {
		if q.Get(want) == "" {
			t.Errorf("authorize URL missing %q: %s", want, authURL)
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256 (never plain)", q.Get("code_challenge_method"))
	}
	if cookieValue == "" {
		t.Error("cookie value empty")
	}
	// Cookie should decode back to a valid StateCookie with matching state+nonce.
	sc, err := DecodeStateCookie(cookieValue, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("DecodeStateCookie: %v", err)
	}
	if sc.State != q.Get("state") {
		t.Errorf("state cookie state=%q != authorize-url state=%q", sc.State, q.Get("state"))
	}
	if sc.Nonce != q.Get("nonce") {
		t.Errorf("state cookie nonce=%q != authorize-url nonce=%q", sc.Nonce, q.Get("nonce"))
	}
}

// TestBuildAuthorizeRequest_DynamicRedirect — when the caller supplies
// a per-request redirectURI (e.g. derived from the incoming HTTP
// Host header), the authorize URL's redirect_uri and the state
// cookie's RedirectURI BOTH carry that exact value, NOT the static
// one configured at InitProvider time. Pins the dual-origin support
// that lets one binary serve both IP and hostname entry points.
func TestBuildAuthorizeRequest_DynamicRedirect(t *testing.T) {
	key := newTestKey(t)
	issuer, shutdown := newFullMockIdP(t, &mockIdPConfig{key: key, clientID: "cid"})
	defer shutdown()
	initWithCtx(t, issuer, "cid") // static RedirectURI = https://example.mil/api/auth/oidc/callback

	dynamic := "https://10.20.30.40:8443/api/auth/oidc/callback"
	authURL, cookieValue, err := BuildAuthorizeRequest([]byte("0123456789abcdef0123456789abcdef"), dynamic)
	if err != nil {
		t.Fatalf("BuildAuthorizeRequest: %v", err)
	}

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if got := u.Query().Get("redirect_uri"); got != dynamic {
		t.Errorf("authorize URL redirect_uri = %q, want dynamic %q", got, dynamic)
	}
	sc, err := DecodeStateCookie(cookieValue, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("DecodeStateCookie: %v", err)
	}
	if sc.RedirectURI != dynamic {
		t.Errorf("state cookie RedirectURI = %q, want %q — /callback would fail spec-required exact-match", sc.RedirectURI, dynamic)
	}
}

// TestBuildAuthorizeRequest_EmptyDynamicFallsBackToStatic — passing
// an empty redirectURI keeps the legacy single-origin behavior so
// callers that haven't adopted the dynamic path (or deployments that
// register only one redirect URI in the IdP) still work.
func TestBuildAuthorizeRequest_EmptyDynamicFallsBackToStatic(t *testing.T) {
	key := newTestKey(t)
	issuer, shutdown := newFullMockIdP(t, &mockIdPConfig{key: key, clientID: "cid"})
	defer shutdown()
	initWithCtx(t, issuer, "cid") // static RedirectURI = https://example.mil/api/auth/oidc/callback

	authURL, cookieValue, err := BuildAuthorizeRequest([]byte("0123456789abcdef0123456789abcdef"), "")
	if err != nil {
		t.Fatalf("BuildAuthorizeRequest: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	// initWithCtx wires RedirectURI="https://example.mil/api/auth/oidc/callback".
	if got := u.Query().Get("redirect_uri"); got != "https://example.mil/api/auth/oidc/callback" {
		t.Errorf("empty dynamic should fall back to config RedirectURI; got %q", got)
	}
	sc, err := DecodeStateCookie(cookieValue, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("DecodeStateCookie: %v", err)
	}
	if sc.RedirectURI != "" {
		t.Errorf("state cookie RedirectURI should be empty on fallback path; got %q", sc.RedirectURI)
	}
}

func TestExchangeAndVerify_HappyPath(t *testing.T) {
	key := newTestKey(t)
	// We know the nonce ahead of the /login call isn't exposed, so the
	// test needs to prepare the /token response to echo whatever nonce the
	// StateCookie carries. Simplest: bypass BuildAuthorizeRequest and
	// craft the StateCookie directly.
	clientID := "cid"
	nonce := "nonce-test-value"
	mockCfg := &mockIdPConfig{
		key:      key,
		clientID: clientID,
		claims: map[string]interface{}{
			"sub":                "alice",
			"preferred_username": "alice",
			"email":              "alice@example.mil",
			"groups":             []string{"cmmc-admins"},
			"amr":                []string{"pwd", "mfa"},
			"auth_time":          time.Now().Unix(),
			"nonce":              nonce,
		},
	}
	issuer, shutdown := newFullMockIdP(t, mockCfg)
	defer shutdown()
	initWithCtx(t, issuer, clientID)

	stateCookie := StateCookie{
		State:    "s1",
		Nonce:    nonce,
		Verifier: "verifier-long-enough-to-satisfy-pkce-check-really-yes",
		IssuedAt: time.Now().Unix(),
	}
	ctx := withTLSTrustingHTTP(t)
	sess, err := ExchangeAndVerify(ctx, "s1", "authz-code", stateCookie)
	if err != nil {
		t.Fatalf("ExchangeAndVerify: %v", err)
	}
	if sess.Username != "alice" {
		t.Errorf("username = %q", sess.Username)
	}
	if !sess.IsAdmin {
		t.Errorf("IsAdmin false despite cmmc-admins group membership")
	}
	if sess.MFAAt.IsZero() {
		t.Errorf("MFAAt not set despite amr containing 'mfa'")
	}
	if sess.Email != "alice@example.mil" {
		t.Errorf("email = %q", sess.Email)
	}
}

func TestExchangeAndVerify_StateMismatch(t *testing.T) {
	key := newTestKey(t)
	issuer, shutdown := newFullMockIdP(t, &mockIdPConfig{
		key:      key,
		clientID: "cid",
		claims:   map[string]interface{}{"sub": "alice"},
	})
	defer shutdown()
	initWithCtx(t, issuer, "cid")

	sc := StateCookie{State: "expected", Nonce: "n", Verifier: "v", IssuedAt: time.Now().Unix()}
	ctx := withTLSTrustingHTTP(t)
	_, err := ExchangeAndVerify(ctx, "attacker-provided", "code", sc)
	if err == nil || !strings.Contains(err.Error(), "state mismatch") {
		t.Fatalf("expected state mismatch error, got: %v", err)
	}
}

func TestExchangeAndVerify_RequireMFA_RejectsUnmfa(t *testing.T) {
	key := newTestKey(t)
	clientID := "cid"
	nonce := "n-no-mfa"
	mockCfg := &mockIdPConfig{
		key:      key,
		clientID: clientID,
		claims: map[string]interface{}{
			"sub":                "bob",
			"preferred_username": "bob",
			"amr":                []string{"pwd"}, // only password, no MFA
			"nonce":              nonce,
		},
	}
	issuer, shutdown := newFullMockIdP(t, mockCfg)
	defer shutdown()
	// Bring up provider with RequireMFA=true.
	resetSingleton()
	cfg := Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: "secret",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid"},
		UsernameClaim: "preferred_username",
		GroupsClaim:   "groups",
		MFAClaim:      "amr",
		RequireMFA:    true,
	}
	if err := InitProvider(testCtx(), cfg); err != nil {
		t.Fatalf("InitProvider: %v", err)
	}

	sc := StateCookie{State: "s", Nonce: nonce, Verifier: "v", IssuedAt: time.Now().Unix()}
	ctx := withTLSTrustingHTTP(t)
	_, err := ExchangeAndVerify(ctx, "s", "code", sc)
	if err == nil || !strings.Contains(err.Error(), "MFA") {
		t.Fatalf("RequireMFA gate did not reject non-MFA session; err=%v", err)
	}
}

func TestExchangeAndVerify_NonceMismatch(t *testing.T) {
	key := newTestKey(t)
	clientID := "cid"
	mockCfg := &mockIdPConfig{
		key:      key,
		clientID: clientID,
		claims: map[string]interface{}{
			"sub":   "carol",
			"nonce": "nonce-from-IdP",
		},
	}
	issuer, shutdown := newFullMockIdP(t, mockCfg)
	defer shutdown()
	initWithCtx(t, issuer, clientID)

	// StateCookie carries a DIFFERENT nonce → verifier accepts the token,
	// then ExchangeAndVerify's nonce check rejects the session.
	sc := StateCookie{State: "s", Nonce: "nonce-from-our-login", Verifier: "v", IssuedAt: time.Now().Unix()}
	ctx := withTLSTrustingHTTP(t)
	_, err := ExchangeAndVerify(ctx, "s", "code", sc)
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce mismatch should be detected; err=%v", err)
	}
}

// withTLSTrustingHTTP installs the test-server-trusting http.Client under
// the oauth2.HTTPClient context key. go-oidc AND the token exchange both
// consult this client for TLS.
func withTLSTrustingHTTP(t *testing.T) context.Context {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	return context.WithValue(context.Background(), oauth2.HTTPClient, c)
}
