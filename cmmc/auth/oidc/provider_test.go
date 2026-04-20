package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// These tests exercise the provider singleton lifecycle: InitProvider
// success, SetConfigForLazyInit → EnsureInitialized retry + cooldown, and
// concurrent snapshot reads.

func newDiscoveryOnlyIssuer(t *testing.T) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	issuer := srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                   issuer,
			"authorization_endpoint":   issuer + "/authorize",
			"token_endpoint":           issuer + "/token",
			"jwks_uri":                 issuer + "/jwks",
			"response_types_supported": []string{"code"},
			"subject_types_supported":  []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})
	return issuer, srv.Close
}

func testCtx() context.Context {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	return context.WithValue(context.Background(), oauth2.HTTPClient, c)
}

// resetSingleton wipes the package-global singleton so each test starts
// from a clean slate. Tests must serialize (no t.Parallel) since they
// mutate shared state.
func resetSingleton() {
	singletonMu.Lock()
	singletonProvider = nil
	singletonVerifier = nil
	singletonOAuth2 = nil
	singletonCfg = Config{}
	singletonInited = false
	singletonMu.Unlock()
	lazyCfgMu.Lock()
	lazyCfg = nil
	lazyAttempted = false
	lazyLastTry = time.Time{}
	lazyCfgMu.Unlock()
}

func TestInitProvider_SuccessSetsSingleton(t *testing.T) {
	resetSingleton()
	issuer, shutdown := newDiscoveryOnlyIssuer(t)
	defer shutdown()

	cfg := Config{
		Issuer:       issuer,
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid"},
	}
	if err := InitProvider(testCtx(), cfg); err != nil {
		t.Fatalf("InitProvider: %v", err)
	}
	if !Initialized() {
		t.Fatal("Initialized() = false after successful init")
	}
	oa, v, gotCfg, ok := Snapshot()
	if !ok {
		t.Fatal("Snapshot ok = false")
	}
	if oa == nil || v == nil {
		t.Fatal("Snapshot returned nil members")
	}
	if gotCfg.ClientID != "cid" {
		t.Errorf("snapshot cfg ClientID = %q, want cid", gotCfg.ClientID)
	}
	if oa.ClientID != "cid" || oa.ClientSecret != "secret" {
		t.Errorf("oauth2 config not populated: %+v", oa)
	}
	if oa.Endpoint.AuthURL == "" || oa.Endpoint.TokenURL == "" {
		t.Errorf("oauth2 endpoint not wired: %+v", oa.Endpoint)
	}
}

func TestInitProvider_InvalidConfig(t *testing.T) {
	resetSingleton()
	err := InitProvider(testCtx(), Config{}) // empty fields
	if err == nil {
		t.Fatal("empty config should fail validation")
	}
	if Initialized() {
		t.Fatal("Initialized() must be false after failed init")
	}
}

func TestInitProvider_UnreachableIssuerReturnsError(t *testing.T) {
	resetSingleton()
	// Use a port guaranteed closed on localhost.
	cfg := Config{
		Issuer:       "https://127.0.0.1:1/",
		ClientID:     "c", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}
	ctx, cancel := context.WithTimeout(testCtx(), 2*time.Second)
	defer cancel()
	if err := InitProvider(ctx, cfg); err == nil {
		t.Fatal("expected error for unreachable issuer")
	}
	if Initialized() {
		t.Fatal("Initialized() must be false after failed discovery")
	}
}

func TestEnsureInitialized_UsesLazyConfig(t *testing.T) {
	resetSingleton()
	issuer, shutdown := newDiscoveryOnlyIssuer(t)
	defer shutdown()

	cfg := Config{
		Issuer:       issuer,
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid"},
	}
	SetConfigForLazyInit(cfg)
	if Initialized() {
		t.Fatal("precondition: should not be initialized before EnsureInitialized")
	}
	if err := EnsureInitialized(testCtx()); err != nil {
		t.Fatalf("EnsureInitialized: %v", err)
	}
	if !Initialized() {
		t.Fatal("Initialized() false after EnsureInitialized success")
	}
	// Second call should be a no-op (already initialized, returns nil).
	if err := EnsureInitialized(testCtx()); err != nil {
		t.Fatalf("second EnsureInitialized: %v", err)
	}
}

func TestEnsureInitialized_NoConfigFails(t *testing.T) {
	resetSingleton()
	err := EnsureInitialized(testCtx())
	if err == nil {
		t.Fatal("EnsureInitialized without SetConfigForLazyInit must fail")
	}
	if !strings.Contains(err.Error(), "no config") {
		t.Errorf("err = %v, want 'no config'", err)
	}
}

func TestEnsureInitialized_CooldownRateLimits(t *testing.T) {
	resetSingleton()
	cfg := Config{
		Issuer:       "https://127.0.0.1:1/",
		ClientID:     "c", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}
	SetConfigForLazyInit(cfg)
	ctx, cancel := context.WithTimeout(testCtx(), 1*time.Second)
	defer cancel()

	// First attempt hits the network and fails (port 1 closed).
	if err := EnsureInitialized(ctx); err == nil {
		t.Fatal("first EnsureInitialized should fail (unreachable)")
	}
	// Second call within cooldown window must return the cooldown error,
	// NOT retry the network — that's the point of the cooldown.
	err := EnsureInitialized(ctx)
	if err == nil {
		t.Fatal("second EnsureInitialized within cooldown should fail")
	}
	if !strings.Contains(err.Error(), "cooling down") {
		t.Errorf("err = %v, want cooldown message", err)
	}
}

func TestSnapshot_ConcurrentSafe(t *testing.T) {
	resetSingleton()
	issuer, shutdown := newDiscoveryOnlyIssuer(t)
	defer shutdown()
	if err := InitProvider(testCtx(), Config{
		Issuer:       issuer,
		ClientID:     "c", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Hammer Snapshot from 50 goroutines while rerunning InitProvider.
	// Under RWMutex this must not race (go test -race catches bugs).
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _, _, _ = Snapshot()
				}
			}
		}()
	}
	for i := 0; i < 5; i++ {
		if err := InitProvider(testCtx(), Config{
			Issuer:       issuer,
			ClientID:     "c", ClientSecret: "s",
			RedirectURI: "https://example.mil/api/auth/oidc/callback",
			Scopes:      []string{"openid"},
		}); err != nil {
			t.Errorf("reinit %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}

// newIssuerWithEndSession mirrors newDiscoveryOnlyIssuer but also
// advertises the end_session_endpoint so EndSessionURL can resolve it.
func newIssuerWithEndSession(t *testing.T, endSession string) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	issuer := srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]interface{}{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if endSession != "" {
			doc["end_session_endpoint"] = endSession
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})
	return issuer, srv.Close
}

// TestEndSessionURL_Encodes pins the URL-encoding contract. Regression
// guard: the first version of this helper concatenated raw strings,
// producing Keycloak-400 URLs like
//   …/logout?post_logout_redirect_uri=http://host:8080/login
// where the unencoded ://  was rejected as "Invalid redirect_uri".
// Re-introducing that bug must break this test.
func TestEndSessionURL_Encodes(t *testing.T) {
	resetSingleton()
	issuer, shutdown := newIssuerWithEndSession(t, "https://idp.example.mil/realms/cmmc/logout")
	defer shutdown()
	if err := InitProvider(testCtx(), Config{
		Issuer: issuer, ClientID: "fb-cmmc", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	u, ok := EndSessionURL("eyJ.hint.sig", "http://cabinet.example.mil:8080/login")
	if !ok {
		t.Fatal("EndSessionURL not advertised")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := parsed.Query()
	if got := q.Get("post_logout_redirect_uri"); got != "http://cabinet.example.mil:8080/login" {
		t.Errorf("post_logout_redirect_uri = %q (expected url-decoded to original)", got)
	}
	// EndSessionURL deliberately omits id_token_hint to survive
	// realm rebuilds / key rotation — the hint becomes invalid and
	// KC returns a dead-end "Invalid parameter: id_token_hint" page.
	// Trade-off documented inline in EndSessionURL.
	if got := q.Get("id_token_hint"); got != "" {
		t.Errorf("id_token_hint = %q, want empty (avoid stale-hint dead-end)", got)
	}
	if got := q.Get("client_id"); got != "fb-cmmc" {
		t.Errorf("client_id = %q, want fb-cmmc (Keycloak requires it when id_token_hint is absent/expired)", got)
	}
	// The serialized query must URL-encode the // and : in the
	// post_logout_redirect_uri value — otherwise Keycloak rejects the
	// whole call. Check the raw form contains %3A%2F%2F.
	if !strings.Contains(parsed.RawQuery, "%3A%2F%2F") {
		t.Errorf("raw query missing encoded :// — got %q", parsed.RawQuery)
	}
}

// TestEndSessionURL_MissingFromDiscovery_ReturnsFalse pins the
// graceful-fallback branch: when the IdP does not advertise
// end_session_endpoint, EndSessionURL returns ("", false) and the
// caller drops back to a local-only logout.
func TestEndSessionURL_MissingFromDiscovery_ReturnsFalse(t *testing.T) {
	resetSingleton()
	issuer, shutdown := newIssuerWithEndSession(t, "") // not advertised
	defer shutdown()
	if err := InitProvider(testCtx(), Config{
		Issuer: issuer, ClientID: "c", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if u, ok := EndSessionURL("hint", "http://example/login"); ok || u != "" {
		t.Errorf("expected ok=false,u=\"\"; got ok=%v u=%q", ok, u)
	}
}

// TestEndSessionURL_ProviderNotInitialized pins the defensive branch
// in case a handler races startup.
func TestEndSessionURL_ProviderNotInitialized(t *testing.T) {
	resetSingleton()
	if _, ok := EndSessionURL("hint", "http://example/login"); ok {
		t.Fatal("EndSessionURL must return false when provider not initialized")
	}
}

// TestEndSessionURL_EmptyHints pins the minimal-args case — the call
// must still produce a valid URL with just client_id, so a stale
// id_token cookie doesn't block logout.
func TestEndSessionURL_EmptyHints(t *testing.T) {
	resetSingleton()
	issuer, shutdown := newIssuerWithEndSession(t, "https://idp/logout")
	defer shutdown()
	if err := InitProvider(testCtx(), Config{
		Issuer: issuer, ClientID: "cmmc", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	u, ok := EndSessionURL("", "")
	if !ok {
		t.Fatal("EndSessionURL ok=false on advertised endpoint")
	}
	p, _ := url.Parse(u)
	if p.Query().Get("client_id") != "cmmc" {
		t.Errorf("client_id must be set even with empty hints; got %q", p.Query().Get("client_id"))
	}
	if p.Query().Get("id_token_hint") != "" || p.Query().Get("post_logout_redirect_uri") != "" {
		t.Errorf("empty hints must stay empty; got %v", p.Query())
	}
}
