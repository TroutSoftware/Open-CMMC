package fbhttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	cmmcoidc "github.com/filebrowser/filebrowser/v2/cmmc/auth/oidc"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/users"
)

// --- test doubles ---------------------------------------------------------

// fakeUserStore is a minimal users.Store for handler tests. It intentionally
// avoids the full bolt backend to keep these tests hermetic and fast. It
// mirrors the one in cmmc/auth/oidc/provision_test.go but lives in package
// fbhttp — Go test packages don't share unexported helpers.
type fakeUserStore struct {
	mu     sync.Mutex
	byName map[string]*users.User
	nextID uint
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{byName: map[string]*users.User{}, nextID: 1}
}

func (f *fakeUserStore) Get(_ string, id interface{}) (*users.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch v := id.(type) {
	case string:
		u, ok := f.byName[v]
		if !ok {
			return nil, fberrors.ErrNotExist
		}
		return u, nil
	case uint:
		for _, u := range f.byName {
			if u.ID == v {
				return u, nil
			}
		}
		return nil, fberrors.ErrNotExist
	default:
		return nil, fberrors.ErrInvalidDataType
	}
}
func (f *fakeUserStore) Gets(_ string) ([]*users.User, error) { return nil, nil }
func (f *fakeUserStore) Save(u *users.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.byName[u.Username]; dup {
		return fberrors.ErrExist
	}
	u.ID = f.nextID
	f.nextID++
	f.byName[u.Username] = u
	return nil
}
func (f *fakeUserStore) Update(u *users.User, _ ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byName[u.Username] = u
	return nil
}
func (f *fakeUserStore) Delete(_ interface{}) error { return nil }
func (f *fakeUserStore) LastUpdate(_ uint) int64    { return 0 }

// fakeIdentityStore is an in-memory cmmcoidc.IdentityStore for tests.
type fakeIdentityStore struct {
	mu  sync.Mutex
	byK map[string]*cmmcoidc.Identity
}

func newFakeIdentityStore() *fakeIdentityStore {
	return &fakeIdentityStore{byK: map[string]*cmmcoidc.Identity{}}
}
func (f *fakeIdentityStore) Get(key string) (*cmmcoidc.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.byK[key]; ok {
		return v, nil
	}
	return nil, fberrors.ErrNotExist
}
func (f *fakeIdentityStore) Put(id *cmmcoidc.Identity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byK[id.IssSubKey] = id
	return nil
}
func (f *fakeIdentityStore) DeleteByUserID(userID uint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.byK {
		if v.UserID == userID {
			delete(f.byK, k)
		}
	}
	return nil
}
// HasUserID implements the userLookup extension cmmcoidc uses for
// collision detection during backfill. The in-memory store opts in.
func (f *fakeIdentityStore) HasUserID(userID uint) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.byK {
		if v.UserID == userID {
			return true, nil
		}
	}
	return false, nil
}

// newHandlerData constructs the private *data struct the handlers expect.
// Because we are in package fbhttp, we can reach the unexported type.
func newHandlerData(t *testing.T, authMethod settings.AuthMethod) (*data, *fakeUserStore, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "filebrowser"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	set := &settings.Settings{
		Key:                   []byte("test-key-0123456789abcdef0123456789abcdef"),
		AuthMethod:            authMethod,
		Defaults:              settings.UserDefaults{Scope: "."},
		MinimumPasswordLength: settings.DefaultMinimumPasswordLength,
	}
	srv := &settings.Server{Root: dir}
	fake := newFakeUserStore()
	d := &data{
		settings: set,
		server:   srv,
		store: &storage.Storage{
			Users:          fake,
			OIDCIdentities: newFakeIdentityStore(),
		},
	}
	return d, fake, dir
}

// --- mock IdP for handler flow tests --------------------------------------

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	return k
}

// newMockIdPServer brings up a TLS httptest server with OIDC discovery,
// JWKS, and a configurable /token endpoint. It's a trimmed copy of the
// cmmc/auth/oidc/flow_test.go mock so the fbhttp test stays self-contained.
func newMockIdPServer(t *testing.T, key *rsa.PrivateKey, clientID string, claims map[string]interface{}) (issuer string, shutdown func()) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	issuer = srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-1", Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") == "" || r.FormValue("code_verifier") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c := make(map[string]interface{}, len(claims))
		for k, v := range claims {
			c[k] = v
		}
		if _, ok := c["iss"]; !ok {
			c["iss"] = issuer
		}
		if _, ok := c["aud"]; !ok {
			c["aud"] = clientID
		}
		if _, ok := c["iat"]; !ok {
			c["iat"] = time.Now().Unix()
		}
		if _, ok := c["exp"]; !ok {
			c["exp"] = time.Now().Add(5 * time.Minute).Unix()
		}
		opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-1")
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, opts)
		if err != nil {
			t.Errorf("signer: %v", err)
			return
		}
		idTok, err := jwt.Signed(signer).Claims(c).Serialize()
		if err != nil {
			t.Errorf("sign: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "fake", "token_type": "Bearer", "id_token": idTok, "expires_in": 300,
		})
	})
	return issuer, srv.Close
}

func tlsTrustingCtx() context.Context {
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	return context.WithValue(context.Background(), oauth2.HTTPClient, c)
}

// --- login handler tests --------------------------------------------------

func TestOIDCLoginHandler_404WhenAuthMethodNotOIDC(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	status, err := oidcLoginHandler(w, r, d)
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("status=%d err=%v, want 404/nil", status, err)
	}
}

func TestOIDCLoginHandler_503WhenProviderUnavailable(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	// Force fresh state: no singleton, no lazy config.
	resetProviderSingletonForTest()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	status, err := oidcLoginHandler(w, r, d)
	if status != http.StatusServiceUnavailable || err == nil {
		t.Fatalf("status=%d err=%v, want 503 + error", status, err)
	}
}

func TestOIDCLoginHandler_302WithStateCookie(t *testing.T) {
	key := newRSAKey(t)
	issuer, shutdown := newMockIdPServer(t, key, "cid", nil)
	defer shutdown()
	resetProviderSingletonForTest()
	cfg := cmmcoidc.Config{
		Issuer:        issuer,
		ClientID:      "cid",
		ClientSecret:  "secret",
		RedirectURI:   "https://example.mil/api/auth/oidc/callback",
		Scopes:        []string{"openid"},
		UsernameClaim: "preferred_username",
		GroupsClaim:   "groups",
		MFAClaim:      "amr",
	}
	if err := cmmcoidc.InitProvider(tlsTrustingCtx(), cfg); err != nil {
		t.Fatalf("InitProvider: %v", err)
	}

	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	status, err := oidcLoginHandler(w, r, d)
	if err != nil || status != 0 { // handler returns 0 when it already wrote the response (302)
		t.Fatalf("status=%d err=%v, want 0 (response already written)", status, err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("http code=%d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "code_challenge_method=S256") {
		t.Errorf("redirect missing PKCE S256: %s", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == cmmcoidc.StateCookieName {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("state cookie not set")
	}
	if !stateCookie.HttpOnly {
		t.Error("state cookie must be HttpOnly")
	}
	if stateCookie.SameSite != http.SameSiteLaxMode {
		t.Error("state cookie must be SameSite=Lax")
	}
}

// --- callback handler tests -----------------------------------------------

func TestOIDCCallbackHandler_404WhenAuthMethodNotOIDC(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodJSONAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=c&state=s", nil)
	status, err := oidcCallbackHandler(time.Hour)(w, r, d)
	if err != nil || status != http.StatusNotFound {
		t.Fatalf("status=%d err=%v, want 404", status, err)
	}
}

func TestOIDCCallbackHandler_400WhenStateOrCodeMissing(t *testing.T) {
	key := newRSAKey(t)
	issuer, shutdown := newMockIdPServer(t, key, "cid", nil)
	defer shutdown()
	resetProviderSingletonForTest()
	if err := cmmcoidc.InitProvider(tlsTrustingCtx(), cmmcoidc.Config{
		Issuer: issuer, ClientID: "cid", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"}, UsernameClaim: "preferred_username",
		GroupsClaim: "groups", MFAClaim: "amr",
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)

	cases := []string{
		"/api/auth/oidc/callback",                 // no params
		"/api/auth/oidc/callback?code=c",          // missing state
		"/api/auth/oidc/callback?state=s",        // missing code
		"/api/auth/oidc/callback?error=access_denied", // IdP error
	}
	for _, u := range cases {
		u := u
		t.Run(u, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, u, nil)
			status, _ := oidcCallbackHandler(time.Hour)(w, r, d)
			if status != http.StatusBadRequest {
				t.Errorf("url %q: status=%d, want 400", u, status)
			}
		})
	}
}

func TestOIDCCallbackHandler_400WhenStateCookieMissing(t *testing.T) {
	key := newRSAKey(t)
	issuer, shutdown := newMockIdPServer(t, key, "cid", nil)
	defer shutdown()
	resetProviderSingletonForTest()
	if err := cmmcoidc.InitProvider(tlsTrustingCtx(), cmmcoidc.Config{
		Issuer: issuer, ClientID: "cid", ClientSecret: "s",
		RedirectURI: "https://example.mil/api/auth/oidc/callback",
		Scopes:      []string{"openid"}, UsernameClaim: "preferred_username",
		GroupsClaim: "groups", MFAClaim: "amr",
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=c&state=s", nil)
	// No cookie attached.
	status, err := oidcCallbackHandler(time.Hour)(w, r, d)
	if status != http.StatusBadRequest || err == nil {
		t.Fatalf("status=%d err=%v, want 400 + error", status, err)
	}
}

func TestOIDCCallbackHandler_HappyPath_SetsAuthCookieAndProvisions(t *testing.T) {
	key := newRSAKey(t)
	clientID := "cid"
	nonce := "test-nonce"
	issuer, shutdown := newMockIdPServer(t, key, clientID, map[string]interface{}{
		"sub":                "alice",
		"preferred_username": "alice",
		"email":              "alice@example.mil",
		"groups":             []string{"cmmc-admins"},
		"amr":                []string{"pwd", "mfa"},
		"nonce":              nonce,
	})
	defer shutdown()

	resetProviderSingletonForTest()
	signingKey := []byte("test-key-0123456789abcdef0123456789abcdef")
	if err := cmmcoidc.InitProvider(tlsTrustingCtx(), cmmcoidc.Config{
		Issuer: issuer, ClientID: clientID, ClientSecret: "s",
		RedirectURI:   "https://example.mil/api/auth/oidc/callback",
		Scopes:        []string{"openid"},
		UsernameClaim: "preferred_username",
		GroupsClaim:   "groups",
		AdminGroups:   []string{"cmmc-admins"},
		MFAClaim:      "amr",
	}); err != nil {
		t.Fatalf("init: %v", err)
	}

	d, store, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	d.settings.Key = signingKey // make the signing key match the state cookie

	// Build a valid state cookie that references the nonce the mock IdP
	// will echo back. We build it directly rather than going through
	// BuildAuthorizeRequest so the test doesn't depend on the login step.
	sc := cmmcoidc.StateCookie{
		State:    "state-abc",
		Nonce:    nonce,
		Verifier: "verifier-long-enough-to-satisfy-pkce-check-really-yes",
		IssuedAt: time.Now().Unix(),
	}
	cookieValue, err := cmmcoidc.EncodeStateCookieForTest(sc, signingKey)
	if err != nil {
		t.Fatalf("encode state cookie: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?code=authz&state=state-abc", nil)
	r.AddCookie(&http.Cookie{Name: cmmcoidc.StateCookieName, Value: cookieValue})
	// Install the trust-all HTTP client in the request's context so the
	// callback's internal oauth2.Exchange accepts the httptest server's
	// self-signed cert. Production code does not use this context key.
	r = r.WithContext(tlsTrustingCtx())

	status, err := oidcCallbackHandler(time.Hour)(w, r, d)
	if err != nil || status != 0 {
		t.Fatalf("status=%d err=%v, want 0 (response written)", status, err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("http code=%d, want 302", w.Code)
	}
	if w.Header().Get("Location") != "/" {
		t.Errorf("Location=%q, want /", w.Header().Get("Location"))
	}

	var authCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "auth" {
			authCookie = c
		}
	}
	if authCookie == nil {
		t.Fatal("auth cookie not set")
	}
	// CMMC 3.13.11 / defense-in-depth — auth cookie MUST be HttpOnly
	// so XSS cannot exfiltrate the session JWT. The SPA bridges the
	// session via POST /api/renew, not by reading the cookie.
	if !authCookie.HttpOnly {
		t.Error("auth cookie must be HttpOnly (CMMC 3.13.11)")
	}
	if strings.Count(authCookie.Value, ".") != 2 {
		t.Errorf("auth cookie is not a JWT (two-dot): %q", authCookie.Value)
	}

	// Provisioning side effects.
	u, gerr := store.Get("", "alice")
	if gerr != nil {
		t.Fatalf("user not provisioned: %v", gerr)
	}
	if !u.Perm.Admin {
		t.Errorf("admin group should have promoted user to admin")
	}
	if !u.LockPassword {
		t.Errorf("OIDC user must have LockPassword=true")
	}
}

// resetProviderSingletonForTest re-initializes the cmmcoidc singleton
// before each handler test so tests don't leak state into each other.
// Runs a harmless InitProvider with an intentionally-failed discovery
// won't reset singletonInited, so we call a dedicated helper exported in
// the oidc package for tests.
func resetProviderSingletonForTest() {
	cmmcoidc.ResetSingletonForTest()
}

// TestOIDCLogoutHandler_RejectsWithoutAuth pins the exact bug a user
// hit in live testing: the SPA POSTed to /api/auth/oidc/logout
// without the X-Auth header. withUser falls through to the cookie
// only on GETs, so a POST without header 401s. Leaving it untested
// meant the logout silently failed (SPA fell through to local-only
// clear while the Keycloak SSO cookie lived on).
func TestOIDCLogoutHandler_RejectsWithoutAuth(t *testing.T) {
	d, _, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/logout", nil)
	status, _ := oidcLogoutHandler(w, r, d)
	if status != http.StatusUnauthorized {
		t.Errorf("no auth → status %d, want 401", status)
	}
}

// TestOIDCLogoutHandler_ClearsCookies exercises the authenticated
// happy path: cookies get an immediate-expiry Set-Cookie, and the
// JSON response carries the end_session_url field. The URL may be
// empty if no IdP singleton is initialized; that's a separate
// concern (a real deployment always has one).
func TestOIDCLogoutHandler_ClearsCookies(t *testing.T) {
	d, fake, _ := newHandlerData(t, fbAuth.MethodOIDCAuth)
	// Seed a user so withUser's userStore.Get(id) succeeds — Save
	// allocates ID 1 (fakeUserStore.nextID starts at 1).
	if err := fake.Save(&users.User{Username: "alice"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	tok := mintTestSession(t, d.settings.Key, time.Now())

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/oidc/logout", nil)
	r.Header.Set("X-Auth", tok)
	r.AddCookie(&http.Cookie{Name: idTokenCookieName, Value: "eyJ.id.tok"})

	status, err := oidcLogoutHandler(w, r, d)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != 0 {
		t.Fatalf("status=%d, want 0 (response already written)", status)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", ct)
	}
	// Assert both session cookies are cleared. MaxAge<0 or Expires in
	// the past both work; the stdlib emits "Max-Age=0" for MaxAge=-1.
	cleared := map[string]bool{"auth": false, idTokenCookieName: false}
	for _, c := range w.Result().Cookies() {
		if _, ok := cleared[c.Name]; !ok {
			continue
		}
		if c.MaxAge < 0 || !c.Expires.IsZero() && c.Expires.Before(time.Now()) || c.MaxAge == 0 {
			cleared[c.Name] = true
		}
	}
	for name, ok := range cleared {
		if !ok {
			t.Errorf("cookie %q not cleared in response", name)
		}
	}
	// Body must be parseable JSON with end_session_url field.
	if !strings.Contains(w.Body.String(), "end_session_url") {
		t.Errorf("response body missing end_session_url: %s", w.Body.String())
	}
}
