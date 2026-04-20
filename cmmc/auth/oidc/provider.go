package oidc

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	singletonMu       sync.RWMutex
	singletonProvider *oidc.Provider
	singletonVerifier *oidc.IDTokenVerifier
	singletonOAuth2   *oauth2.Config
	singletonCfg      Config
	singletonInited   bool

	// lazyCfg holds the config stashed by SetConfigForLazyInit, used by
	// EnsureInitialized() to retry discovery if the boot-time attempt failed
	// (e.g., IdP unreachable at startup).
	lazyCfgMu sync.Mutex
	lazyCfg   *Config
	lazyAttempted bool
	lazyLastTry   time.Time
)

// lazyRetryCooldown bounds how often EnsureInitialized hammers a flapping
// IdP. Handlers call it per request, but we only actually retry at most
// once per cooldown window.
const lazyRetryCooldown = 10 * time.Second

// InitProvider constructs the oidc.Provider singleton by fetching the
// discovery document from the configured issuer. This does a network
// round-trip and must happen at startup, not per-request.
//
// The id_token verifier is constructed with SupportedSigningAlgs set to
// the FIPS-approved allowlist in FIPSAllowedAlgs; any id_token signed
// with EdDSA or HMAC algorithms is rejected at Verify() time.
//
// Safe to call multiple times; subsequent calls replace the singleton
// (useful for tests and config reload).
func InitProvider(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc: discovery for %q: %w", cfg.Issuer, err)
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID:             cfg.ClientID,
		SupportedSigningAlgs: FIPSAllowedAlgs,
	})
	oa := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	singletonMu.Lock()
	defer singletonMu.Unlock()
	singletonProvider = provider
	singletonVerifier = verifier
	singletonOAuth2 = oa
	singletonCfg = cfg
	singletonInited = true
	return nil
}

// Initialized reports whether InitProvider has successfully run. Handlers
// use this to return a clean 503 when the IdP is unreachable at boot.
func Initialized() bool {
	singletonMu.RLock()
	defer singletonMu.RUnlock()
	return singletonInited
}

// Snapshot returns the current singleton state. The returned pointers are
// safe to use concurrently; they are replaced atomically under the mutex
// and must be treated read-only by callers.
func Snapshot() (*oauth2.Config, *oidc.IDTokenVerifier, Config, bool) {
	singletonMu.RLock()
	defer singletonMu.RUnlock()
	return singletonOAuth2, singletonVerifier, singletonCfg, singletonInited
}

// SetConfigForLazyInit stashes the Config so EnsureInitialized can retry
// discovery if boot-time init failed. Call once during startup.
func SetConfigForLazyInit(cfg Config) {
	lazyCfgMu.Lock()
	defer lazyCfgMu.Unlock()
	c := cfg
	lazyCfg = &c
}

// EndSessionURL builds the IdP front-channel logout URL so the app can
// terminate the Keycloak (or Entra / Okta Gov) SSO session when the
// user clicks "logout" — not just clear its own JWT. Without this,
// pressing logout and then re-hitting /login auto-re-authenticates
// the user via the IdP's still-live SSO cookie, which defeats CMMC
// 3.1.11 (session termination).
//
// Parameters:
//   - idTokenHint: the caller's last id_token (optional per spec but
//     strongly recommended — some IdPs, including older Entra, 400 on
//     logout without it).
//   - postLogoutRedirect: absolute URL to return to after IdP logout.
//     Must be registered with the IdP as a valid post-logout URI.
//
// Returns the URL and true if the provider advertises an
// end_session_endpoint in its discovery document. Returns false when
// the IdP is unconfigured or the discovery doc omitted the field —
// the caller should fall back to a local-only logout.
func EndSessionURL(idTokenHint, postLogoutRedirect string) (string, bool) {
	singletonMu.RLock()
	provider := singletonProvider
	cfg := singletonCfg
	singletonMu.RUnlock()
	if provider == nil {
		return "", false
	}
	// The go-oidc provider exposes additional discovery fields via
	// Claims into a struct — end_session_endpoint is not in
	// Endpoint(), only in the full claims document.
	var extra struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&extra); err != nil || extra.EndSessionEndpoint == "" {
		return "", false
	}
	// Build query params. Deliberately OMIT id_token_hint — it fails
	// hard when the cookie carries a token minted under a prior
	// realm generation (fresh-install, key rotation, Keycloak
	// upgrade) and the recovery UX is "Invalid parameter:
	// id_token_hint" with no actionable recovery. Keycloak 18+
	// accepts client_id + post_logout_redirect_uri alone; the
	// post_logout_redirect_uri must be registered on the client,
	// which our bootstrap.sh does. Trade-off: on KC 26 without
	// id_token_hint the user sees a short confirmation page
	// ("Are you sure?") instead of a direct redirect — acceptable
	// for reliability across realm rebuilds.
	q := url.Values{}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	if cfg.ClientID != "" {
		q.Set("client_id", cfg.ClientID)
	}
	// Parameter kept on the signature for API stability and for
	// operators who want to opt back in to direct-redirect at the
	// cost of stale-token errors.
	_ = idTokenHint
	return extra.EndSessionEndpoint + "?" + q.Encode(), true
}

// EnsureInitialized returns nil if the singleton is already initialized,
// otherwise attempts a single InitProvider using the stashed lazy config.
// Retries are rate-limited by lazyRetryCooldown so a flapping IdP does not
// generate a request-per-second discovery storm.
func EnsureInitialized(ctx context.Context) error {
	if Initialized() {
		return nil
	}
	lazyCfgMu.Lock()
	if lazyCfg == nil {
		lazyCfgMu.Unlock()
		return fmt.Errorf("oidc: no config available for lazy init")
	}
	if lazyAttempted && time.Since(lazyLastTry) < lazyRetryCooldown {
		lazyCfgMu.Unlock()
		return fmt.Errorf("oidc: provider not ready (cooling down)")
	}
	cfg := *lazyCfg
	lazyLastTry = time.Now()
	lazyAttempted = true
	lazyCfgMu.Unlock()
	return InitProvider(ctx, cfg)
}
