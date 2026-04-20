package oidc

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// FIPSAllowedAlgs is the set of id_token signing algorithms this backend
// accepts. Under FIPS mode (RHEL go-toolset → RHEL OpenSSL 140-3 or
// microsoft/go → platform crypto) EdDSA and HMAC-based algs are either
// blocked by the crypto provider or disallowed by CMMC policy. This
// allowlist is enforced at verifier construction time in provider.go.
var FIPSAllowedAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// Config holds the OIDC backend configuration. All fields load from the
// FB_OIDC_* environment variable namespace to match filebrowser's existing
// viper-driven convention.
type Config struct {
	// Issuer is the OpenID provider's issuer URL. Used as the discovery root
	// and verified against the id_token "iss" claim. For Entra GCC High this
	// is "https://login.microsoftonline.us/{tenant_id}/v2.0".
	Issuer string

	// ClientID and ClientSecret identify this filebrowser deployment at the
	// IdP. Never log ClientSecret.
	ClientID     string
	ClientSecret string

	// RedirectURI is the absolute https URL the IdP will redirect back to.
	// Must match exactly what is registered at the IdP. Prototype convention:
	// "https://{host}/api/auth/oidc/callback".
	RedirectURI string

	// Scopes requested. "openid" is always included by go-oidc; "profile"
	// and "email" are commonly needed for claim mapping.
	Scopes []string

	// UsernameClaim is the id_token claim used as the filebrowser username.
	// Defaults to "preferred_username". Some Entra tenants emit "upn".
	UsernameClaim string

	// GroupsClaim is the id_token claim (string or []string) used for
	// authorization mapping. Defaults to "groups".
	GroupsClaim string

	// AdminGroups are group values that promote a user to Perm.Admin. An
	// empty list means no user is auto-admin'd (safe default).
	AdminGroups []string

	// MFAClaim is the claim used to detect that the user performed MFA.
	// Defaults to "amr" (array). Okta and Entra both surface MFA in "amr".
	// Keycloak uses "acr" with a numeric or symbolic level.
	MFAClaim string

	// RequireMFA, if true, rejects id_tokens whose MFAClaim does not
	// indicate MFA. Default true — required by CMMC L2 control 3.5.3
	// (MFA for network access to privileged and non-privileged accounts).
	// Set FB_OIDC_REQUIRE_MFA=false only for dev environments with an IdP
	// that doesn't emit MFA claims.
	RequireMFA bool

	// RequireFIPS, if true, refuses to start the server when the Go
	// runtime is not in FIPS 140 mode (see cmmc/crypto/fips). Default
	// true under OIDC — required by CMMC L2 control 3.13.11. Set
	// FB_OIDC_REQUIRE_FIPS=false only for dev environments where the
	// Go toolchain does not support the runtime assertion.
	RequireFIPS bool

	// AllowInsecureHTTPIssuer, if true, relaxes the https requirement
	// on Issuer and RedirectURI to also accept plain http on non-
	// localhost hostnames. DEV-ONLY escape hatch for LAN-access
	// demos (VM on 192.168.x.x reached from a laptop on the same
	// subnet). CMMC L2 production MUST leave this false (3.13.8 /
	// 3.13.15). Boot logs a loud warning when set.
	AllowInsecureHTTPIssuer bool
}

// LoadFromEnv populates a Config from FB_OIDC_* environment variables. This
// is the prototype bootstrap path; longer-term the config flows through the
// same viper layer upstream filebrowser uses.
func LoadFromEnv() (Config, error) {
	scopes := env("FB_OIDC_SCOPES", "openid profile email")
	cfg := Config{
		Issuer:        env("FB_OIDC_ISSUER", ""),
		ClientID:      env("FB_OIDC_CLIENT_ID", ""),
		ClientSecret:  env("FB_OIDC_CLIENT_SECRET", ""),
		RedirectURI:   env("FB_OIDC_REDIRECT_URI", ""),
		Scopes:        strings.Fields(scopes),
		UsernameClaim: env("FB_OIDC_USERNAME_CLAIM", "preferred_username"),
		GroupsClaim:   env("FB_OIDC_GROUPS_CLAIM", "groups"),
		AdminGroups:   splitAndTrim(env("FB_OIDC_ADMIN_GROUPS", "")),
		MFAClaim:      env("FB_OIDC_MFA_CLAIM", "amr"),
		RequireMFA:              boolEnv("FB_OIDC_REQUIRE_MFA", true),
		RequireFIPS:             boolEnv("FB_OIDC_REQUIRE_FIPS", true),
		AllowInsecureHTTPIssuer: boolEnv("FB_OIDC_ALLOW_INSECURE_HTTP_ISSUER", false),
	}
	return cfg, cfg.Validate()
}

// Validate returns an error if any required field is missing or malformed.
func (c Config) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("oidc: FB_OIDC_ISSUER is required")
	}
	iss, err := url.Parse(c.Issuer)
	if err != nil {
		return fmt.Errorf("oidc: FB_OIDC_ISSUER %q is not a valid URL: %w", c.Issuer, err)
	}
	if iss.Scheme != "https" && !isLocalhost(iss.Hostname()) && !c.AllowInsecureHTTPIssuer {
		return fmt.Errorf("oidc: FB_OIDC_ISSUER must be https except for localhost dev (got %q); set FB_OIDC_ALLOW_INSECURE_HTTP_ISSUER=true for LAN dev only", c.Issuer)
	}
	// Reject Entra multi-tenant endpoints — `common`, `organizations`, and
	// `consumers` accept tokens from ANY tenant, defeating iss-based tenant
	// scoping. Operators must pin to their tenant-id form.
	for _, banned := range []string{"/common/", "/organizations/", "/consumers/"} {
		if strings.Contains(c.Issuer, banned) {
			return fmt.Errorf("oidc: FB_OIDC_ISSUER %q uses a multi-tenant endpoint; pin to your tenant id", c.Issuer)
		}
	}
	if c.ClientID == "" {
		return fmt.Errorf("oidc: FB_OIDC_CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("oidc: FB_OIDC_CLIENT_SECRET is required")
	}
	if c.RedirectURI == "" {
		return fmt.Errorf("oidc: FB_OIDC_REDIRECT_URI is required")
	}
	u, err := url.Parse(c.RedirectURI)
	if err != nil {
		return fmt.Errorf("oidc: FB_OIDC_REDIRECT_URI %q invalid: %w", c.RedirectURI, err)
	}
	if u.Scheme != "https" && !isLocalhost(u.Hostname()) && !c.AllowInsecureHTTPIssuer {
		return fmt.Errorf("oidc: FB_OIDC_REDIRECT_URI must be https (got %q); set FB_OIDC_ALLOW_INSECURE_HTTP_ISSUER=true for LAN dev only", c.RedirectURI)
	}
	if len(c.Scopes) == 0 {
		return fmt.Errorf("oidc: FB_OIDC_SCOPES must include at least openid")
	}
	return nil
}

func isLocalhost(h string) bool {
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func boolEnv(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func splitAndTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
