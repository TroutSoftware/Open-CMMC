package oidc

import (
	"strings"
	"testing"
)

func TestConfig_RejectsMultiTenantEntraEndpoints(t *testing.T) {
	bases := []string{
		"https://login.microsoftonline.com/common/v2.0",
		"https://login.microsoftonline.com/organizations/v2.0",
		"https://login.microsoftonline.com/consumers/v2.0",
		"https://login.microsoftonline.us/common/v2.0",
	}
	for _, iss := range bases {
		cfg := Config{
			Issuer:       iss,
			ClientID:     "c",
			ClientSecret: "s",
			RedirectURI:  "https://example.mil/api/auth/oidc/callback",
			Scopes:       []string{"openid"},
		}
		err := cfg.Validate()
		if err == nil {
			t.Errorf("issuer %q should be rejected (multi-tenant endpoint)", iss)
			continue
		}
		if !strings.Contains(err.Error(), "multi-tenant") {
			t.Errorf("issuer %q: want multi-tenant error, got: %v", iss, err)
		}
	}
}

func TestConfig_AcceptsTenantSpecificEntra(t *testing.T) {
	cfg := Config{
		Issuer:       "https://login.microsoftonline.us/11111111-2222-3333-4444-555555555555/v2.0",
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("tenant-specific Entra issuer rejected: %v", err)
	}
}

func TestConfig_RejectsNonHTTPSIssuer(t *testing.T) {
	cfg := Config{
		Issuer:       "http://idp.example.mil/",
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("non-https issuer should be rejected with https error, got: %v", err)
	}
}

// TestConfig_AcceptsHTTPLocalhostIssuer documents the dev-only
// exception: http://localhost:* and 127.0.0.1/::1 issuers are
// accepted because local Keycloak in a container (or tunneled via
// SSH port-forward) is how operators exercise the OIDC flow before
// wiring up a real IdP. Non-localhost http issuers stay rejected —
// see TestConfig_RejectsNonHTTPSIssuer.
func TestConfig_AcceptsHTTPLocalhostIssuer(t *testing.T) {
	cases := []string{
		"http://localhost:8081/realms/cmmc-test",
		"http://127.0.0.1:8081/realms/cmmc-test",
		"http://[::1]:8081/realms/cmmc-test",
	}
	for _, iss := range cases {
		iss := iss
		t.Run(iss, func(t *testing.T) {
			cfg := Config{
				Issuer:       iss,
				ClientID:     "c",
				ClientSecret: "s",
				RedirectURI:  "http://localhost:8080/api/auth/oidc/callback",
				Scopes:       []string{"openid"},
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("localhost http issuer %q should be accepted for dev, got: %v", iss, err)
			}
		})
	}
}

func TestConfig_RequireFIPSDefaultsTrue(t *testing.T) {
	t.Setenv("FB_OIDC_ISSUER", "https://login.microsoftonline.us/11111111-2222-3333-4444-555555555555/v2.0")
	t.Setenv("FB_OIDC_CLIENT_ID", "c")
	t.Setenv("FB_OIDC_CLIENT_SECRET", "s")
	t.Setenv("FB_OIDC_REDIRECT_URI", "https://example.mil/api/auth/oidc/callback")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if !cfg.RequireFIPS {
		t.Errorf("RequireFIPS default must be true (CMMC 3.13.11)")
	}
}

func TestConfig_AllowInsecureHTTPIssuer_AcceptsLANHosts(t *testing.T) {
	// Default: non-localhost http is rejected.
	rejected := Config{
		Issuer:       "http://203.0.113.2:8081/realms/cmmc",
		ClientID:     "c", ClientSecret: "s",
		RedirectURI: "http://203.0.113.2:8080/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}
	if err := rejected.Validate(); err == nil {
		t.Fatal("LAN-IP http issuer must be rejected when AllowInsecureHTTPIssuer=false")
	}

	// With the flag on, both issuer and redirect pass.
	allowed := rejected
	allowed.AllowInsecureHTTPIssuer = true
	if err := allowed.Validate(); err != nil {
		t.Errorf("AllowInsecureHTTPIssuer=true should accept LAN-IP http: %v", err)
	}
}

func TestConfig_AllowInsecureHTTPIssuer_EnvBindsCorrectly(t *testing.T) {
	t.Setenv("FB_OIDC_ISSUER", "http://203.0.113.2:8081/realms/cmmc")
	t.Setenv("FB_OIDC_CLIENT_ID", "c")
	t.Setenv("FB_OIDC_CLIENT_SECRET", "s")
	t.Setenv("FB_OIDC_REDIRECT_URI", "http://203.0.113.2:8080/api/auth/oidc/callback")
	t.Setenv("FB_OIDC_ALLOW_INSECURE_HTTP_ISSUER", "true")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if !cfg.AllowInsecureHTTPIssuer {
		t.Error("env did not propagate to config")
	}
}

func TestConfig_RequireFIPSOverride(t *testing.T) {
	t.Setenv("FB_OIDC_ISSUER", "https://login.microsoftonline.us/tenant-id/v2.0")
	t.Setenv("FB_OIDC_CLIENT_ID", "c")
	t.Setenv("FB_OIDC_CLIENT_SECRET", "s")
	t.Setenv("FB_OIDC_REDIRECT_URI", "https://example.mil/api/auth/oidc/callback")
	t.Setenv("FB_OIDC_REQUIRE_FIPS", "false")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.RequireFIPS {
		t.Errorf("RequireFIPS should be false when env override set")
	}
}

func TestConfig_RequireMFADefaultsTrue(t *testing.T) {
	t.Setenv("FB_OIDC_ISSUER", "https://login.microsoftonline.us/11111111-2222-3333-4444-555555555555/v2.0")
	t.Setenv("FB_OIDC_CLIENT_ID", "c")
	t.Setenv("FB_OIDC_CLIENT_SECRET", "s")
	t.Setenv("FB_OIDC_REDIRECT_URI", "https://example.mil/api/auth/oidc/callback")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if !cfg.RequireMFA {
		t.Errorf("RequireMFA default must be true (CMMC 3.5.3)")
	}
}

func TestConfig_Validate_RequiredFields(t *testing.T) {
	base := Config{
		Issuer:       "https://login.microsoftonline.us/tenant-id/v2.0",
		ClientID:     "c",
		ClientSecret: "s",
		RedirectURI:  "https://example.mil/api/auth/oidc/callback",
		Scopes:       []string{"openid"},
	}
	cases := []struct {
		name  string
		edit  func(*Config)
		want  string
	}{
		{"empty issuer", func(c *Config) { c.Issuer = "" }, "FB_OIDC_ISSUER is required"},
		{"invalid issuer url", func(c *Config) { c.Issuer = "://broken" }, "is not a valid URL"},
		{"empty client_id", func(c *Config) { c.ClientID = "" }, "FB_OIDC_CLIENT_ID"},
		{"empty client_secret", func(c *Config) { c.ClientSecret = "" }, "FB_OIDC_CLIENT_SECRET"},
		{"empty redirect_uri", func(c *Config) { c.RedirectURI = "" }, "FB_OIDC_REDIRECT_URI"},
		{"invalid redirect_uri", func(c *Config) { c.RedirectURI = "://broken" }, "invalid"},
		{"http redirect_uri non-localhost", func(c *Config) { c.RedirectURI = "http://public.example.mil/cb" }, "must be https"},
		{"empty scopes", func(c *Config) { c.Scopes = nil }, "openid"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			c.edit(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err=%v, want containing %q", err, c.want)
			}
		})
	}
}

func TestConfig_Validate_HTTPLocalhostRedirectAccepted(t *testing.T) {
	// Dev convenience: http://localhost/cb is permitted as the only
	// non-https redirect URI (needed for local-machine IdP loopback flows).
	cfg := Config{
		Issuer:       "https://login.microsoftonline.us/tenant-id/v2.0",
		ClientID:     "c", ClientSecret: "s",
		RedirectURI: "http://localhost:8080/api/auth/oidc/callback",
		Scopes:      []string{"openid"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("http://localhost redirect should be accepted for dev; got %v", err)
	}
}

func TestConfig_BoolEnv_InvalidValuesFallBack(t *testing.T) {
	t.Setenv("FB_TEST_BOOL", "not-a-bool")
	if got := boolEnv("FB_TEST_BOOL", true); got != true {
		t.Errorf("invalid bool value should fall back to default true; got false")
	}
	if got := boolEnv("FB_TEST_BOOL", false); got != false {
		t.Errorf("invalid bool value should fall back to default false; got true")
	}
	t.Setenv("FB_TEST_BOOL", "")
	if got := boolEnv("FB_TEST_BOOL", true); got != true {
		t.Errorf("empty bool value should fall back to default; got false")
	}
	t.Setenv("FB_TEST_BOOL", "true")
	if got := boolEnv("FB_TEST_BOOL", false); got != true {
		t.Errorf("valid true should override default false")
	}
	t.Setenv("FB_TEST_BOOL", "false")
	if got := boolEnv("FB_TEST_BOOL", true); got != false {
		t.Errorf("valid false should override default true")
	}
}

func TestConfig_SplitAndTrim(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"single", []string{"single"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{" a , b , c ", []string{"a", "b", "c"}},
		{",,,", nil},
		{"a,,b,", []string{"a", "b"}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.in, func(t *testing.T) {
			got := splitAndTrim(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("len=%d want=%d (got=%v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("i=%d got=%q want=%q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestConfig_IsLocalhost(t *testing.T) {
	cases := map[string]bool{
		"localhost":               true,
		"127.0.0.1":               true,
		"127.0.0.2":               true, // any 127/8 is loopback
		"::1":                     true,
		"10.0.0.1":                false,
		"example.com":             false,
		"0.0.0.0":                 false,
	}
	for host, want := range cases {
		if got := isLocalhost(host); got != want {
			t.Errorf("isLocalhost(%q) = %v, want %v", host, got, want)
		}
	}
}
