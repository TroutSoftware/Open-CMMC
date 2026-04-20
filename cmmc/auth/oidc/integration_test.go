package oidc_test

// Compliance regression tests. These assert that the upstream-touched
// integration points for the CMMC OIDC backend stay wired. They fail
// loudly on rebase if upstream refactors the auth dispatch, the
// MethodOIDCAuth constant, or the registration path.

import (
	"testing"

	"github.com/filebrowser/filebrowser/v2/auth"
)

// TestComplianceRegression_MethodOIDCAuthConst pins the AuthMethod string.
// Changing this silently would break SSP references and deployments' env
// config (FB_OIDC_ISSUER is gated on settings.AuthMethod == "oidc").
func TestComplianceRegression_MethodOIDCAuthConst(t *testing.T) {
	if string(auth.MethodOIDCAuth) != "oidc" {
		t.Fatalf("MethodOIDCAuth = %q, must be \"oidc\" (SSP-referenced constant)", auth.MethodOIDCAuth)
	}
}

// TestComplianceRegression_OIDCAuthImplementsAuther ensures the stub
// still satisfies the Auther interface. If upstream refactors Auther,
// this breaks loudly here rather than at runtime.
func TestComplianceRegression_OIDCAuthImplementsAuther(t *testing.T) {
	var _ auth.Auther = (*auth.OIDCAuth)(nil)
}

// TestComplianceRegression_OIDCAuthRefusesJSONLogin documents the
// intended behavior: OIDC never honors POST /api/login. If someone
// accidentally "fixes" the stub to return a user, every deployment's
// assumption (that auth always passes through /api/auth/oidc/callback)
// breaks.
func TestComplianceRegression_OIDCAuthRefusesJSONLogin(t *testing.T) {
	a := auth.OIDCAuth{}
	u, err := a.Auth(nil, nil, nil, nil)
	if u != nil || err == nil {
		t.Fatalf("OIDCAuth.Auth must always refuse; got user=%v err=%v", u, err)
	}
	if a.LoginPage() {
		t.Fatal("OIDCAuth.LoginPage must return false (no JSON form)")
	}
}
