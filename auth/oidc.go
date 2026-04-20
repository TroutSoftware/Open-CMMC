package auth

import (
	"net/http"
	"os"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodOIDCAuth identifies the OIDC (OpenID Connect) auth method.
//
// OIDC is redirect-based and cannot fit the single-shot Auther.Auth
// contract. Dedicated HTTP routes at /api/auth/oidc/login and
// /api/auth/oidc/callback handle the flow; this stub exists only so that
// settings.AuthMethod = "oidc" can be registered in the storage layer.
const MethodOIDCAuth settings.AuthMethod = "oidc"

// OIDCAuth is a stub Auther for settings.AuthMethod = "oidc". Its Auth
// always returns os.ErrPermission because clients MUST use the dedicated
// /api/auth/oidc/login entry point; the JSON POST /api/login path is not
// applicable to OIDC. LoginPage returns false so the frontend skips the
// JSON-creds form and redirects to the OIDC login endpoint.
type OIDCAuth struct{}

// Auth always refuses. See type doc for rationale.
func (OIDCAuth) Auth(*http.Request, users.Store, *settings.Settings, *settings.Server) (*users.User, error) {
	return nil, os.ErrPermission
}

// LoginPage returns false; OIDC uses redirect endpoints, not a form.
func (OIDCAuth) LoginPage() bool { return false }
