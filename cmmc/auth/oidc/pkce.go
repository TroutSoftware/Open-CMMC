// Package oidc provides the CMMC-Filebrowser OIDC authentication backend.
//
// The OIDC flow is redirect-based and does not fit the single-shot
// auth.Auther contract used by the JSON/Proxy/Hook backends. Instead,
// dedicated HTTP handlers in the fbhttp package wire the /api/auth/oidc/login
// and /api/auth/oidc/callback routes; those handlers delegate verification
// and claim extraction to the functions in this package.
package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE carries a code_verifier and its S256-derived code_challenge per
// RFC 7636. The verifier is kept by the client (filebrowser server) across
// the redirect and presented to the IdP's token endpoint to prove this
// process initiated the authorize request.
type PKCE struct {
	Verifier  string // 43-char base64url(32 random bytes)
	Challenge string // base64url(SHA-256(Verifier))
	Method    string // always "S256" — plain is rejected by RFC 7636 for new deployments
}

// NewPKCE returns a fresh PKCE pair using crypto/rand. Under FIPS mode on
// RHEL go-toolset this pulls from the FIPS-validated DRBG via OpenSSL.
func NewPKCE() (PKCE, error) {
	b, err := randomBytes(32)
	if err != nil {
		return PKCE{}, fmt.Errorf("pkce: random verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(b) // 43 chars
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return PKCE{Verifier: verifier, Challenge: challenge, Method: "S256"}, nil
}

// NewState returns a fresh random state token for the authorize request.
// RFC 6749 §10.12 requires a non-guessable value to defend against CSRF
// on the redirect leg.
func NewState() (string, error) {
	return randomBase64URL(32)
}

// NewNonce returns a fresh random nonce for the id_token.
// OpenID Connect Core §15.5.2 — the nonce MUST be unguessable and MUST be
// echoed back as the `nonce` claim in the id_token for the verifier to
// match. Defends against token replay across sessions.
func NewNonce() (string, error) {
	return randomBase64URL(32)
}

func randomBase64URL(n int) (string, error) {
	b, err := randomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("pkce: rand.Read: %w", err)
	}
	return b, nil
}

// VerifierChallenge recomputes the S256 challenge for a verifier and returns
// it. Used by tests and by defense-in-depth cross-checks.
func VerifierChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
