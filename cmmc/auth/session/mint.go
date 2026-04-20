package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/filebrowser/filebrowser/v2/users"
)

// MintOptions controls the one CMMC-specific knob at token issuance:
// whether the caller requires an MFA timestamp in the resulting token.
// Non-OIDC flows set RequireMFAAt=false (they cannot prove MFA).
type MintOptions struct {
	TTL          time.Duration
	MFAAt        time.Time // zero means "no MFA asserted"
	RequireMFAAt bool      // if true, zero MFAAt returns an error
}

// Mint produces an HS256 session JWT carrying the user info, a fresh
// JTI, and (when provided) the cmmc_mfa_at claim. Returns the
// signed token and the minted jti — callers that enforce an idle
// session tracker (CMMC 3.10.2) must Bump the jti so the first
// request doesn't fail-closed against an unknown jti.
//
// The signing key should be the same key the upstream withUser
// parser uses (typically the HKDF-derived session subkey) so mint
// and verify agree on the MAC.
func Mint(u *users.User, signingKey []byte, opts MintOptions) (string, string, error) {
	if opts.TTL <= 0 {
		return "", "", errors.New("session: TTL must be positive")
	}
	if opts.RequireMFAAt && opts.MFAAt.IsZero() {
		return "", "", errors.New("session: MFA required but MFAAt is zero")
	}
	jti, err := newJTI()
	if err != nil {
		return "", "", fmt.Errorf("session: JTI: %w", err)
	}
	claims := Claims{
		User:  UserInfoFromUser(u),
		JTI:   jti,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(opts.TTL)),
			Issuer:    "File Browser",
			ID:        jti, // standard `jti` claim — mirrored for non-CMMC parsers
		},
	}
	if !opts.MFAAt.IsZero() {
		claims.MFAAt = opts.MFAAt.Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(signingKey)
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

// newJTI returns a 16-byte URL-safe base64 random id. Short enough for
// a cookie, long enough (128 bits) to be unguessable for replay
// defense.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
