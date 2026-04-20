package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// StateCookie carries the short-lived correlation between /login and
// /callback. We don't need a server-side table: the cookie is signed with
// the same HS256 key already used for session JWTs, so tampering is
// detectable at verify time.
//
// RedirectURI is the origin-specific callback URL used for this login
// attempt. Stored here so /callback's token-exchange can replay the
// SAME URL value OIDC requires exact-match between the two calls. A
// deployment that serves filebrowser at both an IP and a hostname
// (see FB_OIDC_REDIRECT_URIS on the realm side) can thus support
// either origin without a redeploy.
type StateCookie struct {
	State       string `json:"s"`
	Nonce       string `json:"n"`
	Verifier    string `json:"v"`
	IssuedAt    int64  `json:"iat"`
	RedirectURI string `json:"ru,omitempty"`
}

// StateCookieTTL bounds how long /login → /callback can take. 10 minutes is
// the commonly-accepted max for interactive flows and is generous for SSO
// + MFA redirects.
const StateCookieTTL = 10 * time.Minute

// StateCookieName is the name of the short-lived cookie set during /login.
const StateCookieName = "fb_oidc_state"

// BuildAuthorizeRequest produces (1) the authorize URL the browser must
// redirect to and (2) an encoded, HMAC-signed state cookie to set before
// issuing that redirect.
//
// signingKey is the process-wide HS256 key (settings.Key upstream) and is
// reused here so we do not introduce a second secret into the deployment.
//
// redirectURI is an optional per-request override for the OAuth2
// RedirectURL. When non-empty, it's used for this authorize request and
// stashed in the state cookie so /callback can reuse it on the token
// exchange (OIDC spec requires exact match). Empty falls back to the
// RedirectURI set at InitProvider time — the legacy single-origin path.
func BuildAuthorizeRequest(signingKey []byte, redirectURI string) (authorizeURL string, cookieValue string, err error) {
	oa, _, _, ok := Snapshot()
	if !ok {
		return "", "", errors.New("oidc: provider not initialized")
	}
	// Override the oauth2.Config per-request when the caller supplied a
	// dynamic redirect. Don't mutate the singleton — make a shallow
	// copy instead. go-oauth2 threads the RedirectURL into both
	// AuthCodeURL and Exchange, so a later /callback needs the same
	// value (via the state cookie).
	if redirectURI != "" {
		oaCopy := *oa
		oaCopy.RedirectURL = redirectURI
		oa = &oaCopy
	}
	pkce, err := NewPKCE()
	if err != nil {
		return "", "", err
	}
	state, err := NewState()
	if err != nil {
		return "", "", err
	}
	nonce, err := NewNonce()
	if err != nil {
		return "", "", err
	}
	sc := StateCookie{
		State:       state,
		Nonce:       nonce,
		Verifier:    pkce.Verifier,
		IssuedAt:    time.Now().Unix(),
		RedirectURI: redirectURI,
	}
	cookieValue, err = encodeStateCookie(sc, signingKey)
	if err != nil {
		return "", "", err
	}
	authorizeURL = oa.AuthCodeURL(
		state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", pkce.Challenge),
		oauth2.SetAuthURLParam("code_challenge_method", pkce.Method),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return authorizeURL, cookieValue, nil
}

// DecodeStateCookie parses and verifies the HMAC signature of a state
// cookie issued by BuildAuthorizeRequest. It also enforces the TTL.
func DecodeStateCookie(cookieValue string, signingKey []byte) (StateCookie, error) {
	body, sig, ok := strings.Cut(cookieValue, ".")
	if !ok || sig == "" {
		return StateCookie{}, errors.New("oidc: state cookie malformed")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return StateCookie{}, fmt.Errorf("oidc: state cookie body: %w", err)
	}
	sigGiven, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return StateCookie{}, fmt.Errorf("oidc: state cookie sig: %w", err)
	}
	sigWant := macBytes(signingKey, raw)
	if !hmac.Equal(sigGiven, sigWant) {
		return StateCookie{}, errors.New("oidc: state cookie signature mismatch")
	}
	var sc StateCookie
	if err := json.Unmarshal(raw, &sc); err != nil {
		return StateCookie{}, fmt.Errorf("oidc: state cookie decode: %w", err)
	}
	if time.Since(time.Unix(sc.IssuedAt, 0)) > StateCookieTTL {
		return StateCookie{}, errors.New("oidc: state cookie expired")
	}
	return sc, nil
}

func encodeStateCookie(sc StateCookie, signingKey []byte) (string, error) {
	raw, err := json.Marshal(sc)
	if err != nil {
		return "", fmt.Errorf("oidc: state cookie marshal: %w", err)
	}
	sig := macBytes(signingKey, raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func macBytes(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}
