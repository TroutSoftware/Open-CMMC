package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// VerifiedSession is the outcome of a successful /callback. It holds the
// claims needed for filebrowser user provisioning and session issuance.
type VerifiedSession struct {
	Subject       string   // stable identifier from the id_token "sub" claim
	Username      string   // claim identified by Config.UsernameClaim
	Email         string   // best-effort from "email"
	FullName      string   // best-effort from "name" (given_name + family_name)
	Groups        []string // claim identified by Config.GroupsClaim
	MFAAt         time.Time
	IsAdmin       bool
	RawIDToken    string // for audit only; never logged
	RawAccessTok  string // for audit only; never logged
}

// ExchangeAndVerify runs the /callback half of the OIDC flow: state check,
// authorization-code exchange with PKCE verifier, id_token signature and
// claim verification, and MFA claim enforcement.
//
// ctx should be a request-scoped context (includes timeout).
// state is the `state` query parameter from the IdP redirect.
// code  is the `code` query parameter.
// stateCookie is the parsed StateCookie recovered from the fb_oidc_state cookie.
func ExchangeAndVerify(ctx context.Context, state, code string, stateCookie StateCookie) (*VerifiedSession, error) {
	oa, verifier, cfg, ok := Snapshot()
	if !ok {
		return nil, errors.New("oidc: provider not initialized")
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.State)) != 1 {
		return nil, errors.New("oidc: state mismatch")
	}
	// Replay the exact redirect URI from /login. OIDC spec (RFC 6749
	// §4.1.3) requires the token-exchange redirect_uri to match the
	// authorize request. When BuildAuthorizeRequest was called with a
	// per-request redirect (IP vs hostname), the state cookie carries
	// it forward; fall back to the singleton's static URL otherwise.
	if stateCookie.RedirectURI != "" {
		oaCopy := *oa
		oaCopy.RedirectURL = stateCookie.RedirectURI
		oa = &oaCopy
	}
	tok, err := oa.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", stateCookie.Verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("oidc: id_token missing from token response")
	}
	idTok, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verify: %w", err)
	}
	if idTok.Nonce != stateCookie.Nonce {
		return nil, errors.New("oidc: id_token nonce mismatch")
	}
	claims, err := extractClaims(idTok, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.RequireMFA {
		if claims.MFAAt.IsZero() {
			return nil, errors.New("oidc: MFA required but id_token does not indicate MFA")
		}
	}
	claims.RawIDToken = rawID
	claims.RawAccessTok = tok.AccessToken
	return claims, nil
}

// rawClaims matches the subset of id_token claims we read. All fields are
// interface{} on purpose — IdPs render arrays vs strings inconsistently for
// groups/amr, and we normalize in code.
type rawClaims struct {
	Sub               string      `json:"sub"`
	Email             string      `json:"email"`
	PreferredUsername string      `json:"preferred_username"`
	UPN               string      `json:"upn"`
	Name              string      `json:"name"`
	Groups            interface{} `json:"groups"`
	AMR               interface{} `json:"amr"`
	ACR               string      `json:"acr"`
	AuthTime          int64       `json:"auth_time"`
	Username          interface{} `json:"username"`
}

func extractClaims(idTok *oidc.IDToken, cfg Config) (*VerifiedSession, error) {
	var rc rawClaims
	if err := idTok.Claims(&rc); err != nil {
		return nil, fmt.Errorf("oidc: claim extraction: %w", err)
	}
	if rc.Sub == "" {
		return nil, errors.New("oidc: id_token missing 'sub' claim")
	}
	sess := &VerifiedSession{
		Subject:  rc.Sub,
		Email:    rc.Email,
		FullName: rc.Name,
	}

	// Username — prefer configured claim, then common fallbacks.
	sess.Username = pickStringClaim(rc, cfg.UsernameClaim)
	if sess.Username == "" {
		sess.Username = firstNonEmpty(rc.PreferredUsername, rc.UPN, rc.Email, rc.Name, rc.Sub)
	}

	// Groups — from configured claim; also accepts `groups` for convenience.
	groupsRaw := genericClaim(rc, cfg.GroupsClaim)
	if groupsRaw == nil {
		groupsRaw = rc.Groups
	}
	sess.Groups = normalizeStringSlice(groupsRaw)

	// Admin determination — any configured AdminGroup in the user's groups.
	adminSet := toSet(cfg.AdminGroups)
	for _, g := range sess.Groups {
		if _, ok := adminSet[g]; ok {
			sess.IsAdmin = true
			break
		}
	}

	// MFA — read whichever claim the operator identified.
	switch strings.ToLower(cfg.MFAClaim) {
	case "amr":
		amr := normalizeStringSlice(rc.AMR)
		for _, v := range amr {
			lv := strings.ToLower(v)
			if lv == "mfa" || strings.HasPrefix(lv, "mfa") || lv == "hwk" || lv == "swk" || lv == "otp" {
				sess.MFAAt = authTime(rc.AuthTime)
				break
			}
		}
	case "acr":
		// Keycloak: acr "2" means multi-factor; some IdPs emit "urn:*:loa-3"
		// or similar. Treat any acr != "0" and != "" as MFA-indicative.
		if rc.ACR != "" && rc.ACR != "0" {
			sess.MFAAt = authTime(rc.AuthTime)
		}
	}

	// Fallback: when amr didn't signal MFA explicitly but the id_token
	// carries acr=1+ (Keycloak sends "1" or higher for any flow that
	// traversed the MFA step), trust it. Without this, Keycloak's
	// CONFIGURE_TOTP required-action flow — which prompts the user to
	// set up TOTP + enter one code during the SAME login — emits
	// amr:["pwd"] (TOTP setup isn't counted as a challenge) but acr="1",
	// and every privileged op after that first login 401s until the
	// user logs out and back in to trigger an explicit TOTP challenge.
	// We own the realm config and require TOTP enrollment realm-wide,
	// so acr!="0" IS sufficient evidence.
	if sess.MFAAt.IsZero() && rc.ACR != "" && rc.ACR != "0" {
		sess.MFAAt = authTime(rc.AuthTime)
	}

	return sess, nil
}

func authTime(ts int64) time.Time {
	if ts <= 0 {
		return time.Now()
	}
	return time.Unix(ts, 0)
}

func pickStringClaim(rc rawClaims, claim string) string {
	switch strings.ToLower(claim) {
	case "preferred_username":
		return rc.PreferredUsername
	case "upn":
		return rc.UPN
	case "email":
		return rc.Email
	case "name":
		return rc.Name
	case "sub":
		return rc.Sub
	case "username":
		if s, ok := rc.Username.(string); ok {
			return s
		}
	}
	return ""
}

func genericClaim(rc rawClaims, claim string) interface{} {
	switch strings.ToLower(claim) {
	case "groups":
		return rc.Groups
	case "amr":
		return rc.AMR
	}
	return nil
}

func normalizeStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
