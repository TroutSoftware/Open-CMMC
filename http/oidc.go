package fbhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	cmmcoidc "github.com/filebrowser/filebrowser/v2/cmmc/auth/oidc"
	session "github.com/filebrowser/filebrowser/v2/cmmc/auth/session"
	audit "github.com/filebrowser/filebrowser/v2/cmmc/audit"
)

// idTokenCookieName stores the raw id_token returned by the IdP so
// the logout handler can supply it as id_token_hint when it calls
// the end_session_endpoint. HttpOnly + short TTL + strict samesite
// — the SPA never reads this.
const idTokenCookieName = "oidc_id_token"

// oidcLoginHandler begins the OIDC authorization code flow. It generates
// a PKCE pair + state + nonce, stores them in a short-lived signed cookie,
// and 302s the browser to the IdP's authorize endpoint.
func oidcLoginHandler(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if d.settings.AuthMethod != fbAuth.MethodOIDCAuth {
		return http.StatusNotFound, nil
	}
	if !cmmcoidc.Initialized() {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := cmmcoidc.EnsureInitialized(ctx); err != nil {
			return http.StatusServiceUnavailable, err
		}
	}
	// Compute the callback URL from the ACTUAL request origin so a
	// single deployment serves both IP-based and hostname-based
	// access. Users browsing via `https://192.168.x.y:8443/` stay on
	// the IP after login; users on `https://cmmc.local:8443/` stay
	// on the hostname (and therefore keep passkey origin binding).
	// KC's allowlist must include both URIs — bootstrap.sh registers
	// every redirect in REDIRECT_URIS.
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	dynamicRedirect := scheme + "://" + r.Host + "/api/auth/oidc/callback"
	authURL, cookieValue, err := cmmcoidc.BuildAuthorizeRequest(d.settings.Key, dynamicRedirect)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cmmcoidc.StateCookieName,
		Value:    cookieValue,
		Path:     "/",
		Expires:  time.Now().Add(cmmcoidc.StateCookieTTL),
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
	return 0, nil
}

// oidcCallbackHandler finishes the OIDC authorization code flow. It
// validates state, exchanges the code with the PKCE verifier, verifies the
// id_token signature and claims (including nonce), enforces MFA if the
// config requires it, provisions or fetches the local user, and sets the
// filebrowser session auth cookie.
func oidcCallbackHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if d.settings.AuthMethod != fbAuth.MethodOIDCAuth {
			return http.StatusNotFound, nil
		}
		if !cmmcoidc.Initialized() {
			return http.StatusServiceUnavailable, errors.New("oidc: provider not initialized")
		}
		q := r.URL.Query()
		if errCode := q.Get("error"); errCode != "" {
			return http.StatusBadRequest, errors.New("oidc: idp error: " + errCode)
		}
		code := q.Get("code")
		state := q.Get("state")
		if code == "" || state == "" {
			return http.StatusBadRequest, errors.New("oidc: missing code or state")
		}
		cookie, err := r.Cookie(cmmcoidc.StateCookieName)
		if err != nil {
			return http.StatusBadRequest, errors.New("oidc: state cookie missing")
		}
		stateCookie, err := cmmcoidc.DecodeStateCookie(cookie.Value, d.settings.Key)
		if err != nil {
			return http.StatusBadRequest, err
		}
		clearStateCookie(w)

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		sess, err := cmmcoidc.ExchangeAndVerify(ctx, state, code, stateCookie)
		if err != nil {
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeReject, "", "", http.StatusUnauthorized, err.Error())
			return http.StatusUnauthorized, err
		}
		_, _, cfg, _ := cmmcoidc.Snapshot()
		user, err := cmmcoidc.ProvisionOrFetchBySubject(
			d.store.OIDCIdentities, d.store.Users, d.store.GroupPerms,
			sess, cfg.Issuer, cfg.AdminGroups, d.settings, d.server,
		)
		if errors.Is(err, cmmcoidc.ErrUsernameCollision) {
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeReject, "", sess.Username, http.StatusConflict, "username collision")
			return http.StatusConflict, err
		}
		if err != nil {
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeFailure, "", sess.Username, http.StatusInternalServerError, "provisioning error")
			return http.StatusInternalServerError, err
		}
		signed, jti, err := session.Mint(user, sessionSigningKey(d.settings), session.MintOptions{
			TTL:          tokenExpireTime,
			MFAAt:        sess.MFAAt,
			RequireMFAAt: cfg.RequireMFA,
		})
		if err != nil {
			emitAuthEvent(r, audit.ActionAuthLoginFail, audit.OutcomeFailure, userIDString(user.ID), user.Username, http.StatusInternalServerError, "mint error")
			return http.StatusInternalServerError, err
		}
		// CMMC 3.10.2 — Bump the fresh jti into the idle tracker
		// BEFORE the SPA's first request arrives. Without this, the
		// tracker's fail-closed policy on unknown jtis 401s every
		// freshly-logged-in session on its first request.
		if sessionIdleTracker != nil {
			sessionIdleTracker.Bump(jti)
		}
		emitAuthEvent(r, audit.ActionAuthLoginOK, audit.OutcomeSuccess, userIDString(user.ID), user.Username, http.StatusFound, "")
		// CMMC 3.13.11 / defense-in-depth — HttpOnly so an XSS
		// payload cannot read the session JWT. The Vue SPA
		// bridges the session into its in-memory auth state via
		// POST /api/renew, which re-authenticates against this
		// HttpOnly cookie and returns the raw JWT in the response
		// body. See frontend/src/views/Login.vue OIDC onMounted
		// flow for the handoff.
		expires := time.Now().Add(tokenExpireTime)
		setSessionCookie(w, r, "auth", signed, expires)
		// Stash the raw id_token so the logout handler can supply it
		// as id_token_hint to the IdP's end_session_endpoint —
		// required by Entra GCC High, recommended by Keycloak.
		setSessionCookie(w, r, idTokenCookieName, sess.RawIDToken, expires)
		http.Redirect(w, r, "/", http.StatusFound)
		return 0, nil
	}
}

// oidcLogoutHandler clears the local session cookies and returns the
// IdP's end_session_endpoint URL so the SPA can finish the
// front-channel logout. Without this hop the Keycloak SSO cookie
// stays live and a subsequent /login silently re-authenticates the
// user — defeating CMMC 3.1.11 session termination.
//
// Response: {"end_session_url": "..."} — empty string if the IdP
// doesn't advertise end_session_endpoint; the SPA then falls back to
// a local-only redirect.
//
// POST /api/auth/oidc/logout — any authenticated user.
var oidcLogoutHandler = withUser(func(w http.ResponseWriter, r *http.Request, _ *data) (int, error) {
	// CMMC 3.1.11 — front-channel logout must also drop the
	// server-side idle row so a stolen cookie cannot be replayed
	// during the remaining session TTL window. Revoke is sticky
	// even if the same jti shows up again. jti was stashed on the
	// request context by withUser; no re-parse needed.
	if sessionIdleTracker != nil {
		sessionIdleTracker.Revoke(jtiFromContext(r.Context()))
	}
	var idTok string
	if c, err := r.Cookie(idTokenCookieName); err == nil {
		idTok = c.Value
	}
	secure := cookieSecure(r)
	// Delete both session cookies. HttpOnly on both — symmetric
	// with how they were set; any auditor grepping for HttpOnly=true
	// on `auth` sees a consistent story.
	for _, name := range []string{"auth", idTokenCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	postLogout := scheme + "://" + r.Host + "/login"
	endURL, _ := cmmcoidc.EndSessionURL(idTok, postLogout)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"end_session_url": endURL})
	return 0, nil
})

// emitAuthEvent emits a structured audit event for OIDC auth outcomes.
// Kept in this file (rather than http/audit.go) because it touches
// only fbhttp-private helpers (extractor, clientIP-from-request).
func emitAuthEvent(r *http.Request, action, outcome, userID, username string, status int, reason string) {
	ev := audit.New(action, outcome)
	ev.CorrelationID = audit.CorrelationIDFromContext(r.Context())
	ev.ClientIP = clientIP(r)
	ev.UserAgent = r.UserAgent()
	ev.UserID = userID
	ev.Username = username
	ev.Status = status
	ev.Reason = reason
	audit.Emit(r.Context(), ev)
}

// userIDString formats filebrowser's numeric user id into the audit
// record's string user_id field so downstream consumers can treat the
// identifier as an opaque string regardless of the backing store.
func userIDString(id uint) string {
	const digits = "0123456789"
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for id > 0 {
		pos--
		buf[pos] = digits[id%10]
		id /= 10
	}
	return string(buf[pos:])
}

// clientIP picks the best approximation of the caller's IP. Proxy
// headers are trusted only when the server has been placed behind a
// managed reverse proxy (documented in architecture.md §3); for the
// Trout Access Gate deployment profile the NGFW sets
// X-Forwarded-For.
func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return v
	}
	return r.RemoteAddr
}

// clearStateCookie invalidates the short-lived OIDC state cookie.
func clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cmmcoidc.StateCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

