package fbhttp

import (
	"net/http"
	"net/url"
	"strings"
)

// isCookieAuthedStateChange reports whether the incoming request
// looks like a state-changing call authenticated via the HttpOnly
// cookie alone (no X-Auth header). That's the CSRF-interesting
// surface: the SPA always sends X-Auth, so an attacker riding on
// the cookie without the header is either a form submission, a
// redirect-triggered GET-turned-POST, or a rogue script.
func isCookieAuthedStateChange(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	if r.Header.Get("X-Auth") != "" {
		return false
	}
	c, _ := r.Cookie("auth")
	return c != nil && c.Value != ""
}

// csrfOriginCheck returns true when the request's Origin (or Referer
// as fallback) names the same host filebrowser is serving from.
// SameSite=Lax already blocks cross-site POST via form / navigation,
// so this is defense-in-depth against:
//   - browsers without SameSite support (old corporate builds),
//   - proxies that strip cookies' SameSite attribute,
//   - extensions that forward same-site headers across origins.
//
// Policy: explicit Origin wins; if absent, fall back to Referer
// (still present on same-origin XHR). If both absent, reject —
// modern browsers send one of the two on any state-changing
// fetch. Non-browser clients that need to call filebrowser's
// state-changing endpoints supply X-Auth instead, which
// short-circuits this check (see isCookieAuthedStateChange).
func csrfOriginCheck(r *http.Request) bool {
	expected := r.Host
	if expected == "" {
		// No Host header — every modern client sends one; reject.
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return originHostEquals(origin, expected)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return originHostEquals(ref, expected)
	}
	return false
}

// originHostEquals extracts the host component of a URL and compares
// it case-insensitively to expected. Handles both full URLs
// (Referer) and scheme+host strings (Origin). Strips :port to keep
// the check on host identity, not port negotiation.
func originHostEquals(raw, expected string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	gotHost := hostWithoutPort(u.Host)
	wantHost := hostWithoutPort(expected)
	return strings.EqualFold(gotHost, wantHost)
}

func hostWithoutPort(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 {
		// IPv6 bracketed form "[...]:port"
		if strings.HasSuffix(h[:i], "]") {
			return h[:i]
		}
		if strings.IndexByte(h[:i], ':') < 0 {
			return h[:i]
		}
	}
	return h
}
