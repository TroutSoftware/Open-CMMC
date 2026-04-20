package fbhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsCookieAuthedStateChange_GETIgnored(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: "a.b.c"})
	if isCookieAuthedStateChange(r) {
		t.Error("GET must not trigger CSRF gate")
	}
}

func TestIsCookieAuthedStateChange_XAuthBypassesGate(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set("X-Auth", "a.b.c")
	r.AddCookie(&http.Cookie{Name: "auth", Value: "a.b.c"})
	if isCookieAuthedStateChange(r) {
		t.Error("X-Auth header must short-circuit CSRF gate (SPA/CLI path)")
	}
}

func TestIsCookieAuthedStateChange_CookieOnlyPOST_HitsGate(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.AddCookie(&http.Cookie{Name: "auth", Value: "a.b.c"})
	if !isCookieAuthedStateChange(r) {
		t.Error("cookie-only POST must trigger CSRF gate")
	}
}

func TestIsCookieAuthedStateChange_NoAuthAtAll(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	if isCookieAuthedStateChange(r) {
		t.Error("no cookie, no header → not a CSRF-gate case (withUser 401s separately)")
	}
}

func TestCSRFOriginCheck_ExplicitOriginMatches(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "cabinet.example.mil:8080"
	r.Header.Set("Origin", "https://cabinet.example.mil:8080")
	if !csrfOriginCheck(r) {
		t.Error("same-host Origin should pass (port-stripped)")
	}
}

func TestCSRFOriginCheck_OriginPortMismatchStillPasses(t *testing.T) {
	// Host check strips port — mismatched ports on same host still
	// pass. This is intentional: filebrowser binds 8080, Origin
	// often comes as no-port when behind a proxy on 443.
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "cabinet.example.mil:8080"
	r.Header.Set("Origin", "https://cabinet.example.mil")
	if !csrfOriginCheck(r) {
		t.Error("same-host port-mismatch should pass (operator decided via Host)")
	}
}

func TestCSRFOriginCheck_CrossOriginRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "cabinet.example.mil"
	r.Header.Set("Origin", "https://attacker.evil")
	if csrfOriginCheck(r) {
		t.Error("cross-origin must be rejected")
	}
}

func TestCSRFOriginCheck_RefererFallback(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "cabinet.example.mil"
	r.Header.Set("Referer", "https://cabinet.example.mil/files/")
	if !csrfOriginCheck(r) {
		t.Error("Referer fallback on same host should pass")
	}
}

func TestCSRFOriginCheck_NoHeadersRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "cabinet.example.mil"
	if csrfOriginCheck(r) {
		t.Error("neither Origin nor Referer → must reject (modern browsers always send one)")
	}
}

func TestCSRFOriginCheck_EmptyHostRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = ""
	r.Header.Set("Origin", "https://cabinet.example.mil")
	if csrfOriginCheck(r) {
		t.Error("empty Host header → reject (defensive)")
	}
}

func TestCSRFOriginCheck_MalformedOriginRejected(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "cabinet.example.mil"
	r.Header.Set("Origin", "not a url")
	if csrfOriginCheck(r) {
		t.Error("malformed Origin must not accidentally pass")
	}
}

func TestCSRFOriginCheck_CaseInsensitiveHost(t *testing.T) {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "Cabinet.Example.MIL"
	r.Header.Set("Origin", "https://cabinet.example.mil")
	if !csrfOriginCheck(r) {
		t.Error("host compare must be case-insensitive")
	}
}
