// CMMC OIDC client-side helpers.
//
// The SPA cannot participate in the redirect-based OIDC flow directly,
// but on mount of the login view it needs to decide between:
//  (a) bridging an existing HttpOnly session cookie into the local
//      auth state by calling POST /api/renew (the backend auth-
//      authenticates via the cookie and returns the raw JWT so the
//      SPA can use X-Auth on subsequent XHR), or
//  (b) kicking off /api/auth/oidc/login which 302s to the IdP.
//
// The cookie itself is HttpOnly post-CMMC-hardening (see
// http/oidc.go callback) — JavaScript can't read it, so the decision
// is made by attempting a renew and seeing whether it 200s.

export type OIDCAction =
  | { type: "bridge-session"; token: string }
  | { type: "start-login" }
  | { type: "no-op" };

/**
 * Attempt to bridge an existing HttpOnly session cookie into the SPA
 * by calling POST /api/renew. The cookie rides along automatically
 * with credentials: include. On 200, the response body is the JWT.
 *
 * Returns the action the caller should take next. Pure async — no
 * side effects on auth state.
 *
 * @param authMethod Server-reported auth method (window.FileBrowser.AuthMethod).
 * @param baseURL filebrowser base URL (leading empty or "/foo").
 * @param fetcher injectable for tests; defaults to window.fetch.
 */
export async function decideOIDCAction(
  authMethod: string,
  baseURL: string,
  fetcher: typeof fetch = fetch
): Promise<OIDCAction> {
  if (authMethod !== "oidc") {
    return { type: "no-op" };
  }
  // Empty-string baseURL is legitimate (root deployment) but
  // undefined almost always means the caller forgot to thread
  // settings through — reject noisily.
  if (baseURL === undefined || baseURL === null) {
    throw new TypeError("decideOIDCAction: baseURL is required");
  }
  try {
    const res = await fetcher(`${baseURL}/api/renew`, {
      method: "POST",
      credentials: "include",
    });
    if (res.ok) {
      const token = (await res.text()).trim();
      if (isJWTShape(token)) {
        return { type: "bridge-session", token };
      }
    }
  } catch {
    // Network failure → fall through to re-login.
  }
  return { type: "start-login" };
}

/**
 * Quick structural sanity check that a string could be a JWT. Does NOT
 * validate the signature (the backend does that) — just confirms the
 * three-segment base64url shape so we don't hand garbage to parseToken.
 */
export function isJWTShape(s: string): boolean {
  if (!s) return false;
  const parts = s.split(".");
  if (parts.length !== 3) return false;
  return parts.every((p) => p.length > 0 && /^[A-Za-z0-9_-]+$/.test(p));
}
