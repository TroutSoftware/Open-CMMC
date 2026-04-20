import { useAuthStore } from "@/stores/auth";
import router from "@/router";
import type { JwtPayload } from "jwt-decode";
import { jwtDecode } from "jwt-decode";
import { authMethod, baseURL, noAuth, logoutPage } from "./constants";
import { StatusError } from "@/api/utils";
import { setSafeTimeout } from "@/api/utils";
import { isJWTShape } from "./oidc";

export function parseToken(token: string) {
  // falsy or malformed jwt will throw InvalidTokenError
  const data = jwtDecode<JwtPayload & { user: IUser }>(token);

  // JWT lives in-memory only. CMMC 3.13.11 — any XSS sink that
  // previously read `localStorage.jwt` is now blind. A page
  // reload drops the in-memory token; the SPA re-bridges from
  // the HttpOnly cookie by calling /api/renew in validateLogin.
  const authStore = useAuthStore();
  authStore.jwt = token;
  authStore.setUser(data.user);

  // proxy auth with custom logout subject to unknown external timeout
  if (logoutPage !== "/login" && authMethod === "proxy") {
    console.warn("idle timeout disabled with proxy auth and custom logout");
    return;
  }

  if (authStore.logoutTimer) {
    clearTimeout(authStore.logoutTimer);
  }

  const expiresAt = new Date(data.exp! * 1000);
  const timeout = expiresAt.getTime() - Date.now();
  authStore.setLogoutTimer(
    setSafeTimeout(() => {
      logout("inactivity");
    }, timeout)
  );
}

export async function validateLogin() {
  // One-shot migration wipe: earlier builds stored the JWT in
  // localStorage. The CMMC hardening (C1.2) removed that; clean
  // the stale key so an upgrading browser doesn't leave the
  // old token sitting in an XSS-reachable store forever.
  localStorage.removeItem("jwt");

  // Bridge an existing HttpOnly session cookie into the in-memory
  // authStore. /api/renew re-authenticates against the cookie and
  // returns the raw JWT in the response body, which parseToken
  // then stores in Pinia only. 401 => not logged in, fall through
  // to the login flow (router's initAuth handles that path).
  try {
    const res = await fetch(`${baseURL}/api/renew`, {
      method: "POST",
      credentials: "include",
    });
    if (res.status === 200) {
      const token = (await res.text()).trim();
      // Defensive: a 200 with empty / non-JWT body is a
      // misbehaving backend (or a proxy that rewrote the
      // response). Treat as not-authenticated rather than
      // letting jwtDecode throw up the stack and leaving
      // the SPA in a half-loaded state.
      if (!isJWTShape(token)) {
        console.warn("validateLogin: /api/renew returned 200 with non-JWT body, treating as unauthenticated");
        return;
      }
      parseToken(token);
    } else if (res.status === 401) {
      // Not authenticated — normal startup when logged out.
      return;
    } else {
      throw new StatusError(
        `${res.status} ${res.statusText}`,
        res.status
      );
    }
  } catch (error) {
    if (error instanceof StatusError) throw error;
    // Network / parse error — let the caller decide (boot will
    // fall through to login view).
    console.warn("validateLogin: session bridge failed", error);
  }
}

export async function login(
  username: string,
  password: string,
  recaptcha: string
) {
  const data = { username, password, recaptcha };

  const res = await fetch(`${baseURL}/api/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  const body = await res.text();

  if (res.status === 200) {
    parseToken(body);
  } else {
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export async function renew(jwt: string) {
  // credentials:include so the HttpOnly cookie rides along even
  // when the caller has no jwt yet (cold reload in fetchURL's
  // interceptor before parseToken has populated authStore).
  const res = await fetch(`${baseURL}/api/renew`, {
    method: "POST",
    credentials: "include",
    headers: jwt ? { "X-Auth": jwt } : {},
  });

  const body = await res.text();

  if (res.status === 200) {
    parseToken(body);
  } else {
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export async function signup(username: string, password: string) {
  const data = { username, password };

  const res = await fetch(`${baseURL}/api/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(data),
  });

  if (res.status !== 200) {
    const body = await res.text();
    throw new StatusError(
      body || `${res.status} ${res.statusText}`,
      res.status
    );
  }
}

export async function logout(reason?: string) {
  const authStore = useAuthStore();

  // CMMC 3.1.11: under OIDC, clearing only the filebrowser cookie
  // leaves the Keycloak SSO cookie alive — a subsequent /login would
  // silently re-auth. Call the backend to run the IdP end_session
  // handshake, then navigate to its URL. Non-OIDC auth methods fall
  // through to the local-only clear.
  if (authMethod === "oidc") {
    try {
      // The backend authenticates the logout call via withUser, which
      // extracts the JWT from the X-Auth header on non-GET requests
      // (see http/auth.go ExtractToken). The auth cookie is only
      // consulted on GETs. Without this header the handler 401s and
      // the end-session URL is never returned, leaving the Keycloak
      // SSO cookie alive — which looks exactly like logout doing
      // nothing. Read the token BEFORE we clear it.
      const token = authStore.jwt ?? "";
      const res = await fetch(`${baseURL}/api/auth/oidc/logout`, {
        method: "POST",
        credentials: "include",
        headers: token ? { "X-Auth": token } : {},
      });
      authStore.clearUser();
      if (res.ok) {
        const body = (await res.json().catch(() => null)) as {
          end_session_url?: string;
        } | null;
        if (body?.end_session_url) {
          window.location.replace(body.end_session_url);
          return;
        }
      }
    } catch {
      // Network failure → fall through to local-only logout so the
      // user isn't stuck on a working session after clicking logout.
    }
  }

  // HttpOnly cookies can't be cleared from JS. OIDC uses its
  // dedicated endpoint above; native/proxy auth go through the
  // generic /api/auth/logout which expires the cookie server-
  // side. Without this the cookie would silently re-authenticate
  // the "logged out" user until TTL.
  if (authMethod !== "oidc") {
    try {
      await fetch(`${baseURL}/api/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch {
      // Network failure — clear state locally anyway.
    }
  }
  authStore.clearUser();

  if (noAuth) {
    window.location.reload();
  } else if (logoutPage !== "/login") {
    document.location.href = `${logoutPage}`;
  } else {
    if (typeof reason === "string" && reason.trim() !== "") {
      router.push({ path: "/login", query: { "logout-reason": reason } });
    } else {
      router.push({ path: "/login" });
    }
  }
}
