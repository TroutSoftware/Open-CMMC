import { describe, it, expect, vi } from "vitest";
import { decideOIDCAction, isJWTShape } from "../oidc";

// Decision table for the Login.vue OIDC branch. HttpOnly cookie
// hardening means the SPA can no longer read the auth cookie from
// JS; decideOIDCAction now bridges the session by calling /api/renew
// which rides the HttpOnly cookie server-side.

const validJWT =
  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_def-ghi";

function fakeFetch(status: number, body: string) {
  return vi.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    text: async () => body,
  })) as unknown as typeof fetch;
}

describe("decideOIDCAction", () => {
  it("returns no-op when auth method is not oidc", async () => {
    const f = fakeFetch(200, validJWT);
    expect(await decideOIDCAction("json", "", f)).toEqual({ type: "no-op" });
    expect(await decideOIDCAction("", "", f)).toEqual({ type: "no-op" });
    expect(f).not.toHaveBeenCalled();
  });

  it("bridges session when /api/renew returns a valid JWT", async () => {
    const f = fakeFetch(200, validJWT);
    const action = await decideOIDCAction("oidc", "", f);
    expect(action).toEqual({ type: "bridge-session", token: validJWT });
    expect(f).toHaveBeenCalledWith(
      "/api/renew",
      expect.objectContaining({ method: "POST", credentials: "include" })
    );
  });

  it("starts login when /api/renew 401s", async () => {
    const f = fakeFetch(401, "");
    expect(await decideOIDCAction("oidc", "", f)).toEqual({
      type: "start-login",
    });
  });

  it("starts login when /api/renew returns malformed body", async () => {
    const f = fakeFetch(200, "not-a-jwt");
    expect(await decideOIDCAction("oidc", "", f)).toEqual({
      type: "start-login",
    });
  });

  it("trims whitespace from the renew body before shape-check", async () => {
    const f = fakeFetch(200, "  " + validJWT + "\n");
    const action = await decideOIDCAction("oidc", "", f);
    expect(action).toEqual({ type: "bridge-session", token: validJWT });
  });

  it("starts login when the fetch throws", async () => {
    const f = vi.fn(async () => {
      throw new Error("network");
    }) as unknown as typeof fetch;
    expect(await decideOIDCAction("oidc", "", f)).toEqual({
      type: "start-login",
    });
  });

  it("respects baseURL prefix", async () => {
    const f = fakeFetch(200, validJWT);
    await decideOIDCAction("oidc", "/fb", f);
    expect(f).toHaveBeenCalledWith(
      "/fb/api/renew",
      expect.objectContaining({ method: "POST" })
    );
  });
});

describe("isJWTShape", () => {
  it("accepts three-segment base64url", () => {
    expect(isJWTShape("abc.def.ghi")).toBe(true);
    expect(isJWTShape(validJWT)).toBe(true);
  });

  it("rejects segment count other than 3", () => {
    expect(isJWTShape("abc.def")).toBe(false);
    expect(isJWTShape("a.b.c.d")).toBe(false);
    expect(isJWTShape("onlyone")).toBe(false);
  });

  it("rejects empty segments", () => {
    expect(isJWTShape("abc..ghi")).toBe(false);
    expect(isJWTShape(".def.ghi")).toBe(false);
    expect(isJWTShape("abc.def.")).toBe(false);
  });

  it("rejects characters outside base64url", () => {
    expect(isJWTShape("abc.def.ghi+jkl")).toBe(false);
    expect(isJWTShape("abc.def.ghi/jkl")).toBe(false);
    expect(isJWTShape("abc.def.ghi=jkl")).toBe(false);
  });

  it("rejects empty string", () => {
    expect(isJWTShape("")).toBe(false);
  });
});
