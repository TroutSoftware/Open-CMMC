import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { setActivePinia, createPinia } from "pinia";

// Minimal in-memory localStorage shim so tests don't require jsdom.
// The SPA code under test only uses getItem/setItem/removeItem.
class MemoryStorage {
  private data = new Map<string, string>();
  getItem(k: string) {
    return this.data.has(k) ? this.data.get(k)! : null;
  }
  setItem(k: string, v: string) {
    this.data.set(k, v);
  }
  removeItem(k: string) {
    this.data.delete(k);
  }
  clear() {
    this.data.clear();
  }
}
(globalThis as unknown as { localStorage: MemoryStorage }).localStorage =
  new MemoryStorage();

// jwtDecode is used by parseToken — stub so we don't need a real
// signed JWT in tests; we only care about the SPA-side plumbing.
vi.mock("jwt-decode", () => ({
  jwtDecode: (s: string) => {
    if (!s.includes(".")) throw new Error("bad");
    return {
      user: { id: 42, username: "alice" } as IUser,
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
  },
}));

vi.mock("@/router", () => ({
  default: { push: vi.fn() },
}));

vi.mock("../constants", () => ({
  baseURL: "",
  authMethod: "oidc",
  noAuth: false,
  logoutPage: "/login",
}));

// setSafeTimeout is from api/utils — stub to avoid needing window.
vi.mock("@/api/utils", async () => {
  const actual = await vi.importActual<typeof import("@/api/utils")>(
    "@/api/utils"
  );
  return {
    ...actual,
    setSafeTimeout: vi.fn((_fn: () => void, _ms: number) => 1),
  };
});

import { validateLogin, renew, parseToken } from "../auth";
import { useAuthStore } from "@/stores/auth";

const validJWT = "aaa.bbb.ccc";

function mockFetch(res: { status: number; body: string }) {
  const m = vi.fn(async () => ({
    ok: res.status >= 200 && res.status < 300,
    status: res.status,
    statusText: "",
    text: async () => res.body,
  }));
  globalThis.fetch = m as unknown as typeof fetch;
  return m;
}

beforeEach(() => {
  setActivePinia(createPinia());
  localStorage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("validateLogin — HttpOnly cookie bridge", () => {
  it("bridges JWT from /api/renew when cookie-authenticated (200)", async () => {
    const f = mockFetch({ status: 200, body: validJWT });
    await validateLogin();
    const store = useAuthStore();
    expect(store.jwt).toBe(validJWT);
    expect(store.user?.username).toBe("alice");
    expect(f).toHaveBeenCalledWith(
      "/api/renew",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
      })
    );
  });

  it("silently returns on 401 (not logged in — normal startup)", async () => {
    mockFetch({ status: 401, body: "" });
    await expect(validateLogin()).resolves.toBeUndefined();
    const store = useAuthStore();
    expect(store.jwt).toBe("");
    expect(store.user).toBeNull();
  });

  it("throws StatusError on non-401 server errors", async () => {
    mockFetch({ status: 500, body: "oops" });
    await expect(validateLogin()).rejects.toMatchObject({
      status: 500,
    });
  });

  it("wipes stale localStorage.jwt from pre-C1.2 builds", async () => {
    localStorage.setItem("jwt", "stale.token.value");
    mockFetch({ status: 401, body: "" });
    await validateLogin();
    expect(localStorage.getItem("jwt")).toBeNull();
  });

  it("treats 200 + empty body as unauthenticated (defensive)", async () => {
    mockFetch({ status: 200, body: "" });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await validateLogin();
    expect(useAuthStore().jwt).toBe("");
    expect(warn).toHaveBeenCalled();
  });

  it("treats 200 + non-JWT body as unauthenticated (defensive)", async () => {
    mockFetch({ status: 200, body: "not-a-jwt" });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await validateLogin();
    expect(useAuthStore().jwt).toBe("");
    expect(warn).toHaveBeenCalled();
  });

  it("does not throw on network failure — console warn only", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("network");
    }) as unknown as typeof fetch;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(validateLogin()).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalled();
  });
});

describe("renew — credentials:include so cookie can auth", () => {
  it("sends credentials:include even when jwt is empty", async () => {
    const f = mockFetch({ status: 200, body: validJWT });
    await renew("");
    expect(f).toHaveBeenCalledWith(
      "/api/renew",
      expect.objectContaining({
        method: "POST",
        credentials: "include",
      })
    );
    const [, opts] = (f.mock.calls[0] ?? []) as [
      string,
      RequestInit
    ];
    // No X-Auth header when jwt is empty — cookie is the sole channel.
    expect((opts.headers as Record<string, string>)["X-Auth"]).toBeUndefined();
  });

  it("includes X-Auth header when jwt is provided", async () => {
    const f = mockFetch({ status: 200, body: validJWT });
    await renew("old.jwt.here");
    const [, opts] = (f.mock.calls[0] ?? []) as [
      string,
      RequestInit
    ];
    expect((opts.headers as Record<string, string>)["X-Auth"]).toBe(
      "old.jwt.here"
    );
  });
});

describe("parseToken — JWT in memory only", () => {
  it("populates authStore but does NOT touch localStorage", () => {
    parseToken(validJWT);
    expect(useAuthStore().jwt).toBe(validJWT);
    expect(localStorage.getItem("jwt")).toBeNull();
  });
});
