import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, LOGOUT_EVENT, describeDetail, loadSession, request, saveSession } from "../api";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("api client", () => {
  beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
  afterEach(() => vi.unstubAllGlobals());

  it("flattens validation error arrays and strings", () => {
    expect(describeDetail([{ msg: "too short" }, "other"])).toBe("too short other");
    expect(describeDetail("Nope")).toBe("Nope");
    expect(describeDetail(undefined)).toBe("Request failed");
  });

  it("sends the bearer token and JSON content type", async () => {
    saveSession({ token: "t0k", role: "USER" });
    vi.mocked(fetch).mockResolvedValue(json({ ok: true }));
    await request("/x", { method: "POST", json: { a: 1 } });
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ Authorization: "Bearer t0k", "Content-Type": "application/json" });
  });

  it("does not force a JSON content type on multipart uploads", async () => {
    vi.mocked(fetch).mockResolvedValue(json({}));
    await request("/upload", { method: "POST", form: new FormData() });
    const init = vi.mocked(fetch).mock.calls[0][1] as RequestInit;
    expect(init.headers).not.toHaveProperty("Content-Type");
  });

  it("clears the session and signals logout on 401 for an authenticated call", async () => {
    saveSession({ token: "t0k", role: "USER" });
    const onLogout = vi.fn();
    window.addEventListener(LOGOUT_EVENT, onLogout);
    vi.mocked(fetch).mockResolvedValue(json({ detail: "Invalid or expired token" }, 401));
    await expect(request("/dashboard")).rejects.toMatchObject({ status: 401 });
    expect(loadSession()).toBeNull();
    expect(onLogout).toHaveBeenCalledOnce();
    window.removeEventListener(LOGOUT_EVENT, onLogout);
  });

  it("does not treat a failed login as an expired session", async () => {
    saveSession({ token: "old", role: "USER" });
    const onLogout = vi.fn();
    window.addEventListener(LOGOUT_EVENT, onLogout);
    vi.mocked(fetch).mockResolvedValue(json({ detail: "Invalid credentials" }, 401));
    await expect(request("/auth/login", { method: "POST", json: {} })).rejects.toBeInstanceOf(ApiError);
    expect(onLogout).not.toHaveBeenCalled();
    window.removeEventListener(LOGOUT_EVENT, onLogout);
  });

  it("reports an unreachable backend in plain language", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("Failed to fetch"));
    await expect(request("/dashboard")).rejects.toThrow(/Cannot reach the server/);
  });

  it("rejects a 200 response that is not JSON", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("<html>", { status: 200 }));
    await expect(request("/dashboard")).rejects.toThrow(/unexpected response/);
  });

  it("ignores corrupt stored sessions", () => {
    sessionStorage.setItem("cybershield.session", "{not json");
    expect(loadSession()).toBeNull();
  });
});
