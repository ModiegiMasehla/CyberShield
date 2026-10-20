import type { Role, Session } from "./types";

export const API_URL: string = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";
const STORAGE_KEY = "cybershield.session";
export const LOGOUT_EVENT = "cybershield:logout";
export const MFA_REQUIRED_MESSAGE = "MFA verification required";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// sessionStorage (not localStorage): the token disappears when the tab closes. It is still readable by
// any script running on the page, so the page must never render untrusted HTML (React escapes by default).
export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as Partial<Session>) : null;
    return parsed?.token && parsed.role ? { token: parsed.token, role: parsed.role as Role } : null;
  } catch {
    return null;
  }
}
export function saveSession(session: Session | null): void {
  try {
    if (session) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable (private mode): the session just will not survive a reload */
  }
}

export function describeDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((d) => (typeof d === "string" ? d : (d as { msg?: string })?.msg)).filter(Boolean);
    if (parts.length) return parts.join(" ");
  }
  return "Request failed";
}

interface Options {
  method?: "GET" | "POST" | "PATCH";
  json?: unknown;
  form?: FormData;
  timeoutMs?: number;
  signal?: AbortSignal;
}

async function send(path: string, opts: Options): Promise<Response> {
  const session = loadSession();
  const headers: Record<string, string> = {};
  if (session) headers.Authorization = `Bearer ${session.token}`;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form; // the browser sets the multipart boundary itself
  else if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  }
  const timeout = AbortSignal.timeout(opts.timeoutMs ?? 30_000);
  const signal = opts.signal ? AbortSignal.any([opts.signal, timeout]) : timeout;
  let response: Response;
  try {
    response = await fetch(API_URL + path, { method: opts.method ?? "GET", headers, body, signal });
  } catch (e) {
    if (opts.signal?.aborted) throw e;
    const timedOut = e instanceof DOMException && e.name === "TimeoutError";
    throw new ApiError(
      timedOut ? "The request timed out. Try again." : "Cannot reach the server. Check that the backend is running.",
      0,
    );
  }
  if (!response.ok) {
    if (response.status === 401 && session && path !== "/auth/login") {
      saveSession(null);
      window.dispatchEvent(new Event(LOGOUT_EVENT));
    }
    const payload = await response.json().catch(() => ({}));
    throw new ApiError(describeDetail((payload as { detail?: unknown }).detail), response.status);
  }
  return response;
}

export async function request<T>(path: string, opts: Options = {}): Promise<T> {
  const response = await send(path, opts);
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("The server returned an unexpected response.", response.status);
  }
}

export async function download(path: string): Promise<Blob> {
  return (await send(path, { timeoutMs: 60_000 })).blob();
}

export const post = <T>(path: string, json: unknown, timeoutMs?: number) =>
  request<T>(path, { method: "POST", json, timeoutMs });
