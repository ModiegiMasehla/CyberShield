import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import App from "../App";
import { saveSession } from "../api";

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const DASH = { security_score: 80, critical_alerts: 0, high_alerts: 1, medium_alerts: 2, open_incidents: 3, vulnerabilities: 4 };

beforeEach(() => vi.stubGlobal("fetch", vi.fn()));
afterEach(() => vi.unstubAllGlobals());

it("asks for the authenticator code when MFA is required and then signs in", async () => {
  const user = userEvent.setup();
  vi.mocked(fetch)
    .mockResolvedValueOnce(json({ detail: "MFA verification required" }, 401))
    .mockResolvedValueOnce(json({ access_token: "tok", token_type: "bearer", role: "USER" }))
    .mockResolvedValue(json(DASH));
  render(<App />);
  await user.type(screen.getByLabelText("Email"), "a@b.co");
  await user.type(screen.getByLabelText("Password"), "pw");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  const otp = await screen.findByLabelText("Authenticator code");
  await user.type(otp, "123456");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByText("Security Score")).toBeInTheDocument();
  const body = JSON.parse((vi.mocked(fetch).mock.calls[1][1] as RequestInit).body as string);
  expect(body).toMatchObject({ email: "a@b.co", otp: "123456" });
});

it("shows an error for wrong credentials without asking for MFA", async () => {
  const user = userEvent.setup();
  vi.mocked(fetch).mockResolvedValue(json({ detail: "Invalid credentials" }, 401));
  render(<App />);
  await user.type(screen.getByLabelText("Email"), "a@b.co");
  await user.type(screen.getByLabelText("Password"), "bad");
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Invalid credentials");
  expect(screen.queryByLabelText("Authenticator code")).not.toBeInTheDocument();
});

it("hides staff-only sections from ordinary users", async () => {
  saveSession({ token: "t", role: "USER" });
  vi.mocked(fetch).mockResolvedValue(json(DASH));
  render(<App />);
  await screen.findByText("Security Score");
  expect(screen.getByRole("tab", { name: "Tools" })).toBeInTheDocument();
  for (const name of ["Incidents", "Alerts", "Lab tools", "Audit log"]) {
    expect(screen.queryByRole("tab", { name })).not.toBeInTheDocument();
  }
  expect(screen.queryByRole("button", { name: /security report/i })).not.toBeInTheDocument();
});

it("shows admin sections and renders API data as text, never as HTML", async () => {
  const user = userEvent.setup();
  saveSession({ token: "t", role: "ADMIN" });
  vi.mocked(fetch).mockImplementation(async (url) =>
    String(url).endsWith("/incidents")
      ? json([{ id: 1, title: "<img src=x onerror=alert(1)>", severity: "HIGH", category: "c", status: "OPEN", asset: "a",
          description: "d", resolution: null, assigned_analyst_id: null, created_at: null }])
      : json(DASH));
  render(<App />);
  await user.click(await screen.findByRole("tab", { name: "Incidents" }));
  expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
  expect(document.querySelector("img")).toBeNull();
  expect(screen.getByRole("tab", { name: "Audit log" })).toBeInTheDocument();
});

it("returns to the sign-in page with a notice when the session expires", async () => {
  saveSession({ token: "expired", role: "USER" });
  vi.mocked(fetch).mockResolvedValue(json({ detail: "Invalid or expired token" }, 401));
  render(<App />);
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Session expired"));
  expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
});
