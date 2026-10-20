import { type FormEvent, useState } from "react";
import { ApiError, MFA_REQUIRED_MESSAGE, post, saveSession } from "../api";
import type { Role, Session } from "../types";
import { ErrorNote, useAction } from "./ui";

interface Props { onLogin: (s: Session) => void; notice?: string }
interface LoginResponse { access_token: string; role: Role }

export function Login({ onLogin, notice }: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [needsOtp, setNeedsOtp] = useState(false);
  const { busy, error, run } = useAction();

  function submit(e: FormEvent) {
    e.preventDefault();
    void run(async () => {
      try {
        const r = await post<LoginResponse>("/auth/login", { email, password, otp: needsOtp ? otp : undefined });
        const session = { token: r.access_token, role: r.role };
        saveSession(session);
        onLogin(session);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401 && err.message === MFA_REQUIRED_MESSAGE) {
          setNeedsOtp(true); // password was accepted; ask for the authenticator code
        }
        throw err;
      }
    });
  }

  return (
    <main className="login">
      <section className="panel" aria-label="Sign in">
        <h1>CYBERSHIELD</h1>
        <p>Defensive cybersecurity fundamentals &amp; monitoring platform</p>
        {notice && <p className="notice" role="status">{notice}</p>}
        <form onSubmit={submit}>
          <label htmlFor="email">Email</label>
          <input id="email" type="email" autoComplete="username" required value={email}
            onChange={(e) => setEmail(e.target.value)} />
          <label htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete="current-password" required value={password}
            onChange={(e) => setPassword(e.target.value)} />
          {needsOtp && (
            <>
              <label htmlFor="otp">Authenticator code</label>
              <input id="otp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6}
                required value={otp} onChange={(e) => setOtp(e.target.value.trim())} />
            </>
          )}
          <ErrorNote message={error} />
          <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
      </section>
    </main>
  );
}
