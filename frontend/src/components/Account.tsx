import { type FormEvent, useEffect, useState } from "react";
import { post, request } from "../api";
import type { Me } from "../types";
import { ErrorNote, Panel, errorText, useAction } from "./ui";

interface MfaSetup { secret: string; otpauth_uri: string }

export function Account({ onPasswordChanged }: { onPasswordChanged: () => void }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loadError, setLoadError] = useState("");
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [code, setCode] = useState("");
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [done, setDone] = useState("");
  const mfa = useAction();
  const pw = useAction();

  useEffect(() => {
    const controller = new AbortController();
    request<Me>("/auth/me", { signal: controller.signal })
      .then(setMe)
      .catch((e) => !controller.signal.aborted && setLoadError(errorText(e)));
    return () => controller.abort();
  }, []);

  function startMfa() {
    void mfa.run(async () => setSetup(await post<MfaSetup>("/auth/mfa/setup", {})));
  }
  function enableMfa(e: FormEvent) {
    e.preventDefault();
    void mfa.run(async () => {
      await post("/auth/mfa/enable", { code });
      setMe((m) => (m ? { ...m, mfa_enabled: true } : m));
      setSetup(null);
      setCode("");
      setDone("Multi-factor authentication is now enabled.");
    });
  }
  function changePassword(e: FormEvent) {
    e.preventDefault();
    void pw.run(async () => {
      await post("/auth/password/change", { current_password: current, new_password: next });
      onPasswordChanged(); // every existing session is revoked by the server, so sign in again
    });
  }

  return (
    <div className="grid">
      <Panel title="Multi-factor authentication">
        <ErrorNote message={loadError} />
        {me && <p>Signed in as <b>{me.email}</b> ({me.role}). MFA is <b>{me.mfa_enabled ? "enabled" : "not enabled"}</b>.</p>}
        {done && <p role="status">{done}</p>}
        {me && !me.mfa_enabled && !setup && <button onClick={startMfa} disabled={mfa.busy}>Set up MFA</button>}
        {setup && (
          <form onSubmit={enableMfa}>
            <p>Add this secret to your authenticator app, then enter the 6-digit code it shows.</p>
            <code className="secret">{setup.secret}</code>
            <label htmlFor="mfa-code">Authenticator code</label>
            <input id="mfa-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required
              value={code} onChange={(e) => setCode(e.target.value.trim())} />
            <button type="submit" disabled={mfa.busy}>Enable MFA</button>
          </form>
        )}
        <ErrorNote message={mfa.error} />
      </Panel>
      <Panel title="Change password">
        <form onSubmit={changePassword}>
          <label htmlFor="cur-pw">Current password</label>
          <input id="cur-pw" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
          <label htmlFor="new-pw">New password</label>
          <input id="new-pw" type="password" autoComplete="new-password" required value={next} onChange={(e) => setNext(e.target.value)} />
          <ErrorNote message={pw.error} />
          <button type="submit" disabled={pw.busy}>Change password</button>
        </form>
      </Panel>
    </div>
  );
}
