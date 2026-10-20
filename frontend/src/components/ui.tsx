import { type ReactNode, useCallback, useState } from "react";

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong.";
}

/** Runs an async action with busy/error state so every panel gives loading and failure feedback. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const run = useCallback(async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run, clearError: () => setError("") };
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel" aria-label={title}>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return message ? (
    <p className="error" role="alert">
      {message}
    </p>
  ) : null;
}

export function Severity({ level }: { level: string }) {
  return <span className={`badge badge-${level.toLowerCase()}`}>{level}</span>;
}

export function formatDate(value: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString();
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="muted">{children}</p>;
}
