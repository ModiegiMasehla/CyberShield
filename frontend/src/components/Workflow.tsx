import { type FormEvent, useCallback, useEffect, useState } from "react";
import { post, request } from "../api";
import type { Alert, AuditEntry, Incident, Vulnerability } from "../types";
import { Empty, ErrorNote, Panel, Severity, errorText, formatDate, useAction } from "./ui";

function useList<T>(path: string) {
  const [items, setItems] = useState<T[] | null>(null);
  const [error, setError] = useState("");
  const reload = useCallback(async (signal?: AbortSignal) => {
    try {
      setItems(await request<T[]>(path, { signal }));
      setError("");
    } catch (e) {
      if (!signal?.aborted) setError(errorText(e));
    }
  }, [path]);
  useEffect(() => {
    const controller = new AbortController();
    // eslint-disable-next-line react-hooks/set-state-in-effect -- initial fetch on mount
    void reload(controller.signal);
    return () => controller.abort();
  }, [reload]);
  return { items, error, reload };
}

const INCIDENT_STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATED", "RECOVERED", "CLOSED"];
const ALERT_STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];

function StatusSelect({ id, value, options, onChange, label }: {
  id: number; value: string; options: string[]; label: string; onChange: (status: string) => void;
}) {
  return (
    <select aria-label={`${label} ${id} status`} value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => <option key={o}>{o}</option>)}
    </select>
  );
}

export function Incidents() {
  const { items, error, reload } = useList<Incident>("/incidents");
  const create = useAction();
  const update = useAction();
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("MEDIUM");

  function submit(e: FormEvent) {
    e.preventDefault();
    void create.run(async () => {
      await post("/incidents", { title, description, severity });
      setTitle("");
      setDescription("");
      await reload();
    });
  }
  function changeStatus(id: number, status: string) {
    void update.run(async () => {
      await request(`/incidents/${id}`, { method: "PATCH", json: { status } });
      await reload();
    });
  }
  return (
    <div className="grid">
      <Panel title="Incidents">
        <ErrorNote message={error || update.error} />
        {items === null && !error && <Empty>Loading incidents…</Empty>}
        {items?.length === 0 && <Empty>No incidents recorded yet.</Empty>}
        {items?.map((i) => (
          <div className="row" key={i.id}>
            <span><b>#{i.id} {i.title}</b> <Severity level={i.severity} /></span>
            <StatusSelect id={i.id} label="Incident" value={i.status} options={INCIDENT_STATUSES} onChange={(s) => changeStatus(i.id, s)} />
          </div>
        ))}
      </Panel>
      <Panel title="Report an incident">
        <form onSubmit={submit}>
          <label htmlFor="inc-title">Title</label>
          <input id="inc-title" required maxLength={255} value={title} onChange={(e) => setTitle(e.target.value)} />
          <label htmlFor="inc-desc">Description</label>
          <textarea id="inc-desc" required maxLength={5000} rows={4} value={description} onChange={(e) => setDescription(e.target.value)} />
          <label htmlFor="inc-sev">Severity</label>
          <select id="inc-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => <option key={s}>{s}</option>)}
          </select>
          <ErrorNote message={create.error} />
          <button type="submit" disabled={create.busy}>{create.busy ? "Saving…" : "Create incident"}</button>
        </form>
      </Panel>
    </div>
  );
}

export function Alerts() {
  const { items, error, reload } = useList<Alert>("/alerts");
  const update = useAction();
  function changeStatus(id: number, status: string) {
    void update.run(async () => {
      await request(`/alerts/${id}`, { method: "PATCH", json: { status } });
      await reload();
    });
  }
  return (
    <Panel title="Alerts">
      <ErrorNote message={error || update.error} />
      {items === null && !error && <Empty>Loading alerts…</Empty>}
      {items?.length === 0 && <Empty>No alerts.</Empty>}
      {items?.map((a) => (
        <div className="row" key={a.id}>
          <span><Severity level={a.severity} /> <b>{a.type}</b> — {a.description} <small>({a.source}, {formatDate(a.created_at)})</small></span>
          <StatusSelect id={a.id} label="Alert" value={a.status} options={ALERT_STATUSES} onChange={(s) => changeStatus(a.id, s)} />
        </div>
      ))}
    </Panel>
  );
}

export function Vulnerabilities() {
  const { items, error } = useList<Vulnerability>("/vulnerabilities");
  return (
    <Panel title="Vulnerabilities">
      <ErrorNote message={error} />
      {items === null && !error && <Empty>Loading vulnerabilities…</Empty>}
      {items?.length === 0 && <Empty>No vulnerabilities recorded.</Empty>}
      {items?.map((v) => (
        <div className="row" key={v.id}>
          <span><Severity level={v.severity} /> <b>{v.title}</b>{v.cve_id ? ` (${v.cve_id})` : ""}<br /><small>{v.recommendation}</small></span>
          <span>{v.cvss ?? "—"}</span>
        </div>
      ))}
    </Panel>
  );
}

export function AuditLog() {
  const { items, error } = useList<AuditEntry>("/audit-logs?limit=100");
  return (
    <Panel title="Audit log (latest 100)">
      <ErrorNote message={error} />
      {items === null && !error && <Empty>Loading audit log…</Empty>}
      {items?.length === 0 && <Empty>No audit entries.</Empty>}
      <div className="table-wrap">
        {items && items.length > 0 && (
          <table>
            <thead><tr><th>When</th><th>Action</th><th>Resource</th><th>Result</th><th>IP</th></tr></thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}><td>{formatDate(r.at)}</td><td>{r.action}</td><td>{r.resource}</td><td>{r.result}</td><td>{r.ip ?? "—"}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
