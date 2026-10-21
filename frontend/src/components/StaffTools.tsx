import { useState } from "react";
import { post, request } from "../api";
import type { HeaderResult, LogResult, ScanResult } from "../types";
import { ErrorNote, Panel, Severity, useAction } from "./ui";

const MAX_LOG_BYTES = 2_000_000; // Match the API's decimal 2 MB limit.

function HeadersTool() {
  const [url, setUrl] = useState("http://127.0.0.1:8000");
  const [result, setResult] = useState<HeaderResult | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Panel title="Web Header Check">
      <label htmlFor="hdr-url">URL (authorized targets only)</label>
      <input id="hdr-url" value={url} onChange={(e) => { setUrl(e.target.value); setResult(null); }} />
      <button disabled={busy || !url.trim()} onClick={() => run(async () => setResult(await post("/tools/web/headers", { url })))}>
        {busy ? "Checking…" : "Check headers"}
      </button>
      <ErrorNote message={error} />
      {result && (
        <div role="status">
          <p>HTTP {result.status_code} · {result.https ? "HTTPS" : "HTTP (unencrypted)"} · server: {result.server}</p>
          <ul>{result.headers.map((h) => <li key={h.header}>{h.status === "PRESENT" ? "✔" : "✖"} {h.header} — {h.why}</li>)}</ul>
        </div>
      )}
    </Panel>
  );
}

function ScanTool() {
  const [target, setTarget] = useState("127.0.0.1");
  const [start, setStart] = useState(1);
  const [end, setEnd] = useState(1024);
  const [result, setResult] = useState<ScanResult | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Panel title="Port Scanner (lab ranges only)">
      <label htmlFor="scan-target">Target IP</label>
      <input id="scan-target" value={target} onChange={(e) => setTarget(e.target.value)} />
      <div className="row-inputs">
        <div>
          <label htmlFor="scan-start">From port</label>
          <input id="scan-start" type="number" min={1} max={65535} value={start} onChange={(e) => setStart(Number(e.target.value))} />
        </div>
        <div>
          <label htmlFor="scan-end">To port</label>
          <input id="scan-end" type="number" min={1} max={65535} value={end} onChange={(e) => setEnd(Number(e.target.value))} />
        </div>
      </div>
      <button disabled={busy || !target.trim()}
        onClick={() => run(async () => setResult(await post("/tools/network/scan", { target: target.trim(), start_port: start, end_port: end }, 90_000)))}>
        {busy ? "Scanning…" : "Scan"}
      </button>
      <ErrorNote message={error} />
      {result && (
        <div role="status">
          {result.ports.length === 0 ? <p className="muted">No open ports found on {result.target}.</p> : (
            <ul>{result.ports.map((p) => <li key={p.port}>{p.port} — {p.service}</li>)}</ul>
          )}
        </div>
      )}
    </Panel>
  );
}

function LogTool() {
  const [file, setFile] = useState<File | null>(null);
  const [save, setSave] = useState(false);
  const [result, setResult] = useState<LogResult | null>(null);
  const { busy, error, run } = useAction();
  const tooBig = !!file && file.size > MAX_LOG_BYTES;
  return (
    <Panel title="Log Analyzer">
      <label htmlFor="log-file">Log file (max 2 MB)</label>
      <input id="log-file" type="file" accept=".log,.txt,text/plain"
        onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null); }} />
      <label className="check"><input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} /> Save findings as alerts</label>
      {tooBig && <p className="error" role="alert">File is larger than 2 MB.</p>}
      <button disabled={busy || !file || tooBig}
        onClick={() => run(async () => {
          const form = new FormData();
          form.append("file", file as File);
          setResult(await request(`/tools/logs/analyze?save_alerts=${save}`, { method: "POST", form, timeoutMs: 60_000 }));
        })}>
        {busy ? "Analyzing…" : "Analyze"}
      </button>
      <ErrorNote message={error} />
      {result && (
        <div role="status">
          <p>{result.lines_analyzed} lines analyzed{result.truncated ? " (truncated)" : ""}; {result.sensitive_path_requests} sensitive-path requests.</p>
          {result.alerts.length === 0 ? <p className="muted">No alerts raised.</p> : (
            <ul>{result.alerts.map((a, i) => <li key={`${a.type}-${a.source}-${i}`}><Severity level={a.severity} /> {a.description} ({a.source})</li>)}</ul>
          )}
        </div>
      )}
    </Panel>
  );
}

export function StaffTools() {
  return (
    <div className="grid">
      <HeadersTool />
      <ScanTool />
      <LogTool />
    </div>
  );
}
