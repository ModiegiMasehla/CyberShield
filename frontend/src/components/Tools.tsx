import { useState } from "react";
import { post, request } from "../api";
import type { DnsResult, PasswordResult, UrlResult } from "../types";
import { ErrorNote, Panel, Severity, useAction } from "./ui";

function PasswordTool() {
  const [value, setValue] = useState("");
  const [result, setResult] = useState<PasswordResult | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Panel title="Password Security Analyzer">
      <label htmlFor="pw-input">Password to test</label>
      <input id="pw-input" type="password" autoComplete="off" placeholder="Analyzed in memory only" value={value}
        onChange={(e) => { setValue(e.target.value); setResult(null); }} />
      <button disabled={busy || !value} onClick={() => run(async () => setResult(await post("/tools/password/analyze", { password: value })))}>
        Analyze
      </button>
      <ErrorNote message={error} />
      {result && (
        <div role="status">
          <p><b>{result.strength}</b> — {result.score}/100</p>
          <ul>{result.issues.map((i) => <li key={i}>{i}</li>)}</ul>
        </div>
      )}
    </Panel>
  );
}

function UrlTool() {
  const [url, setUrl] = useState("https://example.com");
  const [result, setResult] = useState<UrlResult | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Panel title="URL Security Analyzer">
      <label htmlFor="url-input">URL</label>
      <input id="url-input" value={url} onChange={(e) => { setUrl(e.target.value); setResult(null); }} />
      <button disabled={busy || !url.trim()} onClick={() => run(async () => setResult(await post("/tools/url/analyze", { url })))}>
        Analyze
      </button>
      <ErrorNote message={error} />
      {result && (
        <div role="status">
          <p><Severity level={result.risk} /> score {result.score}</p>
          {result.findings.length === 0 ? <p className="muted">No risk indicators found.</p> : (
            <ul>{result.findings.map((f) => <li key={f}>{f}</li>)}</ul>
          )}
        </div>
      )}
    </Panel>
  );
}

function DnsTool() {
  const [domain, setDomain] = useState("example.com");
  const [result, setResult] = useState<DnsResult | null>(null);
  const { busy, error, run } = useAction();
  return (
    <Panel title="DNS Lookup">
      <label htmlFor="dns-input">Domain</label>
      <input id="dns-input" value={domain} onChange={(e) => { setDomain(e.target.value); setResult(null); }} />
      <button disabled={busy || !domain.trim()}
        onClick={() => run(async () => setResult(await request(`/tools/dns/${encodeURIComponent(domain.trim())}`)))}>
        {busy ? "Looking up…" : "Look up"}
      </button>
      <ErrorNote message={error} />
      {result && (
        <dl role="status">
          {Object.entries(result).map(([type, values]) => (
            <div key={type}>
              <dt>{type}</dt>
              <dd>{values.length ? values.join(", ") : "none"}</dd>
            </div>
          ))}
        </dl>
      )}
    </Panel>
  );
}

export function Tools() {
  return (
    <div className="grid">
      <PasswordTool />
      <UrlTool />
      <DnsTool />
    </div>
  );
}
