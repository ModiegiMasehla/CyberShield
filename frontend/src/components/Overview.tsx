import { useEffect, useState } from "react";
import { download, request } from "../api";
import type { Dashboard, Role } from "../types";
import { ErrorNote, Panel, errorText, useAction } from "./ui";

export function Overview({ role }: { role: Role }) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const report = useAction();

  useEffect(() => {
    const controller = new AbortController();
    request<Dashboard>("/dashboard", { signal: controller.signal })
      .then(setData)
      .catch((e) => !controller.signal.aborted && setError(errorText(e)));
    return () => controller.abort();
  }, []);

  function downloadReport() {
    void report.run(async () => {
      const blob = await download("/reports/security.pdf");
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "cybershield-security-assessment.pdf";
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  const cards: [string, string | number][] = data
    ? [
        ["Security Score", `${data.security_score}/100`],
        ["Critical", data.critical_alerts],
        ["High", data.high_alerts],
        ["Medium", data.medium_alerts],
        ["Open Incidents", data.open_incidents],
        ["Vulnerabilities", data.vulnerabilities],
      ]
    : [];
  return (
    <>
      <ErrorNote message={error} />
      {!data && !error && <p className="muted" role="status">Loading dashboard…</p>}
      <div className="cards">
        {cards.map(([label, value]) => (
          <div className="card" key={label}>
            <b>{label}</b>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
      <div className="grid">
        <Panel title="Learning Centre">
          <p><b>CIA Triad:</b> confidentiality, integrity and availability.</p>
          <p><b>Defense in depth:</b> use multiple independent controls.</p>
          <p><b>Least privilege:</b> give each account only the access it needs.</p>
        </Panel>
        {role !== "USER" && (
          <Panel title="Security report">
            <p>Download a PDF summary of the current security posture.</p>
            <ErrorNote message={report.error} />
            <button onClick={downloadReport} disabled={report.busy}>
              {report.busy ? "Preparing…" : "Download security report"}
            </button>
          </Panel>
        )}
      </div>
    </>
  );
}
