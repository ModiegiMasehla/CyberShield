import { useEffect, useMemo, useState } from "react";
import { LOGOUT_EVENT, loadSession, saveSession } from "./api";
import { Account } from "./components/Account";
import { Login } from "./components/Login";
import { Overview } from "./components/Overview";
import { StaffTools } from "./components/StaffTools";
import { Tools } from "./components/Tools";
import { Alerts, AuditLog, Incidents, Vulnerabilities } from "./components/Workflow";
import type { Role, Session } from "./types";

interface Tab { id: string; label: string; roles: Role[] }
const ALL: Role[] = ["ADMIN", "SECURITY_ANALYST", "USER"];
const STAFF: Role[] = ["ADMIN", "SECURITY_ANALYST"];
const TABS: Tab[] = [
  { id: "overview", label: "Overview", roles: ALL },
  { id: "tools", label: "Tools", roles: ALL },
  { id: "vulns", label: "Vulnerabilities", roles: ALL },
  { id: "incidents", label: "Incidents", roles: STAFF },
  { id: "alerts", label: "Alerts", roles: STAFF },
  { id: "lab", label: "Lab tools", roles: STAFF },
  { id: "audit", label: "Audit log", roles: ["ADMIN"] },
  { id: "account", label: "Account", roles: ALL },
];

export default function App() {
  const [session, setSession] = useState<Session | null>(loadSession);
  const [notice, setNotice] = useState("");
  const [tab, setTab] = useState("overview");

  useEffect(() => {
    const onLogout = () => {
      setSession(null);
      setNotice("Session expired. Please sign in again.");
    };
    window.addEventListener(LOGOUT_EVENT, onLogout);
    return () => window.removeEventListener(LOGOUT_EVENT, onLogout);
  }, []);

  const tabs = useMemo(() => TABS.filter((t) => session && t.roles.includes(session.role)), [session]);

  function logout(message = "") {
    saveSession(null);
    setSession(null);
    setNotice(message);
    setTab("overview");
  }

  if (!session) {
    return <Login notice={notice} onLogin={(s) => { setNotice(""); setSession(s); }} />;
  }
  return (
    <main>
      <header>
        <div>
          <h1>CYBERSHIELD</h1>
          <span>Security Operations Dashboard</span>
        </div>
        <button onClick={() => logout()}>Logout</button>
      </header>
      <p className="notice">Only scan systems you own or have explicit permission to test.</p>
      <nav aria-label="Sections">
        <div role="tablist">
          {tabs.map((t) => (
            <button key={t.id} role="tab" id={`tab-${t.id}`} aria-selected={tab === t.id} aria-controls="panel"
              className={tab === t.id ? "tab active" : "tab"} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      </nav>
      <div id="panel" role="tabpanel" aria-labelledby={`tab-${tab}`}>
        {tab === "overview" && <Overview role={session.role} />}
        {tab === "tools" && <Tools />}
        {tab === "vulns" && <Vulnerabilities />}
        {tab === "incidents" && <Incidents />}
        {tab === "alerts" && <Alerts />}
        {tab === "lab" && <StaffTools />}
        {tab === "audit" && <AuditLog />}
        {tab === "account" && <Account onPasswordChanged={() => logout("Password changed. Please sign in again.")} />}
      </div>
    </main>
  );
}
