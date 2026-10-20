export type Role = "ADMIN" | "SECURITY_ANALYST" | "USER";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Session { token: string; role: Role }
export interface Me { id: number; email: string; role: Role; mfa_enabled: boolean }
export interface Dashboard {
  security_score: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  open_incidents: number;
  vulnerabilities: number;
}
export interface PasswordResult { score: number; strength: string; issues: string[]; recommendations: string[] }
export interface UrlResult { risk: string; score: number; findings: string[] }
export type DnsResult = Record<string, string[]>;
export interface HeaderResult {
  url: string;
  status_code: number;
  https: boolean;
  server: string;
  headers: { header: string; status: "PRESENT" | "MISSING"; why: string }[];
  cookies: { name: string; secure: boolean; httponly: boolean; samesite: boolean }[];
}
export interface ScanResult { target: string; ports: { port: number; state: string; service: string }[] }
export interface LogAlert { type: string; severity: Severity; source: string; description: string; evidence: string }
export interface LogResult {
  failed_logins_by_ip: Record<string, number>;
  sensitive_path_requests: number;
  lines_analyzed: number;
  truncated: boolean;
  alerts: LogAlert[];
}
export interface Incident {
  id: number;
  title: string;
  severity: Severity;
  category: string;
  status: string;
  asset: string;
  description: string;
  resolution: string | null;
  assigned_analyst_id: number | null;
  created_at: string | null;
}
export interface Alert {
  id: number;
  type: string;
  severity: Severity;
  status: string;
  source: string;
  description: string;
  evidence: string | null;
  assigned_analyst_id: number | null;
  created_at: string | null;
}
export interface Vulnerability {
  id: number;
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cve_id: string | null;
  cvss: number | null;
}
export interface AuditEntry {
  id: number;
  user_id: number | null;
  action: string;
  resource: string;
  result: string;
  ip: string | null;
  at: string | null;
}
export interface NetInfo {
  hostname: string;
  local_ip: string;
  interfaces: string[];
  dns: string[];
  default_gateway: string;
  os: string;
}
