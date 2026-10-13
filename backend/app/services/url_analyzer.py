from urllib.parse import urlparse, parse_qs
import ipaddress, re

def analyze_url(url: str):
    parsed = urlparse(url)
    findings, score = [], 0
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"risk":"HIGH", "findings":["Invalid HTTP(S) URL."], "score":90}
    if parsed.scheme == "http":
        score += 30; findings.append("HTTP is unencrypted; prefer HTTPS.")
    try:
        ipaddress.ip_address(parsed.hostname)
        score += 20; findings.append("URL uses an IP address instead of a domain.")
    except ValueError:
        pass
    if parsed.hostname.count(".") >= 4:
        score += 10; findings.append("Excessive subdomain depth may warrant review.")
    if "%" in parsed.path or "%" in parsed.query:
        score += 10; findings.append("Encoded URL components are present.")
    q = parse_qs(parsed.query)
    if any(k.lower() in {"redirect","url","next","return","redirect_uri"} for k in q):
        score += 10; findings.append("Redirect-like parameter detected; inspect destination handling.")
    if re.search(r"@|xn--", url, re.I):
        score += 15; findings.append("Potentially deceptive URL syntax detected.")
    risk = "LOW" if score < 25 else "MEDIUM" if score < 55 else "HIGH"
    if not findings: findings.append("No obvious heuristic indicators found.")
    return {"risk":risk, "score":min(100, score), "findings":findings, "domain":parsed.hostname, "port":parsed.port}
