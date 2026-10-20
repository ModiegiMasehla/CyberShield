import ipaddress
import re
from urllib.parse import parse_qs, urlparse

NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*", re.I)


def analyze_url(url: str):
    findings, score = [], 0
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        return {"risk": "HIGH", "findings": ["Invalid HTTP(S) URL."], "score": 90}
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"risk": "HIGH", "findings": ["Invalid HTTP(S) URL."], "score": 90}
    if parsed.scheme == "http":
        score += 30
        findings.append("HTTP is unencrypted; prefer HTTPS.")
    try:
        ipaddress.ip_address(parsed.hostname)
        score += 20
        findings.append("URL uses an IP address instead of a domain.")
    except ValueError:
        if NUMERIC_HOST.fullmatch(parsed.hostname):
            score += 25
            findings.append("Obfuscated numeric host (decimal/hex/octal IP encoding).")
    if parsed.hostname.count(".") >= 4:
        score += 10
        findings.append("Excessive subdomain depth may warrant review.")
    if "%" in parsed.path or "%" in parsed.query:
        score += 10
        findings.append("Encoded URL components are present.")
    q = parse_qs(parsed.query)
    if any(k.lower() in {"redirect", "url", "next", "return", "redirect_uri"} for k in q):
        score += 10
        findings.append("Redirect-like parameter detected; inspect destination handling.")
    if parsed.username is not None:
        score += 40
        findings.append("URL embeds credentials ('user@host'); the real destination is the part after '@'.")
    if any(label.startswith("xn--") for label in parsed.hostname.split(".")):
        score += 30
        findings.append("Punycode (xn--) hostname may impersonate another domain.")
    risk = "LOW" if score < 25 else "MEDIUM" if score < 55 else "HIGH"
    if not findings:
        findings.append("No obvious heuristic indicators found.")
    return {
        "risk": risk,
        "score": min(100, score),
        "findings": findings,
        "domain": parsed.hostname,
        "port": port,
    }
