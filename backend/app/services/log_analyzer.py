import ipaddress
import re
from collections import Counter

from .detection import rule_threshold

IP_RE = re.compile(r"(?<!\d)\d{1,3}(?:\.\d{1,3}){3}(?!\d)")
FAIL_RE = re.compile(r"failed|failure|invalid password|authentication failure", re.I)
SENSITIVE = re.compile(r"/(?:admin|login|wp-admin|\.env|config)", re.I)
MAX_LINES = 10000
MAX_LINE_CHARS = 4096  # longer lines are truncated: keeps work per line bounded
BRUTE_FORCE_THRESHOLD = rule_threshold("BRUTE_FORCE")
BRUTE_FORCE_HIGH = 20
SENSITIVE_THRESHOLD = rule_threshold("SUSPICIOUS_ACTIVITY")


def _valid_ips(line: str) -> list[tuple[int, int, str]]:
    found = []
    for m in IP_RE.finditer(line):
        try:
            ipaddress.IPv4Address(m.group())
        except ValueError:
            continue  # e.g. 999.1.1.1 or a version string
        found.append((m.start(), m.end(), m.group()))
    return found


def failed_login_source(line: str) -> str | None:
    """Return the IPv4 address blamed for a failed login on this line, or None.

    Single pass over keyword and address matches (linear time). When several candidates exist, the one that
    starts first wins: an address followed later by a failure keyword, or a keyword followed by an address.
    """
    line = line[:MAX_LINE_CHARS]
    fails = list(FAIL_RE.finditer(line))
    if not fails:
        return None
    ips = _valid_ips(line)
    if not ips:
        return None
    candidates = []
    before = next((ip for ip in ips if ip[1] <= fails[-1].start()), None)  # address ... keyword
    if before:
        candidates.append((before[0], before[2]))
    for f in fails:  # keyword ... address
        after = next((ip for ip in ips if ip[0] >= f.end()), None)
        if after:
            candidates.append((f.start(), after[2]))
            break
    return min(candidates)[1] if candidates else None


def analyze_lines(lines):
    counts = Counter()
    sensitive = 0
    for line in lines[:MAX_LINES]:
        source = failed_login_source(line)
        if source:
            counts[source] += 1
        if SENSITIVE.search(line[:MAX_LINE_CHARS]):
            sensitive += 1
    alerts = []
    for ip, n in counts.items():
        if n >= BRUTE_FORCE_THRESHOLD:
            alerts.append(
                {
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH" if n >= BRUTE_FORCE_HIGH else "MEDIUM",
                    "source": ip,
                    "description": f"{n} failed authentication attempts detected.",
                    "evidence": f"threshold={BRUTE_FORCE_THRESHOLD}; count={n}",
                }
            )
    if sensitive >= SENSITIVE_THRESHOLD:
        alerts.append(
            {
                "type": "SUSPICIOUS_ACTIVITY",
                "severity": "MEDIUM",
                "source": "web-log",
                "description": f"{sensitive} sensitive-path requests detected.",
                "evidence": f"count={sensitive}",
            }
        )
    return {
        "failed_logins_by_ip": dict(counts),
        "sensitive_path_requests": sensitive,
        "lines_analyzed": min(len(lines), MAX_LINES),
        "truncated": len(lines) > MAX_LINES,
        "alerts": alerts,
    }
