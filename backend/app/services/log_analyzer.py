import re
from collections import Counter

IP = r"\d{1,3}(?:\.\d{1,3}){3}"
FAIL = r"(?:failed|failure|invalid password|authentication failure)"
FAILED = re.compile(rf"{FAIL}.*?(?P<ip>{IP})|(?P<ip2>{IP}).*{FAIL}", re.I)
SENSITIVE = re.compile(r"/(?:admin|login|wp-admin|\.env|config)", re.I)
MAX_LINES = 10000
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_HIGH = 20
SENSITIVE_THRESHOLD = 10


def analyze_lines(lines):
    counts = Counter()
    sensitive = 0
    for line in lines[:MAX_LINES]:
        m = FAILED.search(line)
        if m:
            counts[m.group("ip") or m.group("ip2")] += 1
        if SENSITIVE.search(line):
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
