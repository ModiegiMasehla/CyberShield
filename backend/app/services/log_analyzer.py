import re
from collections import Counter
FAILED = re.compile(r"(?:failed|failure|invalid password|authentication failure).*?(?P<ip>\d+\.\d+\.\d+\.\d+)|(?P<ip2>\d+\.\d+\.\d+\.\d+).*(?:failed|failure|invalid password|authentication failure)", re.I)

def analyze_lines(lines):
    counts=Counter()
    sensitive=0
    for line in lines[:10000]:
        m=FAILED.search(line)
        if m: counts[m.group("ip") or m.group("ip2")] += 1
        if re.search(r"/(?:admin|login|wp-admin|\.env|config)", line, re.I): sensitive += 1
    alerts=[]
    for ip,n in counts.items():
        if n >= 5:
            alerts.append({"type":"BRUTE_FORCE","severity":"HIGH" if n>=20 else "MEDIUM","source":ip,"description":f"{n} failed authentication attempts detected.","evidence":f"threshold=5; count={n}"})
    if sensitive >= 10:
        alerts.append({"type":"SUSPICIOUS_ACTIVITY","severity":"MEDIUM","source":"web-log","description":f"{sensitive} sensitive-path requests detected.","evidence":f"count={sensitive}"})
    return {"failed_logins_by_ip":dict(counts), "sensitive_path_requests":sensitive, "alerts":alerts}
