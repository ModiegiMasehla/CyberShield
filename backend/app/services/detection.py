RULES = [
    {"name":"Brute force","condition":"failed_login_attempts >= 5","type":"BRUTE_FORCE","severity":"HIGH"},
    {"name":"Sensitive endpoint burst","condition":"sensitive_requests >= 10","type":"SUSPICIOUS_ACTIVITY","severity":"MEDIUM"},
    {"name":"Privilege escalation","condition":"privilege_changes >= 1","type":"PRIVILEGE_ESCALATION","severity":"HIGH"},
]
def detect(metrics):
    alerts=[]
    if metrics.get("failed_login_attempts",0)>=5:
        alerts.append({"type":"BRUTE_FORCE","severity":"HIGH"})
    if metrics.get("sensitive_requests",0)>=10:
        alerts.append({"type":"SUSPICIOUS_ACTIVITY","severity":"MEDIUM"})
    if metrics.get("privilege_changes",0)>=1:
        alerts.append({"type":"PRIVILEGE_ESCALATION","severity":"HIGH"})
    return alerts
