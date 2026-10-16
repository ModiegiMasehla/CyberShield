RULES = [
    {
        "name": "Brute force",
        "metric": "failed_login_attempts",
        "threshold": 5,
        "type": "BRUTE_FORCE",
        "severity": "HIGH",
    },
    {
        "name": "Sensitive endpoint burst",
        "metric": "sensitive_requests",
        "threshold": 10,
        "type": "SUSPICIOUS_ACTIVITY",
        "severity": "MEDIUM",
    },
    {
        "name": "Privilege escalation",
        "metric": "privilege_changes",
        "threshold": 1,
        "type": "PRIVILEGE_ESCALATION",
        "severity": "HIGH",
    },
]


def detect(metrics):
    """Evaluate every rule in RULES against a metrics dict; RULES is the single source of truth."""
    alerts = []
    for rule in RULES:
        value = metrics.get(rule["metric"], 0)
        if value >= rule["threshold"]:
            alerts.append(
                {
                    "type": rule["type"],
                    "severity": rule["severity"],
                    "rule": rule["name"],
                    "description": (
                        f"{rule['name']}: {rule['metric']}={value} (threshold {rule['threshold']})."
                    ),
                }
            )
    return alerts
