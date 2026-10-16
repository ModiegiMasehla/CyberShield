import re

COMMON = {"password", "password123", "123456", "qwerty", "letmein", "admin", "welcome"}


def analyze_password(password: str) -> dict:
    # Password is used transiently and never persisted/logged.
    score = 0
    issues = []
    if len(password) >= 12:
        score += 25
    else:
        issues.append("Password is shorter than 12 characters.")
    if re.search(r"[A-Z]", password):
        score += 15
    else:
        issues.append("Add uppercase letters.")
    if re.search(r"[a-z]", password):
        score += 15
    else:
        issues.append("Add lowercase letters.")
    if re.search(r"\d", password):
        score += 15
    else:
        issues.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    else:
        issues.append("Add symbols.")
    lower = password.lower()
    if lower in COMMON:
        score = max(0, score - 30)
        issues.append("Common password pattern detected.")
    if re.search(r"(.)\1\1", password):
        score = max(0, score - 10)
        issues.append("Repeated-character pattern detected.")
    if any(str(i) in lower for i in range(123, 456, 111)):
        score = max(0, score - 5)
        issues.append("Sequential-number pattern detected.")
    score = min(100, max(0, score))
    strength = "Very Weak" if score < 25 else "Weak" if score < 50 else "Moderate" if score < 75 else "Strong"
    return {
        "score": score,
        "strength": strength,
        "issues": issues,
        "recommendations": [
            "Do not reuse passwords.",
            "Enable MFA.",
            "Use a unique password manager-generated secret.",
        ],
    }
