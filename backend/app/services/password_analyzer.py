import re

COMMON = {"password", "password123", "123456", "qwerty", "letmein", "admin", "welcome"}
# Words that make a password guessable even when decorated with digits and symbols.
COMMON_WORDS = (
    "password", "passw0rd", "qwerty", "letmein", "welcome", "admin", "login", "iloveyou", "monkey",
    "dragon", "football", "baseball", "master", "summer", "winter", "spring", "autumn", "sunshine",
    "princess", "shadow", "superman", "trustno1", "cybershield",
)  # fmt: skip
LEET = str.maketrans(
    {"@": "a", "4": "a", "0": "o", "1": "l", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"}
)
KEYBOARD_RUNS = ("qwert", "werty", "asdfg", "sdfgh", "zxcvb", "qazws", "1qaz2")
YEAR = re.compile(r"(?:19|20)\d{2}")
LONG_PASSWORD_CAP = 16  # patterns only cap the score for passwords shorter than this


def _has_sequence(text: str, run: int = 4) -> bool:
    """True for ascending or descending runs of letters/digits such as 1234, abcd or 9876."""
    streak = 1
    direction = 0
    for prev, cur in zip(text, text[1:], strict=False):
        step = ord(cur) - ord(prev)
        if step in (1, -1) and prev.isalnum() and cur.isalnum() and (direction in (0, step)):
            streak = streak + 1 if direction == step else 2
            direction = step
            if streak >= run:
                return True
        else:
            streak, direction = 1, 0
    return False


def analyze_password(password: str) -> dict:
    # Password is used transiently and never persisted/logged.
    score = 0
    issues = []
    pattern_found = False
    if len(password) >= 12:
        score += 25
    else:
        issues.append("Password is shorter than 12 characters.")
    if len(password) >= 16:
        score += 10
    if len(password) >= 20:
        score += 10
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
    normalised = lower.translate(LEET)
    if lower in COMMON:
        score = max(0, score - 30)
        issues.append("Common password pattern detected.")
        pattern_found = True
    elif any(word in lower or word in normalised for word in COMMON_WORDS):
        score = max(0, score - 20)
        issues.append("Contains a common word or substitution (for example 'p@ssw0rd').")
        pattern_found = True
    if re.search(r"(.)\1\1", password):
        score = max(0, score - 10)
        issues.append("Repeated-character pattern detected.")
        pattern_found = True
        if re.search(r"(.)\1{3,}", password):
            score = max(0, score - 15)  # runs of 4+ identical characters add almost no entropy
    if _has_sequence(lower) or any(run in lower for run in KEYBOARD_RUNS):
        score = max(0, score - 15)
        issues.append("Sequential or keyboard-run pattern detected.")
        pattern_found = True
    if YEAR.search(password):
        score = max(0, score - 10)
        issues.append("Contains a year, which attackers try first.")
        pattern_found = True
    if pattern_found and len(password) < LONG_PASSWORD_CAP:
        score = min(score, 60)  # a short password built on a predictable pattern is never "Strong"
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
