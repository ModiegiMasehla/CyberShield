from app.services.detection import detect


def test_bruteforce_rule():
    assert any(x["type"] == "BRUTE_FORCE" for x in detect({"failed_login_attempts": 10}))


def test_privilege_rule():
    assert any(x["type"] == "PRIVILEGE_ESCALATION" for x in detect({"privilege_changes": 1}))


def test_sensitive_rule_and_no_false_positive():
    assert any(x["type"] == "SUSPICIOUS_ACTIVITY" for x in detect({"sensitive_requests": 10}))
    assert detect({"failed_login_attempts": 4, "sensitive_requests": 9}) == []
