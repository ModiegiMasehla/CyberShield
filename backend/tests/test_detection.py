from app.services.detection import detect
def test_bruteforce_rule():
    assert any(x["type"]=="BRUTE_FORCE" for x in detect({"failed_login_attempts":10}))
def test_privilege_rule():
    assert any(x["type"]=="PRIVILEGE_ESCALATION" for x in detect({"privilege_changes":1}))
