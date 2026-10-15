from app.services.log_analyzer import analyze_lines
def test_failed_login_detection():
    lines=[f"192.168.1.10 failed password" for _ in range(7)]
    r=analyze_lines(lines)
    assert r["alerts"][0]["type"]=="BRUTE_FORCE"
