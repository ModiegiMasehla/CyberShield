from app.services.password_analyzer import analyze_password


def test_strong_password():
    assert analyze_password("Str0ng!UniquePassword")["score"] >= 75


def test_weak_common_password():
    result = analyze_password("password")
    assert result["score"] < 50
    assert result["issues"]
