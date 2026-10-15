from app.services.url_analyzer import analyze_url
def test_http_is_flagged():
    r=analyze_url("http://example.com/login")
    assert r["risk"] in {"MEDIUM","HIGH"}
def test_https_clean_url():
    r=analyze_url("https://example.com")
    assert r["risk"]=="LOW"
