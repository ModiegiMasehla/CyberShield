import pytest

from app.services.url_analyzer import analyze_url


def test_http_is_flagged():
    assert analyze_url("http://example.com/login")["risk"] in {"MEDIUM", "HIGH"}


def test_https_clean_url():
    assert analyze_url("https://example.com")["risk"] == "LOW"


@pytest.mark.parametrize("url", ["http://example.com:99999/", "http://[::1/", "not-a-url", "ftp://x.com/a"])
def test_malformed_urls_do_not_crash(url):
    assert analyze_url(url)["risk"] == "HIGH"


def test_documented_sample_urls_match_expected_results():
    import os

    from conftest import LAB

    expected = {
        "https://example.com": ("LOW", 0),
        "http://example.com/login": ("MEDIUM", 30),
        "http://192.168.1.5/login?redirect=http://evil.com%2Fx": ("HIGH", 70),
        "https://user@example.com/reset": ("MEDIUM", 40),
        "https://xn--exmple-cua.com/login": ("MEDIUM", 30),
        "ftp://files.example.com/data": ("HIGH", 90),
        "not-a-url": ("HIGH", 90),
    }
    listed = open(os.path.join(LAB, "sample-data", "urls.txt")).read().split()
    for url, (risk, score) in expected.items():
        assert url in listed
        r = analyze_url(url)
        assert (r["risk"], r["score"]) == (risk, score)
