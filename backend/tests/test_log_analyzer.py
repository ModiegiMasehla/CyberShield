import glob
import os

import pytest
from conftest import LAB

from app.services.log_analyzer import analyze_lines

EXPECTED = {
    "auth.log": ({"192.168.56.20": 7}, 0, [("BRUTE_FORCE", "MEDIUM")]),
    "auth_bruteforce_high.log": ({"192.168.56.77": 25}, 0, [("BRUTE_FORCE", "HIGH")]),
    "auth_multiple_sources.log": (
        {"192.168.56.20": 6, "192.168.56.99": 21},
        0,
        [("BRUTE_FORCE", "MEDIUM"), ("BRUTE_FORCE", "HIGH")],
    ),
    "auth_normal.log": ({"192.168.56.31": 4}, 0, []),
    "web_access_probing.log": ({}, 12, [("SUSPICIOUS_ACTIVITY", "MEDIUM")]),
    "web_access_normal.log": ({}, 0, []),
}


def test_failed_login_detection():
    lines = ["192.168.1.10 failed password" for _ in range(7)]
    r = analyze_lines(lines)
    assert r["alerts"][0]["type"] == "BRUTE_FORCE"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample_logs_match_documented_results(name):
    path = os.path.join(LAB, "sample-logs", name)
    with open(path) as fh:
        r = analyze_lines(fh.read().splitlines())
    fails, sensitive, alerts = EXPECTED[name]
    assert r["failed_logins_by_ip"] == fails
    assert r["sensitive_path_requests"] == sensitive
    assert [(a["type"], a["severity"]) for a in r["alerts"]] == alerts


def test_all_sample_logs_are_covered():
    names = {os.path.basename(p) for p in glob.glob(os.path.join(LAB, "sample-logs", "*.log"))}
    assert names == set(EXPECTED)


def test_upload_endpoint_and_save_alerts(client, analyst):
    with open(os.path.join(LAB, "sample-logs", "auth_bruteforce_high.log"), "rb") as fh:
        r = client.post(
            "/api/v1/tools/logs/analyze?save_alerts=true",
            headers=analyst,
            files={"file": ("auth.log", fh.read())},
        )
    assert r.status_code == 200 and r.json()["alerts"][0]["severity"] == "HIGH"
    assert any(a["source"] == "192.168.56.77" for a in client.get("/api/v1/alerts", headers=analyst).json())


def test_upload_too_large(client, analyst):
    r = client.post(
        "/api/v1/tools/logs/analyze", headers=analyst, files={"file": ("big.log", b"x" * 2_000_100)}
    )
    assert r.status_code == 413
