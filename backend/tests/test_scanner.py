import pytest

from app.services.network import validate_lab_target


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.168.56.10", "10.0.0.5"])
def test_lab_targets_accepted(ip):
    validate_lab_target(ip)


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "203.0.113.10", "localhost", "example.com", "169.254.169.254", "0.0.0.0", "224.0.0.1"],
)
def test_unsafe_targets_rejected(target):
    with pytest.raises(ValueError):
        validate_lab_target(target)


def test_scan_api_rejects_public_ip(client, analyst):
    r = client.post("/api/v1/tools/network/scan", headers=analyst, json={"target": "8.8.8.8"})
    assert r.status_code == 400


def test_scan_range_limit_is_exact(client, analyst):
    too_big = client.post(
        "/api/v1/tools/network/scan",
        headers=analyst,
        json={"target": "127.0.0.1", "start_port": 1, "end_port": 1025},
    )
    assert too_big.status_code == 400
    ok = client.post(
        "/api/v1/tools/network/scan",
        headers=analyst,
        json={"target": "127.0.0.1", "start_port": 1, "end_port": 1024},
    )
    assert ok.status_code == 200


def test_scan_rejects_reversed_range(client, analyst):
    r = client.post(
        "/api/v1/tools/network/scan",
        headers=analyst,
        json={"target": "127.0.0.1", "start_port": 20, "end_port": 10},
    )
    assert r.status_code == 400
