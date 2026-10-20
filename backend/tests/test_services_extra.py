import os

import pytest
from conftest import LAB

from app.services.log_analyzer import failed_login_source
from app.services.network import parse_default_gateway, parse_nameservers
from app.services.password_analyzer import analyze_password

ROUTE = (
    "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    "eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
)


def test_default_gateway_parsed_from_route_table():
    assert parse_default_gateway(ROUTE) == "192.168.0.1"
    assert parse_default_gateway("Iface\tDestination\tGateway\tFlags\n") is None


def test_nameservers_parsed_and_comments_ignored():
    assert parse_nameservers("# c\nnameserver 1.1.1.1\nsearch lab\nnameserver 10.0.0.2\n") == [
        "1.1.1.1",
        "10.0.0.2",
    ]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("Failed password for root from 192.168.56.20 port 22 ssh2", "192.168.56.20"),
        ("192.168.1.10 failed password", "192.168.1.10"),
        ("authentication failure; rhost=10.0.0.9", "10.0.0.9"),
        ("Accepted password for root from 10.0.0.9", None),
        ("failed but no address here", None),
        ("failed from 300.1.1.1 then 10.1.1.1", "10.1.1.1"),
    ],
)
def test_failed_login_source(line, expected):
    assert failed_login_source(line) == expected


def test_over_long_lines_are_truncated_not_skipped():
    assert failed_login_source("failed from 10.2.2.2 " + "x" * 100_000) == "10.2.2.2"


def test_password_empty_and_unicode_do_not_crash():
    assert analyze_password("")["strength"] == "Very Weak"
    assert analyze_password("pässwörd-ünïcode-ünïcode-42!")["score"] > 0


def test_password_documented_lab_values():
    expected = {"aaaa1111AAAA": "Weak", "Summer2024!": "Weak", "k9#Lm2$vQx7!pTz4": "Strong"}
    for pw, strength in expected.items():
        assert analyze_password(pw)["strength"] == strength


def test_sample_password_file_does_not_crash():
    path = os.path.join(LAB, "sample-data", "passwords.txt")
    for line in open(path).read().splitlines():
        assert 0 <= analyze_password(line)["score"] <= 100
