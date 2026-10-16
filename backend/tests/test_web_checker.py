import asyncio

import pytest

from app.services.web_checker import UnsafeTargetError, parse_cookie, validate_url


def test_cookie_flags_parsed_from_attributes_not_name():
    c = parse_cookie("secure_session=abc; Path=/")
    assert c["name"] == "secure_session"
    assert c["secure"] is False and c["httponly"] is False
    full = parse_cookie("sid=1; Secure; HttpOnly; SameSite=Lax")
    assert full["secure"] and full["httponly"] and full["samesite"]


@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/latest/meta-data", "ftp://example.com", "http://0.0.0.0/"]
)
def test_validate_url_blocks_unsafe(url):
    with pytest.raises(UnsafeTargetError):
        asyncio.run(validate_url(url))


def test_headers_endpoint_blocks_metadata(client, analyst):
    r = client.post("/api/v1/tools/web/headers", headers=analyst, json={"url": "http://169.254.169.254/"})
    assert r.status_code == 400
