"""Regression tests for defects found during the audit.

Each test was written against the original code and failed there; the fix is what makes it pass.
"""

import asyncio
import ipaddress
import socket
import threading
import time
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from conftest import auth, login
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import SessionLocal
from app.models import AuditLog, Incident, User

STRONG = "Str0ng!Passw0rd#1"


def _user_row(email):
    with SessionLocal() as db:
        return db.scalar(select(User).where(User.email == email))


def _update_user(email, **fields):
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.email == email))
        for k, v in fields.items():
            setattr(u, k, v)
        db.commit()


def _audit_actions():
    with SessionLocal() as db:
        return {a for a in db.scalars(select(AuditLog.action))}


# --------------------------------------------------------------------------- auth


def test_register_race_returns_409_not_500(client, fresh_user, monkeypatch):
    """Two concurrent registrations for one email used to surface an IntegrityError (HTTP 500)."""
    email, password = fresh_user
    real_scalar = Session.scalar

    def blind_scalar(self, statement, *a, **kw):
        if "users.email" in str(statement):
            return None  # simulate the competing request committing after our existence check
        return real_scalar(self, statement, *a, **kw)

    monkeypatch.setattr(Session, "scalar", blind_scalar)
    r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 409


def test_lockout_counter_resets_after_lock_expires(client, fresh_user):
    """After the lock expires, one typo must not immediately re-lock the account."""
    email, password = fresh_user
    for _ in range(5):
        assert login(client, email, "bad").status_code == 401
    assert login(client, email, password).status_code == 423
    _update_user(email, locked_until=datetime.now(UTC) - timedelta(minutes=1))
    assert login(client, email, "typo").status_code == 401
    assert login(client, email, password).status_code == 200


def test_token_is_revoked_by_password_change(client, fresh_user):
    email, password = fresh_user
    old = auth(client, email, password)
    new_password = "An0ther!Str0ngPass"
    r = client.post(
        "/api/v1/auth/password/change",
        headers=old,
        json={"current_password": password, "new_password": new_password},
    )
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me", headers=old).status_code == 401
    assert client.get("/api/v1/auth/me", headers=auth(client, email, new_password)).status_code == 200


def test_totp_code_cannot_be_replayed(client, fresh_user):
    email, password = fresh_user
    headers = auth(client, email, password)
    secret = client.post("/api/v1/auth/mfa/setup", headers=headers).json()["secret"]
    totp = pyotp.TOTP(secret)
    assert (
        client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": totp.now()}).status_code == 200
    )
    code = totp.at(time.time() + 30)  # next step: valid inside the verification window
    assert login(client, email, password, otp=code).status_code == 200
    assert login(client, email, password, otp=code).status_code == 401


def test_failed_password_change_counts_toward_lockout(client, fresh_user):
    """A stolen access token must not allow unlimited guessing of the current password."""
    email, password = fresh_user
    headers = auth(client, email, password)
    for _ in range(5):
        r = client.post(
            "/api/v1/auth/password/change",
            headers=headers,
            json={"current_password": "wrong", "new_password": "An0ther!Str0ngPass"},
        )
        assert r.status_code == 401
    assert login(client, email, password).status_code == 423


def test_concurrent_failed_logins_are_all_counted(client, fresh_user):
    """Stress test: the failure counter is incremented atomically in SQL (no lost updates)."""
    email, _ = fresh_user
    barrier = threading.Barrier(6)

    def attempt():
        barrier.wait()
        login(client, email, "bad")

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert _user_row(email).failed_logins >= 5


# ----------------------------------------------------------------- update semantics


def _make_incident(client, analyst):
    r = client.post(
        "/api/v1/incidents", headers=analyst, json={"title": "T", "description": "d", "severity": "LOW"}
    )
    return r.json()["id"]


def test_incident_assignee_can_be_cleared(client, analyst):
    iid = _make_incident(client, analyst)
    me = client.get("/api/v1/auth/me", headers=analyst).json()["id"]
    assert (
        client.patch(
            f"/api/v1/incidents/{iid}", headers=analyst, json={"assigned_analyst_id": me}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            f"/api/v1/incidents/{iid}", headers=analyst, json={"assigned_analyst_id": None}
        ).status_code
        == 200
    )
    with SessionLocal() as db:
        assert db.get(Incident, iid).assigned_analyst_id is None


def test_explicit_null_status_is_rejected(client, analyst):
    iid = _make_incident(client, analyst)
    assert client.patch(f"/api/v1/incidents/{iid}", headers=analyst, json={"status": None}).status_code == 422


def test_incident_list_exposes_fields_the_ui_needs(client, analyst):
    iid = _make_incident(client, analyst)
    row = next(i for i in client.get("/api/v1/incidents", headers=analyst).json() if i["id"] == iid)
    assert {"description", "resolution", "assigned_analyst_id", "created_at"} <= set(row)


# ------------------------------------------------------------------------- config


def test_unknown_environment_name_is_rejected():
    """ENVIRONMENT=prod used to silently behave like development (demo admin seeded, weak secret OK)."""
    with pytest.raises(ValidationError):
        Settings(environment="prod")


def test_staging_requires_strong_secret_and_does_not_seed():
    with pytest.raises(ValidationError):
        Settings(environment="staging", secret_key="short")
    assert Settings(environment="staging", secret_key="x" * 40).should_seed is False


def test_environment_is_normalised():
    assert Settings(environment=" Production ", secret_key="x" * 40).is_production


def test_wildcard_cors_rejected_outside_development():
    with pytest.raises(ValidationError):
        Settings(environment="production", secret_key="x" * 40, cors_origins="*")


# --------------------------------------------------------------- log analyzer / DoS


def test_log_analyzer_is_linear_on_long_lines():
    from app.services.log_analyzer import analyze_lines

    start = time.perf_counter()
    analyze_lines(["1.1.1.1 " * 5000])
    assert time.perf_counter() - start < 1.0


def test_log_analyzer_ignores_invalid_ip_addresses():
    from app.services.log_analyzer import analyze_lines

    result = analyze_lines(["failed login from 999.999.999.999"] * 10)
    assert result["failed_logins_by_ip"] == {} and result["alerts"] == []


def test_log_upload_is_audited(client, analyst, admin):
    r = client.post(
        "/api/v1/tools/logs/analyze", headers=analyst, files={"file": ("a.log", b"192.168.1.1 failed\n")}
    )
    assert r.status_code == 200
    assert "LOG_ANALYZED" in _audit_actions()


# ---------------------------------------------------------------- password / URL


@pytest.mark.parametrize(
    "pw", ["Qwerty123456!", "Password123!", "P@ssw0rd1234", "Summer2024!!", "Abcdefgh1234!"]
)
def test_predictable_passwords_are_not_rated_strong(pw):
    from app.services.password_analyzer import analyze_password

    assert analyze_password(pw)["strength"] != "Strong"


def test_long_passphrase_is_rated_strong():
    from app.services.password_analyzer import analyze_password

    assert analyze_password("correct-horse-battery-staple-92!")["strength"] == "Strong"


def test_at_sign_in_path_is_not_deceptive():
    from app.services.url_analyzer import analyze_url

    for url in ("https://medium.com/@someuser/post", "https://example.com/search?email=a@b.com"):
        r = analyze_url(url)
        assert r["risk"] == "LOW" and r["score"] == 0, url


def test_userinfo_and_punycode_hosts_are_not_low_risk():
    from app.services.url_analyzer import analyze_url

    assert analyze_url("https://google.com@evil.example/login")["risk"] != "LOW"
    assert analyze_url("https://xn--exmple-cua.com/login")["risk"] != "LOW"


def test_obfuscated_numeric_host_is_flagged():
    from app.services.url_analyzer import analyze_url

    r = analyze_url("http://2130706433/admin")
    assert any("numeric" in f.lower() for f in r["findings"])


# ------------------------------------------------------------------- SSRF / web


@pytest.mark.parametrize(
    "ip", ["100.100.100.200", "fd00:ec2::254", "168.63.129.16", "::ffff:169.254.169.254"]
)
def test_cloud_metadata_addresses_blocked(ip):
    from app.services.web_checker import _is_blocked

    assert _is_blocked(ipaddress.ip_address(ip))


def _serve_once(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def run():
        srv.settimeout(10)
        try:
            while True:
                conn, _ = srv.accept()
                handler(conn)
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_dns_rebinding_cannot_swap_the_validated_address(monkeypatch):
    """The address that passed validation must be the one connected to (no second DNS lookup)."""
    from app.services.web_checker import check_headers

    def handler(conn):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Content-Type-Options: nosniff\r\n\r\nok")
        conn.close()

    srv, port = _serve_once(handler)
    calls = []
    real = socket.getaddrinfo

    def rebinding(host, *a, **kw):
        if host == "rebind.test":
            calls.append(host)
            ip = "127.0.0.1" if len(calls) == 1 else "192.0.2.1"  # 2nd lookup: unroutable
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return real(host, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    try:
        result = asyncio.run(check_headers(f"http://rebind.test:{port}/"))
    finally:
        srv.close()
    assert result["status_code"] == 200
    assert result["url"].startswith("http://rebind.test")


def test_check_headers_does_not_wait_for_the_response_body():
    from app.services.web_checker import check_headers

    def handler(conn):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nServer: lab\r\n\r\nabc")
        time.sleep(8)  # body never completes
        conn.close()

    srv, port = _serve_once(handler)
    start = time.perf_counter()
    try:
        result = asyncio.run(check_headers(f"http://127.0.0.1:{port}/"))
    finally:
        srv.close()
    assert result["server"] == "lab" and time.perf_counter() - start < 3


def test_blocked_scan_attempt_is_audited(client, analyst):
    assert (
        client.post("/api/v1/tools/network/scan", headers=analyst, json={"target": "8.8.8.8"}).status_code
        == 400
    )
    assert "PORT_SCAN_BLOCKED" in _audit_actions()


# ----------------------------------------------------------- middleware / misc


def test_rate_limiter_forgets_idle_clients(monkeypatch):
    from app import middleware

    clock = [1000.0]
    monkeypatch.setattr(middleware.time, "monotonic", lambda: clock[0])
    limiter = middleware._SlidingWindow()
    for i in range(500):
        limiter.allow(f"ip{i}", 5)
    clock[0] += 61
    limiter.allow("fresh", 5)
    assert len(limiter.hits) < 10


def test_network_info_is_staff_only_and_populated(client, user, analyst):
    assert client.get("/api/v1/tools/network/info", headers=user).status_code == 403
    info = client.get("/api/v1/tools/network/info", headers=analyst).json()
    assert isinstance(info["interfaces"], list) and info["interfaces"]
    assert isinstance(info["dns"], list)


def test_request_id_header_is_set_and_sanitised(client):
    r = client.get("/api/v1/health")
    assert len(r.headers["x-request-id"]) >= 16
    ok = client.get("/api/v1/health", headers={"X-Request-ID": "trace-abc_123"})
    assert ok.headers["x-request-id"] == "trace-abc_123"
    bad = client.get("/api/v1/health", headers={"X-Request-ID": "bad id\twith spaces"})
    assert bad.headers["x-request-id"] != "bad id\twith spaces"


def test_duplicate_config_module_is_gone():
    with pytest.raises(ImportError):
        import app.api.config  # noqa: F401
