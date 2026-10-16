import pyotp
from conftest import auth, login


def test_login_success_and_me(client, fresh_user):
    email, password = fresh_user
    headers = auth(client, email, password)
    assert client.get("/api/v1/auth/me", headers=headers).json()["email"] == email


def test_login_wrong_password_and_unknown_user_same_response(client, fresh_user):
    email, _ = fresh_user
    a = login(client, email, "wrong-password")
    b = login(client, "nobody@example.com", "wrong-password")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_lockout_after_repeated_failures(client, fresh_user):
    email, password = fresh_user
    for _ in range(5):
        assert login(client, email, "bad").status_code == 401
    assert login(client, email, password).status_code == 423


def test_invalid_token_rejected(client):
    r = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.token"})
    assert r.status_code == 401


def test_password_change(client, fresh_user):
    email, password = fresh_user
    headers = auth(client, email, password)
    new = "An0ther!Str0ngPass"
    assert (
        client.post(
            "/api/v1/auth/password/change",
            headers=headers,
            json={"current_password": "x", "new_password": new},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/password/change",
            headers=headers,
            json={"current_password": password, "new_password": "weak"},
        ).status_code
        == 400
    )
    ok = client.post(
        "/api/v1/auth/password/change",
        headers=headers,
        json={"current_password": password, "new_password": new},
    )
    assert ok.status_code == 200
    assert login(client, email, password).status_code == 401
    assert login(client, email, new).status_code == 200


def test_mfa_flow_and_setup_cannot_be_replaced(client, fresh_user):
    email, password = fresh_user
    headers = auth(client, email, password)
    secret = client.post("/api/v1/auth/mfa/setup", headers=headers).json()["secret"]
    totp = pyotp.TOTP(secret)
    assert client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": "000000"}).status_code == 400
    assert (
        client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": totp.now()}).status_code == 200
    )
    assert client.post("/api/v1/auth/mfa/setup", headers=headers).status_code == 409
    assert login(client, email, password).status_code == 401
    assert login(client, email, password, otp=totp.now()).status_code == 200


def test_bad_otp_counts_toward_lockout(client, fresh_user):
    email, password = fresh_user
    headers = auth(client, email, password)
    secret = client.post("/api/v1/auth/mfa/setup", headers=headers).json()["secret"]
    client.post("/api/v1/auth/mfa/enable", headers=headers, json={"code": pyotp.TOTP(secret).now()})
    for _ in range(5):
        assert login(client, email, password, otp="000000").status_code == 401
    assert login(client, email, password, otp=pyotp.TOTP(secret).now()).status_code == 423


def test_failed_logins_are_audited(client, admin, fresh_user):
    email, _ = fresh_user
    login(client, email, "bad")
    rows = client.get("/api/v1/audit-logs", headers=admin).json()
    assert any(r["action"] == "LOGIN_FAILED" for r in rows)


def test_login_rate_limited(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 3)
    codes = [login(client, "nobody@example.com", "x").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert 429 in codes[3:]
