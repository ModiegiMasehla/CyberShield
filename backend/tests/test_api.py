def test_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_root_health_endpoint(client):
    assert client.get("/health").json()["status"] == "ok"


def test_register_rejects_weak_password(client):
    r = client.post("/api/v1/auth/register", json={"email": "new@example.com", "password": "weak"})
    assert r.status_code == 400


def test_register_duplicate_email(client, fresh_user):
    email, password = fresh_user
    r = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 409


def test_security_headers_present(client):
    r = client.get("/api/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_password_tool_rejects_non_string(client):
    assert client.post("/api/v1/tools/password/analyze", json={"password": 123}).status_code == 422


def test_password_tool_ok(client):
    r = client.post("/api/v1/tools/password/analyze", json={"password": "password"})
    assert r.status_code == 200 and r.json()["score"] < 50


def test_dashboard_requires_auth(client):
    assert client.get("/api/v1/dashboard").status_code == 401


def test_dashboard_ok(client, user):
    r = client.get("/api/v1/dashboard", headers=user)
    assert r.status_code == 200
    assert 0 <= r.json()["security_score"] <= 100


def test_dns_rejects_invalid_domain(client, user):
    assert client.get("/api/v1/tools/dns/not_a_domain", headers=user).status_code == 400
