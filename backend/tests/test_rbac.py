def test_user_cannot_access_staff_endpoints(client, user):
    for path in ("/api/v1/alerts", "/api/v1/incidents", "/api/v1/reports/security.pdf", "/api/v1/audit-logs"):
        assert client.get(path, headers=user).status_code == 403, path


def test_analyst_cannot_read_audit_logs(client, analyst):
    assert client.get("/api/v1/audit-logs", headers=analyst).status_code == 403


def test_admin_reads_audit_logs(client, admin):
    assert client.get("/api/v1/audit-logs", headers=admin).status_code == 200


def test_user_cannot_scan(client, user):
    assert (
        client.post("/api/v1/tools/network/scan", headers=user, json={"target": "127.0.0.1"}).status_code
        == 403
    )


def test_vulnerabilities_listed(client, user):
    assert len(client.get("/api/v1/vulnerabilities", headers=user).json()) >= 2
