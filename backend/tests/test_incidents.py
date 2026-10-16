def test_incident_lifecycle(client, analyst):
    r = client.post(
        "/api/v1/incidents",
        headers=analyst,
        json={"title": "Test", "description": "desc", "severity": "HIGH"},
    )
    assert r.status_code == 201
    iid = r.json()["id"]
    assert (
        client.patch(f"/api/v1/incidents/{iid}", headers=analyst, json={"status": "CONTAINED"}).status_code
        == 200
    )
    listed = client.get("/api/v1/incidents", headers=analyst).json()
    assert next(i for i in listed if i["id"] == iid)["status"] == "CONTAINED"


def test_incident_rejects_invalid_values(client, analyst):
    bad = {"title": "T", "description": "d", "severity": "SUPER"}
    assert client.post("/api/v1/incidents", headers=analyst, json=bad).status_code == 422
    ok = client.post(
        "/api/v1/incidents", headers=analyst, json={"title": "T", "description": "d", "severity": "LOW"}
    )
    iid = ok.json()["id"]
    assert (
        client.patch(f"/api/v1/incidents/{iid}", headers=analyst, json={"status": "BOGUS"}).status_code == 422
    )


def test_incident_assignee_must_exist(client, analyst):
    ok = client.post(
        "/api/v1/incidents", headers=analyst, json={"title": "T", "description": "d", "severity": "LOW"}
    )
    iid = ok.json()["id"]
    r = client.patch(f"/api/v1/incidents/{iid}", headers=analyst, json={"assigned_analyst_id": 99999})
    assert r.status_code == 400


def test_incident_not_found(client, analyst):
    assert (
        client.patch("/api/v1/incidents/99999", headers=analyst, json={"status": "OPEN"}).status_code == 404
    )


def test_alert_resolution_lowers_dashboard_counts(client, analyst, admin):
    before = client.get("/api/v1/dashboard", headers=analyst).json()["high_alerts"]
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    target = next(a for a in alerts if a["severity"] == "HIGH" and a["status"] == "NEW")
    assert (
        client.patch(
            f"/api/v1/alerts/{target['id']}", headers=analyst, json={"status": "FALSE_POSITIVE"}
        ).status_code
        == 200
    )
    assert client.get("/api/v1/dashboard", headers=analyst).json()["high_alerts"] == before - 1


def test_report_pdf(client, analyst):
    r = client.get("/api/v1/reports/security.pdf", headers=analyst)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
