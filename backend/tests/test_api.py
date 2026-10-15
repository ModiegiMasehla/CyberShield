def test_health(client):
    r=client.get("/api/v1/health")
    assert r.status_code==200
    assert r.json()["status"]=="ok"

def test_register_rejects_weak_password(client):
    r=client.post("/api/v1/auth/register",json={"email":"new@example.com","password":"weak"})
    assert r.status_code==400
