import os
import tempfile
import uuid

_tmp = tempfile.mkdtemp(prefix="cybershield-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-hs256"
os.environ["ENVIRONMENT"] = "development"
os.environ["RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["LOGIN_RATE_LIMIT_PER_MINUTE"] = "100000"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.middleware import limiter  # noqa: E402

LAB = os.path.join(os.path.dirname(__file__), "..", "..", "security-lab")


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _reset_limiter():
    limiter.reset()


def login(client, email, password, otp=None):
    body = {"email": email, "password": password}
    if otp:
        body["otp"] = otp
    return client.post("/api/v1/auth/login", json=body)


def auth(client, email, password):
    r = login(client, email, password)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def admin(client):
    return auth(client, "admin@cybershield.local", "CyberShield!Admin123")


@pytest.fixture()
def analyst(client):
    return auth(client, "analyst@cybershield.local", "CyberShield!Analyst123")


@pytest.fixture()
def user(client):
    return auth(client, "user@cybershield.local", "CyberShield!User123")


@pytest.fixture()
def fresh_user(client):
    email = f"{uuid.uuid4().hex[:10]}@example.com"
    password = "Str0ng!Passw0rd#1"
    assert (
        client.post("/api/v1/auth/register", json={"email": email, "password": password}).status_code == 201
    )
    return email, password
