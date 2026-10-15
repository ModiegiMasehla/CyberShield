import os
os.environ["DATABASE_URL"]="sqlite:///./test.db"
os.environ["SECRET_KEY"]="test-secret"
import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture()
def client():
    with TestClient(app) as c: yield c
