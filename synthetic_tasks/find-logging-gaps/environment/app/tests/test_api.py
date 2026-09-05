from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_login_happy_path():
    r = client.post("/login", json={"username": "svc-ops", "password": "Ops!Pass42"})
    assert r.status_code == 200, r.text
    assert "token" in r.json()
