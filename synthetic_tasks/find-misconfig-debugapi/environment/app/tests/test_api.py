from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_login_with_seeded_credentials():
    r = client.post("/login", json={"username": "admin", "password": "admin123"})
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ok"}
    assert "session" in r.cookies
