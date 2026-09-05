from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_login_and_me():
    r = client.post("/login", json={"username": "alice", "password": "pw-alice"})
    assert r.status_code == 200, r.text
    me = client.get("/me", headers={"Authorization": f"Bearer {r.json()['token']}"})
    assert me.status_code == 200, me.text
    assert me.json() == {"sub": "alice"}


def test_bad_password_rejected():
    r = client.post("/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401
