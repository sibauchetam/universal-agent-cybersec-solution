from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_register_login_me():
    r = client.post("/register", json={"email": "dave@example.com", "password": "DavePass1!"})
    # 400 tolerated on re-runs: dave persists in the SQLite file across runs
    assert r.status_code in (200, 201, 400), r.text
    r = client.post("/login", json={"email": "dave@example.com", "password": "DavePass1!"})
    assert r.status_code == 200, r.text
    me = client.get("/me", headers={"Authorization": f"Bearer {r.json()['token']}"})
    assert me.status_code == 200, me.text
    assert me.json() == {"email": "dave@example.com"}


def test_wrong_password_rejected():
    r = client.post("/login", json={"email": "dave@example.com", "password": "WrongPass!"})
    assert r.status_code == 401
