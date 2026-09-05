import requests

BASE = "http://127.0.0.1:8000"


def test_healthz():
    assert requests.get(f"{BASE}/healthz").status_code == 200


def test_login_ok_sets_cookie():
    r = requests.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.cookies.get("session")
