import requests

BASE = "http://127.0.0.1:8000"


def test_healthz():
    assert requests.get(f"{BASE}/healthz").status_code == 200


def test_transfer_happy_path():
    r = requests.post(
        f"{BASE}/transfer",
        json={"from": "alice", "to": "bob", "amount": 10, "request_id": "qa-visible-1"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"
