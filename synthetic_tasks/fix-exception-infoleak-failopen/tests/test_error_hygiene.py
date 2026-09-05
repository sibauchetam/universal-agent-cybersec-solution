import requests

BASE = "http://127.0.0.1:8000"
H = {"Authorization": "Bearer tok-admin-001"}

def test_healthz(): assert requests.get(f"{BASE}/healthz").status_code == 200

def test_happy_path_unchanged():
    r = requests.get(f"{BASE}/orders", headers=H)
    assert r.status_code == 200 and r.json()["orders"][0]["item"] == "keyboard"

def test_500_does_not_leak():
    r = requests.get(f"{BASE}/orders", params={"sort": "explode"}, headers=H)
    assert r.status_code == 500
    body = r.text.lower()
    for banned in ["traceback", "sqlite3", "operationalerror", "pr0d-0nly", "ops_rw",
                   "prod.db", "no such table", ".py"]:
        assert banned not in body, f"leaked: {banned}"
    assert r.json() == {"detail": "Internal server error"}

def test_missing_token_rejected():
    r = requests.get(f"{BASE}/orders")
    assert r.status_code == 401

def test_garbage_token_rejected_fail_closed():
    for hdr in ["Bearer !!!", "Bearer ", "Basic dXNlcjpwYXNz", ""]:
        r = requests.get(f"{BASE}/orders", headers={"Authorization": hdr})
        assert r.status_code in (401, 403), f"{hdr!r} -> {r.status_code}"

def test_500_body_contract_even_for_unknown_paths():
    r = requests.post(f"{BASE}/orders", headers=H, json={"boom": True})
    assert r.status_code in (404, 405, 422)
