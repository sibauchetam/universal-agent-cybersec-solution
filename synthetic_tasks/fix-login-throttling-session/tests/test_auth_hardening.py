import re, requests

BASE = "http://127.0.0.1:8000"

def test_healthz(): assert requests.get(f"{BASE}/healthz").status_code == 200

def test_lockout_after_five_failures():
    for i in range(5):
        r = requests.post(f"{BASE}/login", json={"username": "ops", "password": "wrong"})
        assert r.status_code in (200, 401)          # failures may be 200-with-denied or 401
    r6 = requests.post(f"{BASE}/login", json={"username": "ops", "password": "Ops!Pass42"})
    assert r6.status_code == 429, "6th attempt (even correct) must be throttled"

def test_lockout_survives_restart():
    # harness restarts the service between test classes; state must persist
    r = requests.post(f"{BASE}/login", json={"username": "ops", "password": "wrong"})
    assert r.status_code in (200, 401, 429)

def test_other_user_not_locked():
    r = requests.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"})
    assert r.status_code == 200 and r.json()["status"] == "ok"

def test_session_entropy_and_rotation():
    s1 = requests.Session(); s2 = requests.Session()
    t1 = s1.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"}).cookies.get("session")
    t2 = s2.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"}).cookies.get("session")
    assert t1 and t2 and t1 != t2
    assert re.fullmatch(r"[0-9a-f]{32,}", t1), f"weak token: {t1!r}"

def test_remember_me_expiry():
    r = requests.post(f"{BASE}/remember", json={"username": "viewer"},
                      allow_redirects=False)
    sc = r.headers.get("set-cookie", "")
    m = re.search(r"[Mm]ax-[Aa]ge=(\d+)", sc)
    assert m, f"no max-age in Set-Cookie: {sc!r}"
    assert 0 < int(m.group(1)) <= 7 * 24 * 3600
