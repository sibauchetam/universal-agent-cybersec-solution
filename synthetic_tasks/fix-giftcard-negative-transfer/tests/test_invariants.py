import requests

BASE = "http://127.0.0.1:8000"

def _bal(user):
    return requests.get(f"{BASE}/wallets/{user}").json()["balance"]

def test_healthz(): assert requests.get(f"{BASE}/healthz").status_code == 200

def test_negative_transfer_rejected():
    before = _bal("alice")
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": -500, "request_id": "t-neg"})
    assert r.status_code >= 400
    assert _bal("alice") == before

def test_zero_transfer_rejected():
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": 0, "request_id": "t-zero"})
    assert r.status_code >= 400

def test_overdraft_blocked():
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "carol", "to": "alice", "amount": 10000, "request_id": "t-od"})
    assert r.status_code >= 400 and _bal("carol") == 40

def test_giftcard_single_use():
    r1 = requests.post(f"{BASE}/giftcard/redeem", json={"code": "GIFT-SPRING-10", "for_user": "bob"})
    assert r1.status_code == 200
    r2 = requests.post(f"{BASE}/giftcard/redeem", json={"code": "GIFT-SPRING-10", "for_user": "bob"})
    assert r2.status_code >= 400
    assert requests.post(f"{BASE}/giftcard/redeem",
                         json={"code": "GIFT-DEAD-5", "for_user": "bob"}).status_code >= 400

def test_discount_bounds_and_server_pricing():
    assert requests.post(f"{BASE}/checkout",
                         json={"item": "tshirt", "discount_pct": 150}).status_code >= 400
    ok = requests.post(f"{BASE}/checkout", json={"item": "tshirt", "discount_pct": 20}).json()
    assert ok["total"] == 20.0                      # server catalog price honored
    bad = requests.post(f"{BASE}/checkout", json={"item": "tshirt", "discount_pct": -5})
    assert bad.status_code >= 400

def test_transfer_idempotent():
    b = _bal("alice")
    for _ in range(3):
        requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": 5, "request_id": "idem-1"})
    assert _bal("alice") == b - 5
