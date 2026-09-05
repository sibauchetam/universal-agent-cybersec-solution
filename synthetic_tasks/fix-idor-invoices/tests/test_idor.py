ALICE = {"X-User-Id": "1"}
BOB = {"X-User-Id": "2"}

def test_owner_still_reads_own_invoice(client):
    r = client.get("/invoices/101", headers=ALICE)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 101 and body["owner_id"] == 1
    assert body["amount_cents"] == 125000 and body["status"] == "open"

def test_other_users_invoice_not_readable(client):
    r = client.get("/invoices/101", headers=BOB)
    assert r.status_code in (403, 404), f"IDOR read still works: {r.status_code} {r.text}"

def test_list_is_filtered_to_own_invoices(client):
    r = client.get("/invoices", headers=BOB)
    assert r.status_code == 200
    ids = sorted(item["id"] for item in r.json())
    assert ids == [201, 202], f"bob sees foreign invoices: {ids}"

def test_cannot_pay_others_invoice(client):
    r = client.post("/invoices/101/pay", headers=BOB)
    assert r.status_code in (403, 404)
    after = client.get("/invoices/101", headers=ALICE)
    assert after.json()["status"] == "open", "bob's pay flipped alice's invoice"

def test_owner_pays_own_invoice(client):
    r = client.post("/invoices/102/pay", headers=ALICE)
    assert r.status_code == 200
    assert client.get("/invoices/102", headers=ALICE).json()["status"] == "paid"
