ALICE = {"X-User-Id": "1"}


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_alice_lists_exactly_own_invoices(client):
    r = client.get("/invoices", headers=ALICE)
    assert r.status_code == 200
    ids = sorted(item["id"] for item in r.json())
    assert ids == [101, 102], f"alice must see exactly her invoices: {ids}"


def test_alice_pays_own_invoice(client):
    r = client.post("/invoices/102/pay", headers=ALICE)
    assert r.status_code == 200
    assert client.get("/invoices/102", headers=ALICE).json()["status"] == "paid"


def test_unknown_invoice_is_404(client):
    r = client.get("/invoices/999", headers=ALICE)
    assert r.status_code == 404
