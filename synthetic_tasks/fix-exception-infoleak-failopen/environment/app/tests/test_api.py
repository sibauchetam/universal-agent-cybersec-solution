from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_orders_with_valid_token():
    r = client.get("/orders", headers={"Authorization": "Bearer tok-admin-001"})
    assert r.status_code == 200, r.text
    assert r.json()["orders"][0]["item"] == "keyboard"
