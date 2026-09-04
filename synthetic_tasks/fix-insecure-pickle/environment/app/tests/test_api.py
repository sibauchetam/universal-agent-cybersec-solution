import base64
import json

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_list_jobs_empty():
    assert client.get("/jobs").status_code == 200


def test_create_and_list_job():
    r = client.post("/jobs?name=build-a&priority=2")
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": "build-a"}
    names = [j["name"] for j in client.get("/jobs").json()]
    assert "build-a" in names


def test_import_valid_json_blob():
    blob = base64.b64encode(json.dumps({"name": "idx", "priority": 1, "params": {"t": "x"}}).encode()).decode()
    r = client.post("/jobs/import", json={"blob_b64": blob})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": "idx"}


def test_import_garbage_rejected():
    r = client.post("/jobs/import", json={"blob_b64": "!!!not-base64!!!"})
    assert r.status_code in (400, 422)
