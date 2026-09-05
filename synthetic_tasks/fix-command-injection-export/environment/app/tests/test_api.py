from pathlib import Path

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_weekly_export():
    r = client.post("/export", json={"report_id": "weekly-42", "format": "pdf"})
    assert r.status_code == 200, r.text
    out = Path("/tmp/exports/weekly-42.pdf")
    assert out.exists()
    assert out.read_bytes().startswith(b"RENDER-OK-weekly-42")
