import os
from pathlib import Path

def _rm_pwned():
    for p in ("/tmp/pwned", "/tmp/pwned2", "/tmp/pwned3"):
        Path(p).unlink(missing_ok=True)

def test_normal_export_still_works(client):
    _rm_pwned()
    r = client.post("/export", json={"report_id": "q2-financials", "format": "pdf"})
    assert r.status_code == 200, r.text
    out = Path("/tmp/exports/q2-financials.pdf")
    assert out.exists()
    assert out.read_bytes().startswith(b"RENDER-OK-q2-financials")

def test_semicolon_payload_creates_no_file(client):
    _rm_pwned()
    r = client.post("/export", json={"report_id": "weekly-42; touch /tmp/pwned", "format": "pdf"})
    assert not Path("/tmp/pwned").exists(), "semicolon injection executed"

def test_backtick_payload_creates_no_file(client):
    _rm_pwned()
    client.post("/export", json={"report_id": "weekly-42`touch /tmp/pwned2`", "format": "pdf"})
    assert not Path("/tmp/pwned2").exists(), "backtick injection executed"

def test_format_field_injection_rejected(client):
    _rm_pwned()
    r = client.post("/export", json={"report_id": "weekly-42", "format": "pdf; touch /tmp/pwned3"})
    assert not Path("/tmp/pwned3").exists(), "format-field injection executed"
    assert r.status_code in (400, 422), f"malicious format accepted: {r.status_code}"

def test_unknown_report_not_200(client):
    r = client.post("/export", json={"report_id": "no-such-report", "format": "pdf"})
    assert r.status_code != 200
