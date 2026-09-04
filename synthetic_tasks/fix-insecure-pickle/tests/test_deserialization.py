import base64, json, pickle
from pathlib import Path


def _b64(obj) -> str:
    return base64.b64encode(obj).decode()


def _json_blob(job: dict) -> str:
    return _b64(json.dumps(job).encode())


def test_valid_json_blob_imported(client):
    blob = _json_blob({"name": "nightly-index", "priority": 3, "params": {"target": "idx"}})
    r = client.post("/jobs/import", json={"blob_b64": blob})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": "nightly-index"}
    names = [j["name"] for j in client.get("/jobs").json()]
    assert "nightly-index" in names


class _RCE:
    def __reduce__(self):
        import subprocess
        return (subprocess.run, (["touch", "/tmp/pwned"],))


def test_pickle_rce_payload_neutralized(client):
    Path("/tmp/pwned").unlink(missing_ok=True)
    r = client.post("/jobs/import", json={"blob_b64": _b64(pickle.dumps(_RCE()))})
    assert r.status_code in (400, 422), f"malicious blob accepted: {r.status_code}"
    assert not Path("/tmp/pwned").exists(), "pickle payload executed (RCE)"


def test_builtin_reduce_payload_neutralized(client):
    blob = _b64(pickle.dumps(("os", "system", ("touch /tmp/pwned2",))))
    r = client.post("/jobs/import", json={"blob_b64": blob})
    assert r.status_code in (400, 422)
    assert not Path("/tmp/pwned2").exists()


def test_wrong_types_rejected(client):
    blob = _json_blob({"name": 123, "priority": 3, "params": {}})
    assert client.post("/jobs/import", json={"blob_b64": blob}).status_code in (400, 422)


def test_extra_field_rejected(client):
    blob = _json_blob({"name": "x", "priority": 1, "params": {}, "admin": True})
    assert client.post("/jobs/import", json={"blob_b64": blob}).status_code in (400, 422)


def test_priority_out_of_range_rejected(client):
    blob = _json_blob({"name": "x", "priority": 42, "params": {}})
    assert client.post("/jobs/import", json={"blob_b64": blob}).status_code in (400, 422)


def test_garbage_bytes_rejected(client):
    assert client.post("/jobs/import", json={"blob_b64": _b64(b"\x80\x04garbage")}).status_code in (400, 422)
