# TASK-07 — fix-insecure-pickle

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A08 Software/Data Integrity Failures** (insecure deserialization, CWE-502) |
| Difficulty | medium |
| Deliverable | Fixed deserialization path + green pytest regression (RCE payload must not execute) |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden pytest on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-insecure-pickle"
description = "Replace pickle.loads on attacker-controlled job blobs with strict JSON validation in a FastAPI job runner."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "deserialization", "owasp-a08", "cwe-502", "pickle", "fastapi", "fix"]

[verifier]
timeout_sec = 120.0

[agent]
timeout_sec = 900.0

[environment]
build_timeout_sec = 600.0
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []

[verifier.env]

[environment.env]

[solution.env]
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app`. The application is a FastAPI job runner. Clients submit jobs as
base64-encoded blobs to `POST /jobs/import`.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. The job blob
wire format is **JSON** with exactly the fields:

- `name` — string, 1–128 chars
- `priority` — integer, 0–9
- `params` — object with string keys and string values

Invalid blobs must be rejected with a 4xx status and must **never** execute
attacker-controlled code (no `pickle`, `yaml.load`, `eval`, or similar).

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `json`, `base64` are sufficient).
````

## 3. `environment/` composition

No database — in-memory job list.

| Path | Contents |
|---|---|
| `environment/Dockerfile`, `environment/entrypoint.sh` | same pattern (no postgres) |
| `environment/app/pyproject.toml` | deps: fastapi, uvicorn[standard], httpx, pytest |
| `environment/app/AGENTS.md` | same discipline doc |
| `environment/app/main.py` | FastAPI app, `GET /healthz`, router registration |
| `environment/app/routers/jobs.py` | **vulnerable** — verbatim below |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/tests/test_api.py` | visible regression (encoding-agnostic, passes pre- AND post-fix): `POST /jobs/import` with garbage base64 → 400; `GET /jobs` → `[]` initially; `GET /healthz` 200. Also seeds a job through a direct `POST /jobs` JSON endpoint and lists it |

`environment/app/routers/jobs.py` (verbatim):

```python
import base64, pickle
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["jobs"])

_JOBS: list[dict] = []


class ImportRequest(BaseModel):
    blob_b64: str


@router.post("/jobs/import")
async def import_job(req: ImportRequest):
    try:
        job = pickle.loads(base64.b64decode(req.blob_b64))  # VULNERABLE: CWE-502, RCE via __reduce__
    except Exception:
        raise HTTPException(status_code=400, detail="bad blob")
    _JOBS.append(job)
    return {"imported": job["name"]}


@router.post("/jobs")
async def create_job(name: str, priority: int, params: dict[str, str] | None = None):
    job = {"name": name, "priority": priority, "params": params or {}}
    _JOBS.append(job)
    return {"imported": job["name"]}


@router.get("/jobs")
async def list_jobs():
    return [{"name": j["name"], "priority": j["priority"]} for j in _JOBS]
```

## 4. Verifier (`tests/`)

`tests/test.sh`: kill stale uvicorn, start fresh from `/app`, `rm -f /tmp/pwned` first,
run `pytest /tests`, reward 0/1.

`tests/test_deserialization.py` (hidden verifier — payloads are forged at runtime so the test
is fully deterministic without embedded binary constants):

```python
import base64, json, os, pickle
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
```

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `routers/jobs.py`; identify `pickle.loads` on attacker-controlled base64.
2. Patch `import_job`:
   ```python
   import json

   @router.post("/jobs/import")
   async def import_job(req: ImportRequest):
       try:
           raw = base64.b64decode(req.blob_b64, validate=True)
           job = json.loads(raw)
       except Exception:
           raise HTTPException(status_code=400, detail="bad blob")
       if not isinstance(job, dict) or set(job) != {"name", "priority", "params"}:
           raise HTTPException(status_code=422, detail="invalid job schema")
       if not isinstance(job["name"], str) or not (1 <= len(job["name"]) <= 128):
           raise HTTPException(status_code=422, detail="invalid name")
       if isinstance(job["priority"], bool) or not isinstance(job["priority"], int) or not (0 <= job["priority"] <= 9):
           raise HTTPException(status_code=422, detail="invalid priority")
       if not isinstance(job["params"], dict) or not all(
           isinstance(k, str) and isinstance(v, str) for k, v in job["params"].items()
       ):
           raise HTTPException(status_code=422, detail="invalid params")
       _JOBS.append(job)
       return {"imported": job["name"]}
   ```
3. Remove the `pickle` import. Restart uvicorn; `pytest tests/ -q` → green.

## 6. Expected agent difficulty profile

- **Steps:** ~10–16 tool calls.
- **Small-model failure modes:**
  - Keeps a pickle fallback "for backwards compatibility" → `test_pickle_rce_payload_neutralized`
    executes `touch /tmp/pwned` and fails hard (this is the trap the task is designed around).
  - Accepts extra fields (no `set(job) != {...}` check) → `test_extra_field_rejected`.
  - Allows `bool` as priority (Python `isinstance(True, int)` is true) → out-of-range test may
    still pass but the extra-field/type discipline is a nice discriminator; models that use
    Pydantic-only validation often accept `{"name": 123}` due to coercion — the strict test catches it.
  - Returns 500 instead of 4xx for malformed base64.
  - Encoding confusion: treating `blob_b64` as already-JSON text (ignores the base64 layer) —
    the valid-blob test fails.
