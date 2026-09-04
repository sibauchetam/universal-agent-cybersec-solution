# TASK-05 — fix-command-injection-export

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A03 Injection** (OS command injection, CWE-78) |
| Difficulty | medium |
| Deliverable | Fixed FastAPI code + green pytest regression (injection payloads neutralized) |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden pytest on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-command-injection-export"
description = "Fix OS command injection in a FastAPI report exporter that shells out to a rendering tool."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "command-injection", "owasp-a03", "cwe-78", "fastapi", "fix"]

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
You are working in `/app`. The application is a FastAPI report-exporter that shells out
to a rendering tool.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. In particular:

- Legitimate exports (report ids like `weekly-42`, `q2-financials`) must keep working.
- Client-controlled values must never be interpreted by a shell.
- Invalid input must be rejected with a 4xx response.

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`.
````

## 3. `environment/` composition

No database. FastAPI + `asyncio` subprocess.

| Path | Contents |
|---|---|
| `environment/Dockerfile`, `environment/entrypoint.sh` | same pattern (no postgres) |
| `environment/app/pyproject.toml` | deps: fastapi, uvicorn[standard], httpx, pytest |
| `environment/app/AGENTS.md` | same discipline doc |
| `environment/app/main.py` | FastAPI app + `GET /healthz` + router registration; ensures `/tmp/exports` exists at startup |
| `environment/app/routers/export.py` | **vulnerable** — verbatim below |
| `environment/app/tools/render.py` | benign CLI tool: dict `REPORTS = {"weekly-42": "...", "q2-financials": "..."}`; args `--report ID --format F --out PATH`; exits 2 if ID unknown; writes `RENDER-OK-<report_id>` bytes to `--out` |
| `environment/app/tests/test_api.py` | visible regression: `POST /export {"report_id": "weekly-42"}` → 200 and `/tmp/exports/weekly-42.pdf` exists; healthz 200 |

`environment/app/routers/export.py` (verbatim):

```python
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["export"])


class ExportRequest(BaseModel):
    report_id: str
    format: str = "pdf"


@router.post("/export")
async def export(req: ExportRequest):
    out = f"/tmp/exports/{req.report_id}.{req.format}"
    cmd = (
        f"python3 /app/tools/render.py --report {req.report_id} "
        f"--format {req.format} --out {out}"
    )
    # VULNERABLE: shell interpretation of client-controlled values
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail="render failed")
    return {"output": out}
```

## 4. Verifier (`tests/`)

`tests/test.sh`: kill stale uvicorn, start fresh from `/app`, `rm -f /tmp/pwned*` before the
pytest run, run `pytest /tests`, reward 0/1.

`tests/test_cmdi.py` (hidden verifier — exact expected values):

```python
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
```

**Exact grading semantics:** binary 0/1 — all five tests pass. Note the payload tests are
file-based (no `/tmp/pwned*` artifacts after the run) plus a 4xx requirement only for the
`format` field, so both "validate then exec-without-shell" and "exec-without-shell only"
fixes pass.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `routers/export.py` and `tools/render.py`; spot `create_subprocess_shell` with f-string.
2. Patch:
   ```python
   import re
   _SAFE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

   @router.post("/export")
   async def export(req: ExportRequest):
       if not _SAFE.fullmatch(req.report_id) or not _SAFE.fullmatch(req.format):
           raise HTTPException(status_code=422, detail="invalid report id or format")
       out = f"/tmp/exports/{req.report_id}.{req.format}"
       proc = await asyncio.create_subprocess_exec(
           "python3", "/app/tools/render.py",
           "--report", req.report_id, "--format", req.format, "--out", out,
           stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
       )
       stdout, stderr = await proc.communicate()
       if proc.returncode != 0:
           raise HTTPException(status_code=404, detail="unknown report")
       return {"output": out}
   ```
3. Restart uvicorn; `pytest tests/ -q` → green.

## 6. Expected agent difficulty profile

- **Steps:** ~10–15 tool calls.
- **Small-model failure modes:**
  - Adds `shlex.quote` but keeps `create_subprocess_shell` — usually still passes the file-based
    tests, but models often then break the *normal* export by quoting the whole command string.
  - Over-strict regex (rejects `-` or digits) breaks `weekly-42` regression.
  - Maps unknown-report errors to 500 and crashes on empty `stderr` decoding — only the 4xx
    requirement for `format` is enforced, but the unknown-report regression catches a 200-echo bug.
  - Forgets `pkill -f uvicorn` and tests the old process → false confusion loop.
