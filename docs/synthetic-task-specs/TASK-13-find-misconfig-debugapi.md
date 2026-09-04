# TASK-13 — find-misconfig-debugapi

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A02 Security Misconfiguration** (CWE-16, CWE-489, CWE-942, CWE-798) |
| Difficulty | **easy** |
| Deliverable | `/app/security_report.json` (audit report; **no code changes**) |
| Pattern cloned from | `local_task/find-sqli-login` + `docs/synthetic-task-specs/TASK-01` (audit → findings[] JSON) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/find-misconfig-debugapi"
description = "Audit a FastAPI admin dashboard for security misconfiguration (debug mode, wildcard CORS, default credentials, secret-exposing debug endpoint) and report findings as JSON."
authors = []
keywords = []

[metadata]
difficulty = "easy"
category = "security"
tags = ["local", "owasp-a02", "misconfiguration", "cors", "debug", "default-credentials", "audit"]

[verifier]
timeout_sec = 120.0

[agent]
timeout_sec = 600.0

[environment]
build_timeout_sec = 600.0
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app`. The application is an internal FastAPI admin dashboard
that is being prepared for production deployment.

Perform a security configuration audit (OWASP A02: Security Misconfiguration
focus). Do not modify application code.

Your deliverable is a machine-readable JSON report at:

`/app/security_report.json`

The report must be valid JSON with this top-level shape:

```json
{
  "findings": [
    {
      "title": "Short finding title",
      "severity": "critical|high|medium|low|informational",
      "category": "Vulnerability category",
      "location": "Affected file, function, endpoint, or component",
      "evidence": "Concrete code or behavior that demonstrates the issue",
      "impact": "Security impact",
      "recommendation": "Recommended remediation"
    }
  ]
}
```

Cover every distinct misconfiguration you can substantiate from the code and
running service. Include enough detail for each finding to be actionable.
````

## 3. `environment/` composition

Pure FastAPI, in-memory "users" dict; no database.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | Same recipe as `find-sqli-login` (`FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY app/ .`, `uv pip install .`, `COPY entrypoint.sh /entrypoint.sh`, `EXPOSE 8000`, `ENTRYPOINT ["/entrypoint.sh"]`) |
| `environment/entrypoint.sh` | `uvicorn main:app --host 0.0.0.0 --port 8000 --reload &` then `tail -f /dev/null` (**`--reload` + dev server in "prod" — itself a finding**) |
| `environment/app/pyproject.toml` | deps: `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pytest>=8` |
| `environment/app/AGENTS.md` | Project context: "internal dashboard, staging build; do not change code" |
| `environment/app/config.py` | **Misconfig source** — see below |
| `environment/app/main.py` | App assembly: CORS, debug endpoint, static mount, exception page — see below |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/routers/admin.py` | Login with default credentials; session cookie flags |
| `environment/app/README.md` | Committed ops doc containing the seeded credentials ("first login: admin / admin123") |
| `environment/app/tests/test_api.py` | regression: `/healthz` 200; login with seeded creds returns 200 |

`environment/app/config.py` (key fragments):

```python
import os

DEBUG = True                      # stack traces enabled in "production"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin123"       # default credential, never rotated
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False   # readable from JS
```

`environment/app/main.py` (key fragments):

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import config, os, traceback

app = FastAPI(debug=config.DEBUG)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # wildcard
    allow_credentials=True,       # invalid + unsafe combination
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def debug_error(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "trace": traceback.format_exc()},  # leaks internals
    )

@app.get("/debug/env")
def debug_env():
    return dict(os.environ)       # dumps API keys / DB creds, no auth

app.mount("/static", StaticFiles(directory="."), show_dir_listing=True)  # serves .env too
```

`environment/app/routers/admin.py` (key fragments):

```python
@router.post("/login")
def login(req: LoginRequest, response: Response):
    if req.username == config.ADMIN_USER and req.password == config.ADMIN_PASSWORD:
        response.set_cookie("session", "fixed-session-token-0001")   # static token, no flags
        return {"status": "ok"}
    return {"status": "denied"}
```

Vulnerability inventory (what a correct audit must surface — ≥4 distinct findings):

1. **Debug mode + verbose exception pages** — `FastAPI(debug=True)`, `--reload`, handler returning
   `str(exc)` and full traceback (CWE-489, CWE-209).
2. **Wildcard CORS with credentials** — `allow_origins=["*"]` + `allow_credentials=True` (CWE-942).
3. **Default credentials** — `admin/admin123` in `config.py` and documented in committed `README.md` (CWE-798).
4. **Unauthenticated `/debug/env`** — dumps full process environment including secrets (CWE-200).
5. **Directory listing + source/`.env` exposure** — `StaticFiles(directory=".", show_dir_listing=True)` (CWE-548).
6. **Insecure session cookies** — `SESSION_COOKIE_*` flags off; static predictable token (CWE-614, CWE-330).
7. **Dev secret fallback** — `SECRET_KEY` default `"dev-secret-key-change-me"` (CWE-1188).

## 4. Verifier (`tests/`)

`tests/test.sh`: identical harness style to `find-sqli-login` — ensure uvicorn is serving
(start from `/app` if `/healthz` is not answering), write 0/1 to `/logs/verifier/reward.txt`,
run `$PYTHON -m pytest /tests -v`.

`tests/test_security_report.py` (hidden verifier):

```python
import hashlib, json
from pathlib import Path
from typing import Any

REPORT_PATH = Path("/app/security_report.json")

def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    return str(value)

def _has_any(text: str, needles: list[str]) -> bool:
    return any(n in text for n in needles)

SIGNAL_GROUPS = {
    "debug": ["debug", "traceback", "stack trace", "verbose error", "cwe-489", "cwe-209"],
    "cors": ["cors", "cross-origin", "cwe-942", "allow_origins", "wildcard"],
    "creds": ["default credential", "admin123", "hardcoded password", "seeded", "cwe-798"],
    "envdump": ["debug/env", "environment", "os.environ", "secret", "cwe-200"],
    "listing": ["directory listing", "show_dir_listing", "staticfiles", "cwe-548"],
    "cookie": ["cookie", "httponly", "secure flag", "cwe-614"],
}

def test_report_valid():
    data = json.loads(REPORT_PATH.read_text())
    assert isinstance(data.get("findings"), list) and data["findings"]

def test_at_least_four_distinct_misconfigs():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    groups_hit = sum(
        1 for needles in SIGNAL_GROUPS.values()
        if any(_has_any(t, needles) for t in flat)
    )
    assert groups_hit >= 4, f"only {groups_hit} misconfiguration groups covered"

def test_default_credential_finding_has_location():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["admin123", "default credential"])
               and _has_any(_flatten(f).lower(), ["config.py", "readme.md", "routers/admin.py"])
               for f in data["findings"])

def test_app_code_unmodified():
    PRISTINE_SHA256 = {"config.py": "<pin-at-build-time>", "main.py": "<pin-at-build-time>"}
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256(Path("/app", rel).read_bytes()).hexdigest() == want
```

**Grading:** binary 0/1 — valid JSON, ≥1 finding, ≥4 signal groups hit across findings,
credential finding names its location, code byte-identical.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. `ls -la /app`, read `config.py`, `main.py`, `routers/admin.py`, `README.md`.
2. Optionally probe `GET /debug/env` and `GET /static/` live to confirm.
3. Write `/app/security_report.json` with 6–7 findings (one per inventory item above).
4. `python3 -c "import json; json.load(open('/app/security_report.json'))"` self-check.

## 6. Expected agent difficulty profile

- **Steps:** ~6–10 tool calls. Easiest of the audit family: every issue is a one-liner grep away.
- **Small-model failure modes:**
  - Writes only one mega-finding "misconfiguration found" — fails the ≥4-groups test.
  - Misses the committed `README.md` as part of the default-credential finding (location signal).
  - "Fixes" `config.py` despite the no-modify instruction → trips the hash pin.
  - Emits invalid JSON with unescaped newlines in `evidence`.
