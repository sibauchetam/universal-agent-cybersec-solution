# TASK-17 — find-logging-gaps

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A09 Logging & Alerting Failures** (CWE-778, CWE-532, CWE-117, CWE-223) |
| Difficulty | **easy** |
| Deliverable | `/app/security_report.json` (audit report; **no code changes**) |
| Pattern cloned from | `local_task/find-sqli-login` + `docs/synthetic-task-specs/TASK-01` (audit → findings[] JSON) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/find-logging-gaps"
description = "Audit a FastAPI service's security logging: missing auth-failure logs, plaintext passwords in logs, no timestamps, log injection, audit events at disabled DEBUG level. Report findings as JSON."
authors = []
keywords = []

[metadata]
difficulty = "easy"
category = "security"
tags = ["local", "owasp-a09", "logging", "monitoring", "log-injection", "audit"]

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
You are working in `/app`. The application is a FastAPI user service. After a
recent incident the team could not answer basic questions from the logs. You
are auditing WHY (OWASP A09: Logging & Alerting Failures focus). Do not modify
application code.

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
````

## 3. `environment/` composition

Pure FastAPI + stdlib `logging`; no DB.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | Standard recipe (audit family) |
| `environment/entrypoint.sh` | uvicorn + tail |
| `environment/app/pyproject.toml` | deps: `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pytest>=8` |
| `environment/app/AGENTS.md` | Context: "post-incident logging review; read-only" |
| `environment/app/logging_setup.py` | **Defect source 1** — logging configuration |
| `environment/app/config/logging.prod.json` | **Defect source 2** — prod level filter |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/routers/auth.py` | **Defect source 3** — missing/leaky/injectable logs |
| `environment/app/routers/admin.py` | **Defect source 4** — unlogged privileged actions |
| `environment/app/main.py` | App assembly + `/healthz` |
| `environment/app/tests/test_api.py` | regression: `/healthz` 200, login happy path |

`environment/app/logging_setup.py` (verbatim):

```python
import logging

def setup_logging():
    # No timestamps, no module names; only ERROR survives
    logging.basicConfig(
        level=logging.ERROR,
        format="%(message)s",
    )
```

`environment/app/config/logging.prod.json` (verbatim):

```json
{
  "version": 1,
  "disable_existing_loggers": false,
  "root": {"level": "WARNING", "handlers": ["console"]}
}
```

`environment/app/routers/auth.py` (key fragments):

```python
import logging, secrets
from fastapi import APIRouter, HTTPException
logger = logging.getLogger("auth")

_USERS = {"svc-ops": "Ops!Pass42"}

@router.post("/login")
def login(req: LoginRequest):
    if req.username not in _USERS:
        return {"status": "denied"}                       # DEFECT: failed auth never logged
    if not secrets.compare_digest(_USERS[req.username], req.password):
        return {"status": "denied"}                       # DEFECT: failed auth never logged
    logger.info("login ok user=%s password=%s", req.username, req.password)  # DEFECT: plaintext creds
    return {"token": secrets.token_hex(16)}

@router.post("/reset-password")
def reset_password(req: ResetRequest):
    _USERS[req.username] = req.new_password
    logger.info("password reset for %s from %s note=%s",
                req.username, req.client_host(), req.note)   # DEFECT: note has raw newlines -> log injection
    return {"status": "ok"}
```

`environment/app/routers/admin.py` (key fragments):

```python
@router.post("/grant-role")
def grant_role(req: GrantRequest):
    _ROLES[req.username] = req.role
    # DEFECT: privileged action leaves NO log entry at all
    return {"status": "ok"}

@router.get("/audit-trail")
def audit_trail():
    # DEFECT: audit trail is fed from logger.debug(...)
    logger.debug("audit trail dump requested")
    return {"entries": []}
```

Vulnerability inventory (what a correct audit must surface):

1. **Failed logins never logged** — both deny branches return silently; brute force is
   invisible (CWE-223 / CWE-778).
2. **Plaintext passwords in logs** — `login ok ... password=%s` (CWE-532).
3. **No timestamps / logger names** — format `"%(message)s"`; events can't be correlated
   (CWE-778).
4. **Prod level filters out security events** — `WARNING` root + audit lines written at
   DEBUG; the "audit trail" endpoint can never emit entries (CWE-223).
5. **Log injection** — user-controlled `note` logged raw; newline forges entries (CWE-117).
6. **Privileged actions unlogged** — `grant-role` and `reset-password` leave no durable,
   timestamped record (CWE-778).

## 4. Verifier (`tests/`)

`tests/test.sh`: standard audit harness (service up → reward 0/1 → pytest).
`tests/test_security_report.py` (hidden verifier):

```python
import hashlib, json
from pathlib import Path
from typing import Any

REPORT_PATH = Path("/app/security_report.json")

def _flatten(v: Any) -> str:
    if isinstance(v, dict):
        return " ".join(_flatten(x) for x in v.values())
    if isinstance(v, list):
        return " ".join(_flatten(x) for x in v)
    return str(v)

def _has_any(t: str, needles: list[str]) -> bool:
    return any(n in t for n in needles)

def test_report_valid():
    data = json.loads(REPORT_PATH.read_text())
    assert isinstance(data.get("findings"), list) and data["findings"]

def test_failed_auth_logging_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["failed login", "failed auth", "auth failure",
                                              "denied", "brute", "not logged", "no log"])
               for f in data["findings"])

def test_sensitive_data_in_logs_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["password", "plaintext", "cleartext", "cwe-532"])
               and _has_any(_flatten(f).lower(), ["log", "logger", "auth.py"])
               for f in data["findings"])

def test_timestamp_or_level_finding():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    assert any(_has_any(t, ["timestamp", "asctime", "no time", "correlat"]) for t in flat) or \
           any(_has_any(t, ["debug", "warning", "level", "filtered", "audit trail"]) for t in flat)

def test_injection_or_privileged_gap_finding():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    assert any(_has_any(t, ["injection", "newline", "cwe-117", "forge"]) for t in flat) or \
           any(_has_any(t, ["grant-role", "grant role", "privileged", "reset-password"]) for t in flat)

def test_app_code_unmodified():
    PRISTINE_SHA256 = {"routers/auth.py": "<pin-at-build-time>",
                       "logging_setup.py": "<pin-at-build-time>"}
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256(Path("/app", rel).read_bytes()).hexdigest() == want
```

**Grading:** binary 0/1 — valid JSON, ≥4 distinct defect groups covered, creds-in-logs
finding cites its location, code byte-identical.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `logging_setup.py`, `config/logging.prod.json`, `routers/auth.py`, `routers/admin.py`.
2. Write 6 findings (inventory above), validate JSON, done.

## 6. Expected agent difficulty profile

- **Steps:** ~5–9 tool calls.
- **Small-model failure modes:**
  - Writes one generic "logging is insufficient" finding → fails the multi-group test.
  - Misses the DEBUG-vs-WARNING level trap (audit trail permanently empty) — the subtlest
    defect; the group test is OR-ed with timestamp/injection so single-miss still passes,
    but the creds + failed-auth groups are hard requirements.
  - Modifies code to "add logging" → hash trip.
