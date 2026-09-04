# TASK-16 — fix-exception-infoleak-failopen

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A10 Mishandling of Exceptional Conditions** (CWE-209, CWE-285 fail-open, CWE-703) |
| Difficulty | medium |
| Deliverable | Patched source; hidden pytest suite runs against the live service |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden tests on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-exception-infoleak-failopen"
description = "A FastAPI service leaks stack traces and DB credentials through its global error handler, and its token-auth path fails OPEN on internal errors. Fix error handling to be fail-closed and non-disclosing."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "owasp-a10", "exception", "error-handling", "fail-open", "infoleak", "fix"]

[verifier]
timeout_sec = 180.0

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
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app`. The application is a FastAPI order-tracking service
protected by a bearer token. A pentest found two classes of issues:

1. Error responses disclose internals: raw exception text, stack traces,
   filesystem paths and DB credentials are returned to clients on 500s.
2. The token-authorization path fails OPEN: if any internal error occurs
   while validating a token, the request is processed as if the token were
   valid.

Fix the application so that:

- All unhandled errors return `{"detail": "Internal server error"}` with
  status 500 and nothing else; full details must be written to the
  server-side log only (stderr is fine).
- Token validation must fail CLOSED: any internal error during token
  verification results in 401 for the protected endpoint, never 200.
- Existing happy-path behavior must not change (the hidden regression suite
  checks the public API contract, including `GET /healthz`).

The service is started by the harness (`uvicorn main:app` on port 8000).
````

## 3. `environment/` composition

In-memory orders list; auth middleware; deliberately fragile DB stub.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | Standard recipe (`secureintelligent/acp:latest`, `WORKDIR /app`, install, entrypoint) |
| `environment/entrypoint.sh` | uvicorn + tail (verifier owns restarts) |
| `environment/app/pyproject.toml` | deps: `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pytest>=8` |
| `environment/app/AGENTS.md` | Service context + contract table (below) |
| `environment/app/main.py` | App assembly, **fail-open auth + leaky handler** — see below |
| `environment/app/store.py` | Orders store with planted crash path + creds in exception text |
| `environment/app/tests/test_api.py` | benign regression (contract): `/healthz` 200; `/orders` with valid token 200 |
| `environment/app/tests/__init__.py` | empty |

`environment/app/main.py` (key fragments):

```python
import traceback
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import store

VALID_TOKENS = {"tok-admin-001": "admin", "tok-view-002": "viewer"}

app = FastAPI()

@app.exception_handler(Exception)
async def raw_error(request: Request, exc: Exception):
    # BUG 1: leaks exception text + traceback to the client
    return JSONResponse(status_code=500,
                        content={"error": str(exc), "trace": traceback.format_exc()})

@app.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path.startswith("/orders"):
        try:
            tok = request.headers.get("Authorization", "").removeprefix("Bearer ")
            role = VALID_TOKENS[tok]
        except Exception:
            # BUG 2: fail-OPEN — malformed/missing token errors fall through as admin
            role = "admin"
        request.state.role = role
    return await call_next(request)

@app.get("/orders")
async def list_orders(request: Request):
    if request.state.role not in {"admin", "viewer"}:
        raise HTTPException(403)
    return {"orders": store.all_orders()}
```

`environment/app/store.py` (key fragments):

```python
_ORDERS = [{"id": 1, "item": "keyboard", "qty": 2}]

def all_orders(sort: str | None = None):
    if sort == "explode":           # reachable via ?sort= param — planted crash
        raise sqlite3.OperationalError(
            "no such table: audit_log (db=/app/data/prod.db, user=ops_rw, password=pr0d-0nly)")
    return _ORDERS
```

(`import sqlite3` at module top; `/orders?sort=explode` reliably 500s with the leak.)

## 4. Verifier (`tests/`)

`tests/test.sh`: same harness family as `fix-sqli-login` — restart service, wait `/healthz`,
reward 0/1, pytest.

`tests/test_error_hygiene.py` (hidden verifier):

```python
import requests

BASE = "http://127.0.0.1:8000"
H = {"Authorization": "Bearer tok-admin-001"}

def test_healthz(): assert requests.get(f"{BASE}/healthz").status_code == 200

def test_happy_path_unchanged():
    r = requests.get(f"{BASE}/orders", headers=H)
    assert r.status_code == 200 and r.json()["orders"][0]["item"] == "keyboard"

def test_500_does_not_leak():
    r = requests.get(f"{BASE}/orders", params={"sort": "explode"}, headers=H)
    assert r.status_code == 500
    body = r.text.lower()
    for banned in ["traceback", "sqlite3", "operationalerror", "pr0d-0nly", "ops_rw",
                   "prod.db", "no such table", ".py"]:
        assert banned not in body, f"leaked: {banned}"
    assert r.json() == {"detail": "Internal server error"}

def test_missing_token_rejected():
    r = requests.get(f"{BASE}/orders")
    assert r.status_code == 401

def test_garbage_token_rejected_fail_closed():
    for hdr in ["Bearer !!!", "Bearer ", "Basic dXNlcjpwYXNz", ""]:
        r = requests.get(f"{BASE}/orders", headers={"Authorization": hdr})
        assert r.status_code in (401, 403), f"{hdr!r} -> {r.status_code}"

def test_500_body_contract_even_for_unknown_paths():
    r = requests.post(f"{BASE}/orders", headers=H, json={"boom": True})
    assert r.status_code in (404, 405, 422)
```

**Grading:** binary 0/1 — all hidden tests green (fail-closed + no-leak + contract).

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `main.py`, `store.py`; spot leaky handler and fail-open middleware.
2. Handler: `return JSONResponse(500, {"detail": "Internal server error"})`; add
   `logging.exception(...)` server-side.
3. Middleware: restructure so any exception during token verification sets
   `role = None` (→ 401), unknown token → 401, valid → role. Never assign a role
   in an `except` block.
4. Restart, replay hidden tests, verify leak strings absent from responses.

## 6. Expected agent difficulty profile

- **Steps:** ~10–16 tool calls.
- **Small-model failure modes:**
  - Genericizes the handler but leaves `str(exc)` in *another* handler or in a 4xx path.
  - Changes fail-open to fail-closed but returns 500 instead of 401 for garbage tokens.
  - "Fixes" by removing the planted crash (`if sort == "explode"`) — the regression suite
    then re-plants nothing but the leak test never triggers a 500; graders see handler
    unchanged in *other* paths; contract test still red if middleware untouched.
  - Removes auth for `/orders` entirely (tests then fail on 401 assertions).
