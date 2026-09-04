# TASK-06 — fix-jwt-none-alg

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A07 Identification & Authentication Failures** (JWT `alg=none` / weak secret / missing expiry validation, CWE-327/347/613) |
| Difficulty | medium |
| Deliverable | Fixed JWT auth code + green pytest regression (verifier forges tokens with the runtime secret) |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden pytest on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-jwt-none-alg"
description = "Fix JWT authentication failures: alg=none bypass, hardcoded secret, missing exp validation in a stdlib-only FastAPI service."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "jwt", "owasp-a07", "authentication", "fastapi", "fix"]

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
You are working in `/app`. The application is a FastAPI service that authenticates users
with HS256 JWT bearer tokens (stdlib-only implementation, no PyJWT).

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them:

- The token verifier must accept **only** tokens whose `alg` is exactly `HS256` and whose
  signature verifies against the secret taken from the `JWT_SECRET` environment variable
  (fail closed if the variable is unset or empty — never fall back to a hardcoded secret).
- Tokens without a well-formed `exp` claim (an integer/number, in the future) must be
  rejected with 401.
- Expired tokens must be rejected with 401.
- Token signing (`POST /login`) must use the same environment-derived secret.

The grading harness starts the service with `JWT_SECRET=verifier-test-secret`.

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `base64`, `json`, `hmac`, `hashlib`, `os`, `time` are sufficient).
````

## 3. `environment/` composition

No database — users in a dict (`alice` / `bob` with fixed passwords).

| Path | Contents |
|---|---|
| `environment/Dockerfile`, `environment/entrypoint.sh` | same pattern (no postgres); entrypoint exports `JWT_SECRET=dev-secret-123` **not** set — the app must read env at runtime |
| `environment/app/pyproject.toml` | deps: fastapi, uvicorn[standard], httpx, pytest |
| `environment/app/AGENTS.md` | same discipline doc |
| `environment/app/jwtauth.py` | **vulnerable** — verbatim below |
| `environment/app/routers/auth.py` | `POST /login {"username","password"}` → 200 `{"token": ...}` or 401 |
| `environment/app/routers/me.py` | `GET /me` reads `Authorization: Bearer <jwt>`, calls `verify()` → `{"sub": payload["sub"]}` or 401 |
| `environment/app/main.py`, `routers/__init__.py` | boilerplate |
| `environment/app/tests/test_api.py` | visible regression: login as alice → `/me` 200 with `{"sub":"alice"}`; bad password 401 |

`environment/app/jwtauth.py` (verbatim):

```python
import base64, hashlib, hmac, json, time

FALLBACK_SECRET = "dev-secret-123"  # VULNERABLE: hardcoded secret


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(payload: dict, secret: str = FALLBACK_SECRET) -> str:
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64u(sig)}"


def verify(token: str) -> dict:
    head_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64u_decode(head_b64))
    payload = json.loads(_b64u_decode(payload_b64))
    if header.get("alg") == "none":
        return payload  # VULNERABLE: alg=none bypass
    sig = hmac.new(FALLBACK_SECRET.encode(), f"{head_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if sig != _b64u_decode(sig_b64):  # VULNERABLE: hardcoded secret, non-constant-time compare
        raise PermissionError("bad signature")
    return payload  # VULNERABLE: no exp validation
```

## 4. Verifier (`tests/`)

`tests/test.sh`: clone of the `fix-sqli-login` harness; **`export JWT_SECRET=verifier-test-secret`**
before starting uvicorn and before pytest; reward 0/1.

`tests/conftest.py` (verifier-side signing with the runtime secret):

```python
import base64, hashlib, hmac, json, os, time

SECRET = os.environ["JWT_SECRET"]  # "verifier-test-secret"

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def make_jwt(header: dict, payload: dict, secret: str = SECRET, alg: str = "HS256") -> str:
    head = _b64u(json.dumps(header, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none":
        return f"{head}.{body}."
    digest = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), digest).digest()
    return f"{head}.{body}.{_b64u(sig)}"
```

`tests/test_jwt.py` (hidden verifier — exact expected values):

```python
def test_valid_token_accepted(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "exp": int(time.time()) + 600})
    r = client.get("/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and r.json() == {"sub": "alice"}

def test_none_alg_rejected(client):
    tok = make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "attacker", "exp": int(time.time()) + 600}, alg="none")
    r = client.get("/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401, "alg=none bypass still works"

def test_hs512_alg_confusion_rejected(client):
    tok = make_jwt({"alg": "HS512", "typ": "JWT"}, {"sub": "attacker", "exp": int(time.time()) + 600}, alg="HS512")
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_expired_token_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "exp": int(time.time()) - 10})
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_missing_exp_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice"})
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_non_numeric_exp_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "exp": "soon"})
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_old_hardcoded_secret_signature_rejected(client):
    tok = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "attacker", "exp": int(time.time()) + 600},
                   secret="dev-secret-123")
    assert client.get("/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

def test_login_flow_still_works(client):
    r = client.post("/login", json={"username": "alice", "password": "pw-alice"})
    assert r.status_code == 200
    me = client.get("/me", headers={"Authorization": f"Bearer {r.json()['token']}"})
    assert me.status_code == 200 and me.json() == {"sub": "alice"}
```

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `jwtauth.py`, `routers/me.py`, `routers/auth.py`; identify alg=none branch, hardcoded
   secret, missing exp check.
2. Rewrite `jwtauth.py`:
   ```python
   import os, time
   SECRET = os.environ.get("JWT_SECRET")
   if not SECRET:
       raise RuntimeError("JWT_SECRET must be set")

   def verify(token: str) -> dict:
       head_b64, payload_b64, sig_b64 = token.split(".")
       header = json.loads(_b64u_decode(head_b64))
       if header.get("alg") != "HS256":
           raise PermissionError("alg not allowed")
       expected = hmac.new(SECRET.encode(), f"{head_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
       if not hmac.compare_digest(expected, _b64u_decode(sig_b64)):
           raise PermissionError("bad signature")
       payload = json.loads(_b64u_decode(payload_b64))
       exp = payload.get("exp")
       if not isinstance(exp, (int, float)) or exp <= time.time():
           raise PermissionError("expired")
       return payload
   ```
3. `sign()` default secret → `SECRET` from env; `routers/me.py` catches `PermissionError` → 401.
4. Restart with `JWT_SECRET=verifier-test-secret uvicorn main:app ...`; `pytest tests/ -q`.

## 6. Expected agent difficulty profile

- **Steps:** ~12–20 tool calls.
- **Small-model failure modes:**
  - Rejects `alg=none` but still trusts any HS256 signature with the hardcoded fallback →
    `test_old_hardcoded_secret_signature_rejected` fails.
  - Rejects non-HS256 by trying to *verify* HS512 (needs sha512 support it may not implement)
    instead of a simple allowlist check.
  - `exp` handling: allows string `"1e9"`, or compares `exp < now` with an off-by-one that
    rejects the valid +600s token.
  - `os.environ["JWT_SECRET"]` at import time breaks when the agent restarts uvicorn *without*
    the env var (fail-closed crash) — agent must replicate the harness env when self-testing.
  - Breaking the visible login regression by moving `sign()` to the env secret while self-testing
    with no `JWT_SECRET` set.
