# TASK-21 — fix-login-throttling-session

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A07 Authentication Failures** (CWE-307, CWE-330, CWE-384, CWE-613) |
| Difficulty | medium |
| Deliverable | Patched source; hidden pytest suite runs against the live service |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden tests on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-login-throttling-session"
description = "A FastAPI login endpoint has no brute-force protection, predictable session tokens, session fixation and a never-expiring remember-me cookie. Fix so hidden auth-hardening tests pass."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "owasp-a07", "rate-limit", "session-fixation", "remember-me", "fix"]

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
You are working in `/app`. The application is a FastAPI service with cookie
sessions. A security review flagged the login flow:

1. No throttling/lockout: password guessing is unlimited.
2. Session tokens are generated with a weak PRNG (`random`) and are
   predictable/short.
3. Session fixation: the pre-auth anonymous session id is kept after login.
4. The "remember me" cookie never expires.

Fix the application so that:

- After 5 FAILED logins for the same username, further attempts for that
  username return 429 (per-attempt; window: any 5 failures). Successful
  login resets the counter. The lockout state must survive service restart
  within the container lifetime.
- Session tokens after login MUST be freshly generated with a CSPRNG,
  at least 128 bits of entropy (32 hex chars) and different between two
  logins of the same user.
- Remember-me cookie lifetime MUST be at most 7 days (max_age seconds,
  integer in response Set-Cookie).
- Keep the public API contract unchanged (paths, fields, `/healthz`).

Users are seeded in-memory: `ops` / `Ops!Pass42`, `viewer` / `View!Pass42`.
The service is started by the harness (`uvicorn main:app` on port 8000).
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/Dockerfile` | Standard recipe; `RUN mkdir -p /app/data` |
| `environment/entrypoint.sh` | uvicorn + tail (verifier owns restarts) |
| `environment/app/pyproject.toml` | deps: `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pytest>=8` |
| `environment/app/AGENTS.md` | API contract table (below); "hidden tests will harden auth" |
| `environment/app/main.py` | App assembly + **vulnerable auth** — see below |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/routers/sessions.py` | Session cookie helpers (weak token, fixation) |
| `environment/app/tests/test_api.py` | benign regression: `/healthz` 200; correct login 200 sets cookie |
| `environment/app/data/` | empty dir for lockout persistence (sqlite3/JSON allowed) |

`environment/app/main.py` (key fragments):

```python
import random, secrets
from fastapi import FastAPI, Response, HTTPException

app = FastAPI()
_USERS = {"ops": "Ops!Pass42", "viewer": "View!Pass42"}
_failed: dict[str, int] = {}          # in-RAM only, lost on restart

@app.post("/login")
def login(req: LoginRequest, response: Response):
    if _USERS.get(req.username) != req.password:
        return {"status": "denied"}                 # BUG: no counter, no 429, silent fail
    sid = f"{random.randint(0, 10**6):06d}-{req.username}"   # BUG: weak PRNG, low entropy
    response.set_cookie("session", sid)             # BUG: fixation — pre-auth sid kept
    return {"status": "ok"}

@app.post("/remember")
def remember(req: RememberRequest, response: Response):
    response.set_cookie("remember", req.username)   # BUG: no max_age, unsigned
    return {"status": "ok"}
```

## 4. Verifier (`tests/`)

`tests/test.sh`: restart service (fresh lockout state via re-seed), wait `/healthz`,
reward 0/1, pytest.

`tests/test_auth_hardening.py` (hidden verifier):

```python
import re, requests

BASE = "http://127.0.0.1:8000"

def test_healthz(): assert requests.get(f"{BASE}/healthz").status_code == 200

def test_lockout_after_five_failures():
    for i in range(5):
        r = requests.post(f"{BASE}/login", json={"username": "ops", "password": "wrong"})
        assert r.status_code in (200, 401)          # failures may be 200-with-denied or 401
    r6 = requests.post(f"{BASE}/login", json={"username": "ops", "password": "Ops!Pass42"})
    assert r6.status_code == 429, "6th attempt (even correct) must be throttled"

def test_lockout_survives_restart():
    # harness restarts the service between test classes; state must persist
    r = requests.post(f"{BASE}/login", json={"username": "ops", "password": "wrong"})
    assert r.status_code in (200, 401, 429)

def test_other_user_not_locked():
    r = requests.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"})
    assert r.status_code == 200 and r.json()["status"] == "ok"

def test_session_entropy_and_rotation():
    s1 = requests.Session(); s2 = requests.Session()
    t1 = s1.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"}).cookies.get("session")
    t2 = s2.post(f"{BASE}/login", json={"username": "viewer", "password": "View!Pass42"}).cookies.get("session")
    assert t1 and t2 and t1 != t2
    assert re.fullmatch(r"[0-9a-f]{32,}", t1), f"weak token: {t1!r}"

def test_remember_me_expiry():
    r = requests.post(f"{BASE}/remember", json={"username": "viewer"},
                      allow_redirects=False)
    sc = r.headers.get("set-cookie", "")
    m = re.search(r"[Mm]ax-[Aa]ge=(\d+)", sc)
    assert m, f"no max-age in Set-Cookie: {sc!r}"
    assert 0 < int(m.group(1)) <= 7 * 24 * 3600
```

**Grading:** binary 0/1 — all hidden tests green.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Replace `_failed` with sqlite-backed counter table at `/app/data/lockout.db`
   (key: username, count, ts) — survives restart.
2. On failure: increment; if count reaches 5 → all further attempts for that
   username return 429 until a successful login resets to 0.
3. Token: `secrets.token_hex(16)` fresh on every login (never reuse request cookies).
4. Remember-me: `set_cookie("remember", user, max_age=7*24*3600, httponly=True)`.
5. Restart, replay hidden tests.

## 6. Expected agent difficulty profile

- **Steps:** ~12–20 tool calls.
- **Small-model failure modes:**
  - Lockout counts globally, not per-username → `test_other_user_not_locked` red.
  - Lockout stored in RAM → survives-restart test red (harness restarts deliberately).
  - Lockout lets the CORRECT password through on attempt 6 → contract says 429.
  - Token includes username suffix or non-hex chars → regex test fails.
  - `max_age` set only on the session cookie, not remember-me → expiry test fails.
