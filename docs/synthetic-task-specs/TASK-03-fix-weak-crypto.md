# TASK-03 — fix-weak-crypto

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A02 Cryptographic Failures** (CWE-327/759/916) |
| Difficulty | **hard** |
| Deliverable | Fixed code + green pytest regression; hidden verifier pins exact hash/token formats |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden pytest on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-weak-crypto"
description = "Fix cryptographic failures in a FastAPI identity service: MD5 passwords, predictable tokens, hashes in logs, plus lazy migration of legacy users."
authors = []
keywords = []

[metadata]
difficulty = "hard"
category = "security"
tags = ["local", "owasp-a02", "cryptography", "pbkdf2", "md5", "fastapi", "postgresql", "fix"]

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

[verifier.env]

[environment.env]

[solution.env]
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app`. The application is a FastAPI identity service backed by
PostgreSQL.

A previous penetration test flagged critical cryptographic failures. Fix all of them:

1. Passwords are hashed with unsalted MD5. Re-implement hashing with PBKDF2-HMAC-SHA256
   via `hashlib.pbkdf2_hmac`, at least **100,000 iterations**, and a fresh random
   **16-byte salt** (`secrets`). Store hashes in exactly this format:
   `pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`
2. Existing MD5 users must still be able to log in. On a successful login against a
   legacy MD5 hash, transparently rehash the stored password to the new format
   (lazy migration) so the stored value no longer looks like an MD5 hex digest.
3. Session tokens are currently base64 of `"<user_id>:<expiry>"` — predictable and
   replayable. Issue `secrets.token_urlsafe(32)` tokens instead; two logins must never
   produce the same token.
4. Password comparison must be constant-time (`hmac.compare_digest`).
5. Password hashes must never appear in application logs.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `hashlib`, `hmac`, `secrets` are sufficient).
````

## 3. `environment/` composition

Same container pattern as `fix-sqli-login` (PostgreSQL + uvicorn + keep-alive entrypoint).

| Path | Contents |
|---|---|
| `environment/Dockerfile`, `environment/entrypoint.sh` | identical to `fix-sqli-login` |
| `environment/app/pyproject.toml` | deps: fastapi, uvicorn[standard], asyncpg, httpx, pytest |
| `environment/app/AGENTS.md` | same discipline doc |
| `environment/app/security.py` | **vulnerable crypto core** — see fragment |
| `environment/app/db.py` | schema `users(id SERIAL PK, email TEXT UNIQUE, password_hash TEXT, created_at TIMESTAMPTZ)`; seeds `alice@example.com` with MD5 of `AlicePass7!` = `5bc47a5d8941ad4fce902984d13f4cd1` and `carol@example.com` with MD5 of `LegacyPass9!` = `ec6b77b99c274f803358001c0ec9dccf` |
| `environment/app/routers/auth.py` | `POST /register`, `POST /login`, `GET /me` — **logs the hash on login** — see fragment |
| `environment/app/routers/__init__.py`, `main.py` | boilerplate |
| `environment/app/tests/test_api.py` | visible regression: register dave → login dave → `/me` returns email; wrong password → 401 |

`environment/app/security.py` (vulnerable, verbatim):

```python
import base64, hashlib, time


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: unsalted MD5


def verify_password(password: str, stored: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == stored  # VULNERABLE: not constant-time


def issue_token(user_id: int) -> str:
    expiry = int(time.time()) + 3600
    return base64.b64encode(f"{user_id}:{expiry}".encode()).decode()  # VULNERABLE: predictable token
```

`environment/app/routers/auth.py` (vulnerable login fragment):

```python
@router.post("/login")
async def login(req: LoginRequest):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id, email, password_hash FROM users WHERE email = $1", req.email)
    if row is None or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    logger.info("login success user=%s hash=%s", row["email"], row["password_hash"])  # VULNERABLE: hash in logs
    return {"token": issue_token(row["id"]), "email": row["email"]}
```

## 4. Verifier (`tests/`)

`tests/test.sh`: clone of `fix-sqli-login/tests/test.sh`, **plus** `export APP_LOG=$LOG_DIR/app.log`
(uvicorn stdout is redirected there) and `DATABASE_URL` exported for the test process.

`tests/conftest.py`: httpx client fixture + asyncpg helper:

```python
import asyncio, os, asyncpg, httpx, pytest

@pytest.fixture
def client() -> httpx.Client:
    return httpx.Client(base_url="http://127.0.0.1:8000", timeout=30.0)

@pytest.fixture
def db():
    url = os.environ["DATABASE_URL"]
    return lambda query: asyncio.get_event_loop().run_until_complete(_fetch(url, query))
```

`tests/test_crypto.py` (hidden verifier — exact expected values):

```python
import base64, hashlib, hmac, re

PBKDF2_RE = re.compile(r"^pbkdf2_sha256\$(\d+)\$([0-9a-f]{32,})\$([0-9a-f]{64})$")

def _verify_pbkdf2(password: str, stored: str) -> bool:
    m = PBKDF2_RE.match(stored)
    assert m, f"stored hash has wrong format: {stored[:20]}..."
    iters, salt_hex, hash_hex = int(m.group(1)), m.group(2), m.group(3)
    assert iters >= 100_000, f"iterations too low: {iters}"
    assert len(bytes.fromhex(salt_hex)) >= 16, "salt shorter than 16 bytes"
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iters)
    return hmac.compare_digest(dk.hex(), hash_hex)

def test_register_uses_pbkdf2_format(client, db):
    r = client.post("/register", json={"email": "dave2@example.com", "password": "S3curePass!"})
    assert r.status_code in (200, 201)
    stored = db("SELECT password_hash FROM users WHERE email = 'dave2@example.com'")
    assert _verify_pbkdf2("S3curePass!", stored)

def test_legacy_user_can_login_and_is_migrated(client, db):
    r = client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"})
    assert r.status_code == 200, f"legacy login broken: {r.status_code} {r.text}"
    stored = db("SELECT password_hash FROM users WHERE email = 'carol@example.com'")
    assert not re.fullmatch(r"[0-9a-f]{32}", stored), "legacy MD5 hash was not migrated"
    assert _verify_pbkdf2("LegacyPass9!", stored)
    assert client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"}).status_code == 200

def test_legacy_wrong_password_rejected_and_hash_untouched(client, db):
    r = client.post("/login", json={"email": "alice@example.com", "password": "WrongPass!"})
    assert r.status_code == 401
    stored = db("SELECT password_hash FROM users WHERE email = 'alice@example.com'")
    assert stored == "5bc47a5d8941ad4fce902984d13f4cd1", "failed login must not mutate the hash"

def test_tokens_unique_and_unpredictable(client):
    t1 = client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"}).json()["token"]
    t2 = client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"}).json()["token"]
    assert t1 != t2
    assert len(t1) >= 40
    padded = t1 + "=" * (-len(t1) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert b":" not in decoded, "token still decodes to user_id:expiry"

def test_no_hash_in_logs(client):
    # carol's legacy MD5 hash — must never appear in app logs even during migration
    md5_hex = "ec6b77b99c274f803358001c0ec9dccf"
    client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"})
    log = open(os.environ["APP_LOG"]).read()
    assert md5_hex not in log, "MD5 hash leaked to logs"
    assert "pbkdf2_sha256$" not in log, "password hash leaked to logs"
```

Plus a hidden copy of the visible regression.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `security.py`, `routers/auth.py`, `db.py`; spot MD5, `==` compare, b64 token, hash logging.
2. Rewrite `security.py`:
   ```python
   import hashlib, hmac, secrets

   ITERATIONS = 200_000

   def hash_password(password: str) -> str:
       salt = secrets.token_bytes(16)
       dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
       return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"

   def verify_password(password: str, stored: str) -> bool:
       if re.fullmatch(r"pbkdf2_sha256\$(\d+)\$([0-9a-f]+)\$([0-9a-f]+)", stored):
           _, iters, salt_hex, hash_hex = stored.split("$", 3)
           dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
           return hmac.compare_digest(dk.hex(), hash_hex)
       return hmac.compare_digest(hashlib.md5(password.encode()).hexdigest(), stored)  # legacy md5

   def issue_token(user_id: int) -> str:
       return secrets.token_urlsafe(32)
   ```
3. In `routers/auth.py`: delete the `logger.info(... hash=...)` line; after a successful legacy
   (non-pbkdf2) verify, run `UPDATE users SET password_hash = $1 WHERE id = $2` with
   `hash_password(req.password)`.
4. Restart uvicorn, `pytest tests/ -q` → green; manually verify carol twice (login still 200
   after migration).

## 6. Expected agent difficulty profile

- **Steps:** ~18–30 tool calls (multi-file read, 2 file rewrites, service restart, 2–3 test
  iterations).
- **Small-model failure modes:**
  - Wrong stored format (e.g. `$pbkdf2$` prefix order swapped, base64 salt instead of hex,
    salt below 16 bytes) → strict regex in the verifier fails.
  - Forgets the legacy-MD5 branch entirely → carol cannot log in (`test_legacy_user_can_login_*`).
  - Migration on *failed* login, or migration that overwrites alice's hash on a wrong-password
    attempt → `test_legacy_wrong_password_rejected_and_hash_untouched`.
  - Keeps `logger.info(... hash=...)` → `test_no_hash_in_logs`.
  - Token still derived from user_id (e.g. `token_urlsafe` of a counter) → uniqueness/unpredictability
    test fails.
  - Slow iteration counts (10k) → fails the `>= 100_000` floor.
