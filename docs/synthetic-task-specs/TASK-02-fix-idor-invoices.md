# TASK-02 — fix-idor-invoices

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A01 Broken Access Control** (IDOR, CWE-639) |
| Difficulty | medium |
| Deliverable | Fixed FastAPI code + green pytest regression on the live service |
| Pattern cloned from | `local_task/fix-sqli-login` (SWE-fix + hidden pytest on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-idor-invoices"
description = "Fix broken object-level authorization (IDOR) in a FastAPI invoice service while keeping the visible regression suite green."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "idor", "owasp-a01", "authorization", "fastapi", "postgresql", "fix"]

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
You are working in `/app`. The application is a FastAPI service backed by PostgreSQL.

The API trusts an `X-User-Id` header that is set by the edge gateway after authentication
(seed users: `alice=1`, `bob=2`, `admin=9`).

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. Authorization
requirements:

- A user must only be able to read, list, and pay **their own** invoices.
- Responses about objects a user does not own must not reveal their existence (use 404).
- Do not introduce new dependencies beyond what is already declared in `pyproject.toml`.
````

## 3. `environment/` composition

Same container pattern as `fix-sqli-login` (PostgreSQL + uvicorn + keep-alive entrypoint,
verifier owns the restart). Fork of the `insecure-api-app` skeleton.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | identical to `fix-sqli-login` (installs postgresql, copies app, entrypoint) |
| `environment/entrypoint.sh` | starts postgres, creates `appuser`/`appdb`, `uvicorn main:app &`, `tail -f /dev/null` |
| `environment/app/pyproject.toml` | same deps as original: fastapi, uvicorn[standard], asyncpg, httpx, pytest |
| `environment/app/AGENTS.md` | same discipline doc as original |
| `environment/app/db.py` | `get_pool()` + `init_schema()` executed at startup: creates `users(id INT PK, username TEXT)` and `invoices(id INT PK, owner_id INT REFERENCES users(id), client_name TEXT, amount_cents BIGINT, status TEXT)` and seeds: users `(1,'alice'),(2,'bob'),(9,'admin')`; invoices `(101,1,'Acme Corp',125000,'open')`, `(102,1,'Globex',89000,'open')`, `(201,2,'Initech',45000,'open')`, `(202,2,'Umbrella',76000,'open')` |
| `environment/app/routers/auth.py` | `GET /healthz` only (header-auth model, no login endpoint) |
| `environment/app/routers/invoices.py` | **three IDOR flaws** — see fragment |
| `environment/app/routers/__init__.py`, `models.py`, `main.py` | boilerplate incl. router registration |
| `environment/app/tests/test_api.py` | visible regression: healthz 200; alice lists exactly 2 invoices; alice pays own invoice 102 → becomes `paid`; unknown id 999 → 404 |

`environment/app/routers/invoices.py` (key vulnerable fragment):

```python
@router.get("/invoices/{invoice_id}")
async def get_invoice(invoice_id: int, x_user_id: int = Header(...)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, owner_id, client_name, amount_cents, status "
            "FROM invoices WHERE id = $1",
            invoice_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)  # VULNERABLE: no ownership check (IDOR)


@router.get("/invoices")
async def list_invoices(x_user_id: int = Header(...)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, owner_id, client_name, amount_cents, status FROM invoices"
        )  # VULNERABLE: returns every tenant's invoices
    return [dict(r) for r in rows]


@router.post("/invoices/{invoice_id}/pay")
async def pay_invoice(invoice_id: int, x_user_id: int = Header(...)):
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE invoices SET status = 'paid' WHERE id = $1", invoice_id
        )  # VULNERABLE: any user can pay anyone's invoice
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="Invoice not found")
    return {"status": "paid"}
```

## 4. Verifier (`tests/`)

`tests/test.sh`: byte-compatible clone of `fix-sqli-login/tests/test.sh` — kill stale uvicorn,
recreate `appdb`, start `uvicorn main:app` from `/app` with `DATABASE_URL`, wait for `/healthz`,
run `pytest /tests`, write 0/1 to `/logs/verifier/reward.txt`.

`tests/conftest.py`:

```python
import httpx, pytest

@pytest.fixture
def client() -> httpx.Client:
    return httpx.Client(base_url="http://127.0.0.1:8000", timeout=10.0)
```

`tests/test_idor.py` (hidden verifier — exact expected values):

```python
ALICE = {"X-User-Id": "1"}
BOB = {"X-User-Id": "2"}

def test_owner_still_reads_own_invoice(client):
    r = client.get("/invoices/101", headers=ALICE)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == 101 and body["owner_id"] == 1
    assert body["amount_cents"] == 125000 and body["status"] == "open"

def test_other_users_invoice_not_readable(client):
    r = client.get("/invoices/101", headers=BOB)
    assert r.status_code in (403, 404), f"IDOR read still works: {r.status_code} {r.text}"

def test_list_is_filtered_to_own_invoices(client):
    r = client.get("/invoices", headers=BOB)
    assert r.status_code == 200
    ids = sorted(item["id"] for item in r.json())
    assert ids == [201, 202], f"bob sees foreign invoices: {ids}"

def test_cannot_pay_others_invoice(client):
    r = client.post("/invoices/101/pay", headers=BOB)
    assert r.status_code in (403, 404)
    after = client.get("/invoices/101", headers=ALICE)
    assert after.json()["status"] == "open", "bob's pay flipped alice's invoice"

def test_owner_pays_own_invoice(client):
    r = client.post("/invoices/102/pay", headers=ALICE)
    assert r.status_code == 200
    assert client.get("/invoices/102", headers=ALICE).json()["status"] == "paid"
```

Plus a hidden copy of the visible regression (`tests/test_regression.py`) to catch over-breaking.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. `grep -rn "VULNERABLE\|owner_id" /app/routers/invoices.py`; read the file.
2. Patch `get_invoice`:
   ```python
   if row is None or row["owner_id"] != x_user_id:
       raise HTTPException(status_code=404, detail="Invoice not found")
   ```
3. Patch `list_invoices`:
   ```python
   rows = await conn.fetch(
       "SELECT id, owner_id, client_name, amount_cents, status "
       "FROM invoices WHERE owner_id = $1", x_user_id,
   )
   ```
4. Patch `pay_invoice`:
   ```python
   result = await conn.execute(
       "UPDATE invoices SET status = 'paid' WHERE id = $1 AND owner_id = $2",
       invoice_id, x_user_id,
   )
   ```
5. `pkill -f "uvicorn main:app" || true`; restart uvicorn; `pytest tests/ -q` → all green.

`solution/solve.sh` applies the three replacements with the same `pathlib.Path(...).replace(...)`
technique as `fix-sqli-login/solution/solve.sh`, restarts the service, waits for `/healthz`,
then runs `pytest tests/ -q`.

## 6. Expected agent difficulty profile

- **Steps:** ~10–16 tool calls (read code, 3 edits, restart service, run tests, maybe 1 fix loop).
- **Small-model failure modes:**
  - Fixes the read endpoint but forgets `pay_invoice` (caught by `test_cannot_pay_others_invoice`).
  - Forgets the list filter or returns `owner_id`-filtered data only for alice (bob's list check).
  - Returns 403 with a body that leaks the invoice; tests accept 403/404 so this is safe, but a
    model that *renames* the header or requires a token breaks the visible regression.
  - Leaves a stale uvicorn process running with old code → appears "unfixed" until restart;
    the AGENTS.md stale-process hint covers this.
