# TASK-15 — fix-giftcard-negative-transfer

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A06 Insecure Design** (CWE-840, CWE-841, CWE-20 business-logic variant) |
| Difficulty | **hard** |
| Deliverable | Patched source; hidden pytest suite runs against the live service |
| Pattern cloned from | `local_task/fix-sqli-search` (SWE-fix + hidden tests on live service) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/fix-giftcard-negative-transfer"
description = "A payments demo has business-logic flaws: negative-amount transfers increase balances, gift cards redeemable repeatedly, client-controlled discount over 100%. Fix the logic so hidden invariant tests pass."
authors = []
keywords = []

[metadata]
difficulty = "hard"
category = "security"
tags = ["local", "owasp-a06", "insecure-design", "business-logic", "race", "payments", "fix"]

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
You are working in `/app`. The application is a FastAPI payments demo (wallets,
gift cards, checkout). QA confirmed the security backlog items below; fix the
application logic so that all invariants hold. Keep the public API contract
(paths, request/response fields) unchanged.

Reported defects:

1. Money transfer: sending a negative amount INCREASES the sender balance.
2. Gift card redemption: the same card code can be redeemed repeatedly.
3. Checkout: the discount percentage is taken from the request and values
   above 100 make the total negative.
4. Re-submitting the same transfer (retry) applies it twice.

Invariants that must hold after your fix:

- Transfer amount must be > 0; sender balance must never go below 0.
- A gift card can be redeemed exactly once (state persists across restarts
  within the container lifetime).
- Discount is validated server-side in [0, 100]; total is never negative;
  prices come from the server, never the client.
- A retried transfer with the same client request id must be idempotent
  (applied once).

The service is started by the harness (`uvicorn main:app` on port 8000).
A `GET /healthz` endpoint must keep working.
````

## 3. `environment/` composition

SQLite file DB at `/app/data/payments.db` (survives verifier-driven restarts),
`sqlite3` stdlib only — no ORM.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | Standard recipe; additionally `RUN mkdir -p /app/data` |
| `environment/entrypoint.sh` | `uvicorn main:app --host 0.0.0.0 --port 8000 &`, `tail -f /dev/null` (verifier owns restarts) |
| `environment/app/pyproject.toml` | deps: `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pytest>=8` |
| `environment/app/AGENTS.md` | Payments demo context; API contract table (below); "do not break /healthz" |
| `environment/app/main.py` | App assembly + startup seeding: wallets `alice=1000`, `bob=250`, `carol=40`; gift cards `GIFT-SPRING-10` (value 10, unused), `GIFT-DEAD-5` (value 5, **already used=True** — used once at seed time); `/healthz` |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/routers/wallets.py` | **Vulnerable transfer + redeem** — see below |
| `environment/app/routers/checkout.py` | **Vulnerable checkout** — see below |
| `environment/app/tests/test_api.py` | benign regression: `/healthz` 200; transfer 10 alice→bob returns 200 |

`environment/app/routers/wallets.py` (key fragments):

```python
@router.post("/transfer")
def transfer(req: TransferRequest):        # {from, to, amount: float, request_id: str|None}
    con = get_db()
    sender = con.execute("SELECT balance FROM wallets WHERE user=?", (req.from_,)).fetchone()
    if not sender:
        raise HTTPException(404, "unknown sender")
    new_balance = sender[0] - req.amount   # negative amount => balance INCREASES
    con.execute("UPDATE wallets SET balance=? WHERE user=?", (new_balance, req.from_))
    con.execute("UPDATE wallets SET balance=balance+? WHERE user=?", (req.amount, req.to))
    con.commit()
    return {"status": "ok", "balance": new_balance}

@router.post("/giftcard/redeem")
def redeem(req: RedeemRequest):            # {code, for_user}
    con = get_db()
    row = con.execute("SELECT value, used FROM giftcards WHERE code=?", (req.code,)).fetchone()
    if not row:
        raise HTTPException(404, "unknown card")
    con.execute("UPDATE wallets SET balance=balance+? WHERE user=?", (row[0], req.for_user))
    # BUG: `used` is never set; GIFT-DEAD-5's seed `used=1` is never checked either
    con.commit()
    return {"status": "ok", "value": row[0]}
```

`environment/app/routers/checkout.py` (key fragments):

```python
CATALOG = {"tshirt": 25.0, "mug": 12.5}    # server-side prices

@router.post("/checkout")
def checkout(req: CheckoutRequest):        # {item, discount_pct: float}  <-- client-controlled
    price = CATALOG[req.item]
    total = price * (1 - req.discount_pct / 100.0)   # discount_pct=150 => negative total
    return {"total": round(total, 2)}
```

## 4. Verifier (`tests/`)

`tests/test.sh`: same harness family as `fix-sqli-search` — kill stale uvicorns, restart
service from `/app` (verifier owns restart), wait `/healthz`, reward 0/1, pytest.

`tests/test_invariants.py` (hidden verifier — runs against live service on 127.0.0.1:8000):

```python
import requests

BASE = "http://127.0.0.1:8000"

def _bal(user):
    return requests.get(f"{BASE}/wallets/{user}").json()["balance"]

def test_healthz(): assert requests.get(f"{BASE}/healthz").status_code == 200

def test_negative_transfer_rejected():
    before = _bal("alice")
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": -500, "request_id": "t-neg"})
    assert r.status_code >= 400
    assert _bal("alice") == before

def test_zero_transfer_rejected():
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": 0, "request_id": "t-zero"})
    assert r.status_code >= 400

def test_overdraft_blocked():
    r = requests.post(f"{BASE}/transfer",
                      json={"from": "carol", "to": "alice", "amount": 10000, "request_id": "t-od"})
    assert r.status_code >= 400 and _bal("carol") == 40

def test_giftcard_single_use():
    r1 = requests.post(f"{BASE}/giftcard/redeem", json={"code": "GIFT-SPRING-10", "for_user": "bob"})
    assert r1.status_code == 200
    r2 = requests.post(f"{BASE}/giftcard/redeem", json={"code": "GIFT-SPRING-10", "for_user": "bob"})
    assert r2.status_code >= 400
    assert requests.post(f"{BASE}/giftcard/redeem",
                         json={"code": "GIFT-DEAD-5", "for_user": "bob"}).status_code >= 400

def test_discount_bounds_and_server_pricing():
    assert requests.post(f"{BASE}/checkout",
                         json={"item": "tshirt", "discount_pct": 150}).status_code >= 400
    ok = requests.post(f"{BASE}/checkout", json={"item": "tshirt", "discount_pct": 20}).json()
    assert ok["total"] == 20.0                      # server catalog price honored
    bad = requests.post(f"{BASE}/checkout", json={"item": "tshirt", "discount_pct": -5})
    assert bad.status_code >= 400

def test_transfer_idempotent():
    b = _bal("alice")
    for _ in range(3):
        requests.post(f"{BASE}/transfer",
                      json={"from": "alice", "to": "bob", "amount": 5, "request_id": "idem-1"})
    assert _bal("alice") == b - 5
```

**Grading:** binary 0/1 — all hidden tests green (balance seeding is deterministic,
tests reset DB by restarting the container image state via `entrypoint.sh` re-seed).

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read routers; identify 4 defects.
2. `transfer`: `if req.amount <= 0: raise HTTPException(422)`; fetch balances of both
   parties, `if sender_balance < req.amount: raise HTTPException(400)`; wrap in a single
   transaction; idempotency table `request_ids(id TEXT PRIMARY KEY)` — insert-or-ignore
   before applying, skip if already present.
3. `redeem`: single `UPDATE giftcards SET used=1 WHERE code=? AND used=0` — check
   `rowcount`; reject unknown/already-used with 409/422.
4. `checkout`: validate `0 <= discount_pct <= 100` else 422; keep server catalog only.
5. Restart service, replay the hidden test list manually, fix residuals.

## 6. Expected agent difficulty profile

- **Steps:** ~15–25 tool calls (multi-file fix + live verification loop).
- **Small-model failure modes:**
  - Fixes only the sign check and misses used-flag check + idempotency (2 tests still red).
  - Breaks the response contract (e.g., 422 vs 400 is fine, but returning `{"total": -x}`
    with 200 is not) — hidden tests assert status >= 400.
  - Validates discount but lets client pass `price` — test asserts server catalog price.
  - Idempotency implemented per-(from,to,amount) instead of per-request_id → retries with
    same request_id double-apply; or idempotency blocks *all* repeats forever including
    legitimate new transfers with different request_id.
  - Concurrency-unsafe `used` check (`SELECT` then `UPDATE`) passes single-thread tests but
    is flagged in review; single-statement conditional UPDATE is the reference fix.
