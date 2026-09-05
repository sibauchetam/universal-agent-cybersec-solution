#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_DIR="${TESTS_DIR:-$TASK_ROOT/tests}"
APP_DB="${APP_DB:-$APP_DIR/app.db}"
LOG_FILE="${SOLVE_LOG:-/tmp/solve_service.log}"
export APP_DIR APP_DB

# Resolve a python that has the app dependencies (fastapi/uvicorn/pytest).
PY=python3
if ! python3 -c "import fastapi, uvicorn, pytest" >/dev/null 2>&1; then
    if [[ -x /home/z/.venv/bin/python ]] && /home/z/.venv/bin/python -c "import fastapi, uvicorn, pytest" >/dev/null 2>&1; then
        PY=/home/z/.venv/bin/python
    fi
fi
echo "[solve] APP_DIR=$APP_DIR APP_DB=$APP_DB TESTS_DIR=$TESTS_DIR PY=$PY"

# ---- 1) apply the business-logic patches ------------------------------------
"$PY" - <<'PYEOF'
import os
import pathlib

app = pathlib.Path(os.environ["APP_DIR"])

FIXED_TRANSFER = '''@router.post("/transfer")
def transfer(req: TransferRequest):
    if req.amount <= 0:
        raise HTTPException(422, "amount must be positive")
    con = get_db()
    try:
        if req.request_id is not None:
            con.execute("CREATE TABLE IF NOT EXISTS request_ids (id TEXT PRIMARY KEY)")
            cur = con.execute(
                "INSERT OR IGNORE INTO request_ids (id) VALUES (?)",
                (req.request_id,),
            )
            if cur.rowcount == 0:
                # Same client request id: already applied -> idempotent replay.
                row = con.execute(
                    "SELECT balance FROM wallets WHERE user=?", (req.from_,)
                ).fetchone()
                con.commit()
                return {"status": "ok", "balance": row[0] if row else None}
        sender = con.execute("SELECT balance FROM wallets WHERE user=?", (req.from_,)).fetchone()
        if not sender:
            raise HTTPException(404, "unknown sender")
        if sender[0] < req.amount:
            raise HTTPException(400, "insufficient funds")
        recipient = con.execute("SELECT balance FROM wallets WHERE user=?", (req.to,)).fetchone()
        if not recipient:
            raise HTTPException(404, "unknown recipient")
        con.execute("UPDATE wallets SET balance=? WHERE user=?", (sender[0] - req.amount, req.from_))
        con.execute("UPDATE wallets SET balance=balance+? WHERE user=?", (req.amount, req.to))
        con.commit()
        return {"status": "ok", "balance": sender[0] - req.amount}
    finally:
        con.close()


'''

FIXED_REDEEM = '''@router.post("/giftcard/redeem")
def redeem(req: RedeemRequest):
    con = get_db()
    try:
        user = con.execute("SELECT 1 FROM wallets WHERE user=?", (req.for_user,)).fetchone()
        if not user:
            raise HTTPException(404, "unknown user")
        row = con.execute("SELECT value, used FROM giftcards WHERE code=?", (req.code,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown card")
        if row["used"]:
            raise HTTPException(409, "card already used")
        # Single conditional UPDATE makes the used-flip race-safe.
        cur = con.execute("UPDATE giftcards SET used=1 WHERE code=? AND used=0", (req.code,))
        if cur.rowcount != 1:
            raise HTTPException(409, "card already used")
        con.execute("UPDATE wallets SET balance=balance+? WHERE user=?", (row["value"], req.for_user))
        con.commit()
        return {"status": "ok", "value": row["value"]}
    finally:
        con.close()
'''

FIXED_CHECKOUT = '''@router.post("/checkout")
def checkout(req: CheckoutRequest):
    if not (0 <= req.discount_pct <= 100):
        raise HTTPException(422, "discount_pct must be within [0, 100]")
    price = CATALOG.get(req.item)
    if price is None:
        raise HTTPException(404, "unknown item")
    total = price * (1 - req.discount_pct / 100.0)
    return {"total": round(total, 2)}
'''

wf = app / "routers" / "wallets.py"
src = wf.read_text()
marker_t = '@router.post("/transfer")'
marker_r = '@router.post("/giftcard/redeem")'
if marker_t not in src or marker_r not in src:
    raise SystemExit("ERROR: vulnerable wallets.py layout changed")
t_start = src.index(marker_t)
r_start = src.index(marker_r)
if not t_start < r_start:
    raise SystemExit("ERROR: unexpected router order in wallets.py")
wf.write_text(src[:t_start] + FIXED_TRANSFER + FIXED_REDEEM)
print("Patched routers/wallets.py (transfer + redeem)")

cf = app / "routers" / "checkout.py"
csrc = cf.read_text()
marker_c = '@router.post("/checkout")'
if marker_c not in csrc:
    raise SystemExit("ERROR: vulnerable checkout.py layout changed")
cf.write_text(csrc[: csrc.index(marker_c)] + FIXED_CHECKOUT)
print("Patched routers/checkout.py (discount bounds, server pricing)")
PYEOF

# ---- 2) restart the service under our control -------------------------------
pkill -f "uvicorn main:app" >/dev/null 2>&1 || true
sleep 1

cd "$APP_DIR"
"$PY" -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level warning >"$LOG_FILE" 2>&1 &
APP_PID=$!

cleanup() {
    kill "$APP_PID" >/dev/null 2>&1 || true
    wait "$APP_PID" 2>/dev/null || true
}
trap cleanup EXIT

healthy=0
for _ in $(seq 1 30); do
    if ! kill -0 "$APP_PID" 2>/dev/null; then
        echo "[solve] ERROR: service exited during startup; log tail:" >&2
        tail -n 20 "$LOG_FILE" >&2 || true
        exit 1
    fi
    if "$PY" - <<'PYEOF'
import urllib.request
urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=1).read()
PYEOF
    then
        healthy=1
        break
    fi
    sleep 1
done

if [[ "$healthy" != "1" ]]; then
    echo "[solve] ERROR: service did not become healthy" >&2
    exit 1
fi

# ---- 3) hidden verifier suite ------------------------------------------------
cd "$APP_DIR"
"$PY" -m pytest "$TESTS_DIR" -q
echo "[solve] All tests pass."
