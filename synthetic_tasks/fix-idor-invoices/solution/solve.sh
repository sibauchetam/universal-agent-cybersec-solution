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

# ---- 1) apply the ownership patches to routers/invoices.py -----------------
"$PY" - <<'PYEOF'
import os
import pathlib

f = pathlib.Path(os.environ["APP_DIR"]) / "routers" / "invoices.py"
src = f.read_text()

patches = [
    (
        # 1) get_invoice: enforce object-level ownership (hide existence -> 404)
        '''    if row is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)  # VULNERABLE: no ownership check (IDOR)''',
        '''    if row is None or row["owner_id"] != x_user_id:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)''',
    ),
    (
        # 2) list_invoices: only the caller's own invoices
        '''        rows = conn.execute(
            "SELECT id, owner_id, client_name, amount_cents, status FROM invoices"
        ).fetchall()  # VULNERABLE: returns every tenant's invoices
''',
        '''        rows = conn.execute(
            "SELECT id, owner_id, client_name, amount_cents, status "
            "FROM invoices WHERE owner_id = ?",
            (x_user_id,),
        ).fetchall()
''',
    ),
    (
        # 3) pay_invoice: a user can pay only their own invoice
        '''        cur = conn.execute(
            "UPDATE invoices SET status = 'paid' WHERE id = ?",
            (invoice_id,),
        )''',
        '''        cur = conn.execute(
            "UPDATE invoices SET status = 'paid' WHERE id = ? AND owner_id = ?",
            (invoice_id, x_user_id),
        )''',
    ),
]

for old, new in patches:
    if old not in src:
        raise SystemExit("ERROR: vulnerable pattern not found - source may have changed")
    src = src.replace(old, new, 1)

f.write_text(src)
print("Patched routers/invoices.py (3 ownership checks)")
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
