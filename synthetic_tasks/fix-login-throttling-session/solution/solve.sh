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

# ---- 1) apply the auth-hardening patches ------------------------------------
"$PY" - <<'PYEOF'
import os
import pathlib

app = pathlib.Path(os.environ["APP_DIR"])

mf = app / "main.py"
src = mf.read_text()

old_imports = '''import random

from fastapi import FastAPI, Response
from pydantic import BaseModel

from routers.sessions import weak_session_token'''
new_imports = '''import os
import sqlite3

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

from routers.sessions import new_session_token, set_remember_cookie, set_session_cookie'''

old_state = '''_USERS = {"ops": "Ops!Pass42", "viewer": "View!Pass42"}
_failed: dict[str, int] = {}          # in-RAM only, lost on restart'''
new_state = '''_USERS = {"ops": "Ops!Pass42", "viewer": "View!Pass42"}

# Lockout counters are persisted in SQLite so they survive service restarts
# within the container lifetime (DB file location follows APP_DIR / APP_DB).
APP_DIR = os.environ.get("APP_DIR", "/app")
DB_PATH = os.environ.get("APP_DB", os.path.join(APP_DIR, "app.db"))
MAX_FAILURES = 5


def _lockout_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS lockout ("
        "username TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0)"
    )
    conn.commit()
    return conn'''

old_login = '''@app.post("/login")
def login(req: LoginRequest, response: Response):
    if _USERS.get(req.username) != req.password:
        return {"status": "denied"}                 # BUG: no counter, no 429, silent fail
    sid = weak_session_token(req.username)          # BUG: weak PRNG, low entropy
    response.set_cookie("session", sid)             # BUG: fixation — pre-auth sid kept
    return {"status": "ok"}'''
new_login = '''@app.post("/login")
def login(req: LoginRequest, response: Response):
    conn = _lockout_db()
    try:
        row = conn.execute(
            "SELECT failures FROM lockout WHERE username=?", (req.username,)
        ).fetchone()
        if row and row[0] >= MAX_FAILURES:
            # Locked: even the correct password is throttled (contract: 429).
            raise HTTPException(status_code=429, detail="too many failed logins")
        if _USERS.get(req.username) != req.password:
            conn.execute(
                "INSERT INTO lockout (username, failures) VALUES (?, 1) "
                "ON CONFLICT(username) DO UPDATE SET failures = failures + 1",
                (req.username,),
            )
            conn.commit()
            return {"status": "denied"}
        # Successful login resets the per-username counter.
        conn.execute(
            "INSERT INTO lockout (username, failures) VALUES (?, 0) "
            "ON CONFLICT(username) DO UPDATE SET failures = 0",
            (req.username,),
        )
        conn.commit()
    finally:
        conn.close()
    sid = new_session_token()      # fresh CSPRNG token every login (no fixation)
    set_session_cookie(response, sid)
    return {"status": "ok"}'''

old_remember = '''@app.post("/remember")
def remember(req: RememberRequest, response: Response):
    response.set_cookie("remember", req.username)   # BUG: no max_age, unsigned
    return {"status": "ok"}'''
new_remember = '''@app.post("/remember")
def remember(req: RememberRequest, response: Response):
    set_remember_cookie(response, req.username)     # max_age capped at 7 days
    return {"status": "ok"}'''

for old, new, what in (
    (old_imports, new_imports, "imports"),
    (old_state, new_state, "lockout storage"),
    (old_login, new_login, "login"),
    (old_remember, new_remember, "remember"),
):
    if old not in src:
        raise SystemExit(f"ERROR: vulnerable pattern not found in main.py: {what}")
    src = src.replace(old, new, 1)
mf.write_text(src)
print("Patched main.py (sqlite lockout, 429, CSPRNG token, remember max_age)")

sf = app / "routers" / "sessions.py"
ssrc = sf.read_text()
if "def weak_session_token" not in ssrc:
    raise SystemExit("ERROR: sessions.py layout changed")
FIXED_SESSIONS = '''# Session cookie helpers (hardened).
import secrets

SESSION_COOKIE = "session"
REMEMBER_COOKIE = "remember"

REMEMBER_MAX_AGE = 7 * 24 * 3600  # security backlog cap: at most 7 days


def new_session_token() -> str:
    # Fresh CSPRNG token per login: 128 bits of entropy, 32 hex chars.
    return secrets.token_hex(16)


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(SESSION_COOKIE, token, httponly=True)


def set_remember_cookie(response, username: str) -> None:
    response.set_cookie(
        REMEMBER_COOKIE, username, max_age=REMEMBER_MAX_AGE, httponly=True
    )
'''
sf.write_text(FIXED_SESSIONS)
print("Patched routers/sessions.py (CSPRNG token, cookie expiry)")
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
