#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
export APP_DIR
APP_DB="${APP_DB:-${APP_DIR}/app.db}"
export APP_DB
APP_LOG="${APP_LOG:-${APP_DIR}/app.log}"
export APP_LOG
PYTHON="${PYTHON:-python3}"

python3 - <<'PYEOF'
import os
import pathlib

app = pathlib.Path(os.environ.get("APP_DIR", "/app"))
f = app / "main.py"
src = f.read_text()

vuln_handler = '''@app.exception_handler(Exception)
async def raw_error(request: Request, exc: Exception):
    # BUG 1: leaks exception text + traceback to the client
    return JSONResponse(status_code=500,
                        content={"error": str(exc), "trace": traceback.format_exc()})
'''
fixed_handler = '''@app.exception_handler(Exception)
async def safe_error(request: Request, exc: Exception):
    # full details stay server-side (stderr); clients get a generic body only
    logging.getLogger(__name__).error(
        "unhandled error on %s %s", request.method, request.url.path, exc_info=exc
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
'''

vuln_middleware = '''@app.middleware("http")
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
'''
fixed_middleware = '''@app.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path.startswith("/orders"):
        role = None
        try:
            tok = request.headers.get("Authorization", "").removeprefix("Bearer ")
            role = VALID_TOKENS.get(tok)
        except Exception:
            role = None  # fail CLOSED on any internal error
        if role is None:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
        request.state.role = role
    return await call_next(request)
'''

for marker in (vuln_handler, vuln_middleware):
    if marker not in src:
        raise SystemExit("ERROR: vulnerable fragment not found in main.py")

src = src.replace(vuln_handler, fixed_handler, 1)
src = src.replace(vuln_middleware, fixed_middleware, 1)
f.write_text(src)
print("Patched main.py (fail-closed auth, non-disclosing 500s)")
PYEOF

pkill -f "uvicorn main:app" || true
sleep 1
: > "$APP_LOG"
cd "$APP_DIR"
"$PYTHON" -m uvicorn main:app --host 127.0.0.1 --port 8000 >> "$APP_LOG" 2>&1 &

for _ in $(seq 1 30); do
    if "$PYTHON" - <<'PYEOF'
import urllib.request
urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=1).read()
PYEOF
    then break; fi
    sleep 1
done

"$PYTHON" - <<'PYEOF'
import urllib.request
urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=2).read()
print("service healthy")
PYEOF

"$PYTHON" -m pytest tests/ -q
echo "All tests pass."
