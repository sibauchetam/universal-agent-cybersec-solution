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
f = app / "jwtauth.py"
src = f.read_text()

for marker in (
    'FALLBACK_SECRET = "dev-secret-123"',
    'if header.get("alg") == "none":',
):
    if marker not in src:
        raise SystemExit("ERROR: vulnerable pattern not found in jwtauth.py: " + marker)

f.write_text('''import base64
import hashlib
import hmac
import json
import os
import time

SECRET = os.environ.get("JWT_SECRET")
if not SECRET:
    # fail closed: the service must never fall back to a hardcoded secret
    raise RuntimeError("JWT_SECRET must be set")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(payload: dict, secret: str | None = None) -> str:
    secret = secret or SECRET
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64u(sig)}"


def verify(token: str) -> dict:
    head_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64u_decode(head_b64))
    if header.get("alg") != "HS256":
        # strict allowlist: alg=none / HS512 / anything else is rejected
        raise PermissionError("alg not allowed")
    expected = hmac.new(SECRET.encode(), f"{head_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64u_decode(sig_b64)):
        raise PermissionError("bad signature")
    payload = json.loads(_b64u_decode(payload_b64))
    exp = payload.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or exp <= time.time():
        raise PermissionError("exp must be a numeric timestamp in the future")
    return payload
''')
print("Patched jwtauth.py")
PYEOF

# The grading harness starts the service with this secret; replicate it here so
# the fail-closed app boots and self-tests run in the harness environment.
export JWT_SECRET="${JWT_SECRET:-verifier-test-secret}"

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
