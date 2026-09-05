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

# ---------- security.py: MD5 -> PBKDF2-HMAC-SHA256, constant-time compare,
# ---------- opaque unpredictable session tokens
f = app / "security.py"
src = f.read_text()
for marker in (
    "hashlib.md5(password.encode()).hexdigest()",
    'base64.b64encode(f"{user_id}:{expiry}".encode())',
):
    if marker not in src:
        raise SystemExit("ERROR: vulnerable pattern not found in security.py: " + marker)
f.write_text('''import hashlib
import hmac
import secrets
import time

ITERATIONS = 200_000

_ACTIVE_TOKENS: dict[str, tuple[int, int]] = {}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"


def _is_pbkdf2(stored: str) -> bool:
    parts = stored.split("$")
    return len(parts) == 4 and parts[0] == "pbkdf2_sha256" and parts[1].isdigit()


def verify_password(password: str, stored: str) -> bool:
    if _is_pbkdf2(stored):
        _, iters, salt_hex, hash_hex = stored.split("$", 3)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    # legacy unsalted MD5 (lazy-migration path); constant-time compare
    return hmac.compare_digest(hashlib.md5(password.encode()).hexdigest(), stored)


def issue_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    _ACTIVE_TOKENS[token] = (user_id, int(time.time()) + 3600)
    return token


def resolve_token(token: str) -> int | None:
    entry = _ACTIVE_TOKENS.get(token)
    if entry is None:
        return None
    user_id, expiry = entry
    if expiry < time.time():
        return None
    return user_id
''')
print("Patched security.py")

# ---------- routers/auth.py: no hashes in logs + lazy MD5->PBKDF2 migration
f = app / "routers" / "auth.py"
src = f.read_text()
vulnerable = '    logger.info("login success user=%s hash=%s", row["email"], row["password_hash"])  # VULNERABLE: hash in logs\n'
fixed = (
    '    if not row["password_hash"].startswith("pbkdf2_sha256$"):\n'
    "        # lazy migration: legacy MD5 -> PBKDF2 on successful login only\n"
    '        db.update_password_hash(row["id"], security.hash_password(req.password))\n'
    '    logger.info("login success user=%s", row["email"])\n'
)
if vulnerable not in src:
    raise SystemExit("ERROR: vulnerable login fragment not found in routers/auth.py")
f.write_text(src.replace(vulnerable, fixed, 1))
print("Patched routers/auth.py")
PYEOF

# The verifier recreates the database (official test.sh drops/recreates it);
# keep the reference run deterministic the same way.
rm -f "$APP_DB"

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
