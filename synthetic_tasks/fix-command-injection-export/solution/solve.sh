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
f = app / "routers" / "export.py"
src = f.read_text()

if "create_subprocess_shell" not in src:
    raise SystemExit("ERROR: vulnerable pattern not found in routers/export.py")

src = src.replace("import asyncio\nimport os\n", "import asyncio\nimport os\nimport re\n", 1)

vulnerable = '''@router.post("/export")
async def export(req: ExportRequest):
    out = f"/tmp/exports/{req.report_id}.{req.format}"
    cmd = (
        f"python3 {APP_DIR}/tools/render.py --report {req.report_id} "
        f"--format {req.format} --out {out}"
    )
    # VULNERABLE: shell interpretation of client-controlled values
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail="render failed")
    return {"output": out}
'''

fixed = '''_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@router.post("/export")
async def export(req: ExportRequest):
    if not _SAFE.fullmatch(req.report_id) or not _SAFE.fullmatch(req.format):
        raise HTTPException(status_code=422, detail="invalid report id or format")
    out = f"/tmp/exports/{req.report_id}.{req.format}"
    # no shell: argv-style exec of the renderer with validated arguments
    proc = await asyncio.create_subprocess_exec(
        "python3", os.path.join(APP_DIR, "tools", "render.py"),
        "--report", req.report_id, "--format", req.format, "--out", out,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise HTTPException(status_code=404, detail="unknown report")
    return {"output": out}
'''

if vulnerable not in src:
    raise SystemExit("ERROR: exact vulnerable export fragment not found")
f.write_text(src.replace(vulnerable, fixed, 1))
print("Patched routers/export.py")
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
