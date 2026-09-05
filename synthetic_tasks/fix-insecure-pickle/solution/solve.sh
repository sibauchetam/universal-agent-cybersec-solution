#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
export APP_DIR
python3 - <<'PYEOF'
import pathlib

f = pathlib.Path(__import__("os").environ["APP_DIR"] + "/routers/jobs.py")
src = f.read_text()
src = src.replace("import base64, pickle\n", "import base64\nimport json\n", 1)
start = src.index('@router.post("/jobs/import")')
end = src.index('@router.post("/jobs")')
fixed = '''@router.post("/jobs/import")
async def import_job(req: ImportRequest):
    try:
        raw = base64.b64decode(req.blob_b64, validate=True)
        job = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="bad blob")
    if not isinstance(job, dict) or set(job) != {"name", "priority", "params"}:
        raise HTTPException(status_code=422, detail="invalid job schema")
    if not isinstance(job["name"], str) or not (1 <= len(job["name"]) <= 128):
        raise HTTPException(status_code=422, detail="invalid name")
    if isinstance(job["priority"], bool) or not isinstance(job["priority"], int) or not (0 <= job["priority"] <= 9):
        raise HTTPException(status_code=422, detail="invalid priority")
    if not isinstance(job["params"], dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in job["params"].items()
    ):
        raise HTTPException(status_code=422, detail="invalid params")
    _JOBS.append(job)
    return {"imported": job["name"]}


'''
src = src[:start] + fixed + src[end:]
f.write_text(src)
print("Patched /app/routers/jobs.py")
PYEOF
cd "$APP_DIR"
PYTHONPATH="$APP_DIR" pytest tests/ -q
echo "All tests pass."
