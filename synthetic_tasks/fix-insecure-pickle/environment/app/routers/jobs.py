import base64, pickle
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["jobs"])

_JOBS: list[dict] = []


class ImportRequest(BaseModel):
    blob_b64: str


@router.post("/jobs/import")
async def import_job(req: ImportRequest):
    try:
        job = pickle.loads(base64.b64decode(req.blob_b64))  # VULNERABLE: CWE-502, RCE via __reduce__
    except Exception:
        raise HTTPException(status_code=400, detail="bad blob")
    _JOBS.append(job)
    return {"imported": job["name"]}


@router.post("/jobs")
async def create_job(name: str, priority: int, params: dict[str, str] | None = None):
    job = {"name": name, "priority": priority, "params": params or {}}
    _JOBS.append(job)
    return {"imported": job["name"]}


@router.get("/jobs")
async def list_jobs():
    return [{"name": j["name"], "priority": j["priority"]} for j in _JOBS]
