import asyncio
import os

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

APP_DIR = os.environ.get("APP_DIR", "/app")

router = APIRouter(tags=["export"])


class ExportRequest(BaseModel):
    report_id: str
    format: str = "pdf"


@router.post("/export")
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
