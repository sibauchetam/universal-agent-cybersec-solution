from fastapi import APIRouter
from pydantic import BaseModel

from fetcher import fetch_url

router = APIRouter(tags=["webhooks"])


class RegisterRequest(BaseModel):
    url: str


class FetchRequest(BaseModel):
    url: str


@router.post("/webhooks/register")
async def register(req: RegisterRequest):
    resp = await fetch_url(req.url)  # server probes the client-supplied URL
    return {"status": resp.status_code}


@router.post("/import/fetch")
async def import_fetch(req: FetchRequest):
    resp = await fetch_url(req.url)
    return {"status": resp.status_code, "length": len(resp.text), "prefix": resp.text[:200]}
