import logging
from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger("admin")

router = APIRouter(tags=["admin"])

_ROLES: dict[str, str] = {}


class GrantRequest(BaseModel):
    username: str
    role: str


@router.post("/grant-role")
def grant_role(req: GrantRequest):
    _ROLES[req.username] = req.role
    # DEFECT: privileged action leaves NO log entry at all
    return {"status": "ok"}


@router.get("/audit-trail")
def audit_trail():
    # DEFECT: audit trail is fed from logger.debug(...)
    logger.debug("audit trail dump requested")
    return {"entries": []}
