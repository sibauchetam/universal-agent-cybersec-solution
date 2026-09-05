import logging, secrets
from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger("auth")

router = APIRouter(tags=["auth"])

_USERS = {"svc-ops": "Ops!Pass42"}


class LoginRequest(BaseModel):
    username: str
    password: str


class ResetRequest(BaseModel):
    username: str
    new_password: str
    note: str = ""
    client: str = "unknown"

    def client_host(self) -> str:
        return self.client


@router.post("/login")
def login(req: LoginRequest):
    if req.username not in _USERS:
        return {"status": "denied"}                       # DEFECT: failed auth never logged
    if not secrets.compare_digest(_USERS[req.username], req.password):
        return {"status": "denied"}                       # DEFECT: failed auth never logged
    logger.info("login ok user=%s password=%s", req.username, req.password)  # DEFECT: plaintext creds
    return {"token": secrets.token_hex(16)}


@router.post("/reset-password")
def reset_password(req: ResetRequest):
    _USERS[req.username] = req.new_password
    logger.info("password reset for %s from %s note=%s",
                req.username, req.client_host(), req.note)   # DEFECT: note has raw newlines -> log injection
    return {"status": "ok"}
