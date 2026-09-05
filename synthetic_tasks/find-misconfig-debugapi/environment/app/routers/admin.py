from fastapi import APIRouter, Response
from pydantic import BaseModel

import config

router = APIRouter(tags=["admin"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(req: LoginRequest, response: Response):
    if req.username == config.ADMIN_USER and req.password == config.ADMIN_PASSWORD:
        response.set_cookie("session", "fixed-session-token-0001")   # static token, no flags
        return {"status": "ok"}
    return {"status": "denied"}
