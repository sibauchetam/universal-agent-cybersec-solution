import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import jwtauth

router = APIRouter(tags=["auth"])

USERS = {"alice": "pw-alice", "bob": "pw-bob"}


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
async def login(req: LoginRequest):
    if USERS.get(req.username) != req.password:
        raise HTTPException(status_code=401, detail="invalid credentials")
    payload = {"sub": req.username, "exp": int(time.time()) + 3600}
    return {"token": jwtauth.sign(payload)}
