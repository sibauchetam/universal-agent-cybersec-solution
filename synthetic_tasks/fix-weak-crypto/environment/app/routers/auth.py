import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

import db
import security

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register", status_code=201)
async def register(req: RegisterRequest):
    try:
        db.create_user(req.email, security.hash_password(req.password))
    except ValueError:
        raise HTTPException(status_code=400, detail="email already registered")
    return {"email": req.email}


@router.post("/login")
async def login(req: LoginRequest):
    row = db.fetch_user(req.email)
    if row is None or not security.verify_password(req.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    logger.info("login success user=%s hash=%s", row["email"], row["password_hash"])  # VULNERABLE: hash in logs
    return {"token": security.issue_token(row["id"]), "email": row["email"]}


@router.get("/me")
async def me(request: Request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    user_id = security.resolve_token(header.removeprefix("Bearer "))
    if user_id is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    row = db.fetch_user_by_id(user_id)
    if row is None:
        raise HTTPException(status_code=401, detail="unknown user")
    return {"email": row["email"]}
