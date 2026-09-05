import random

from fastapi import FastAPI, Response
from pydantic import BaseModel

from routers.sessions import weak_session_token

app = FastAPI(title="session-auth-demo")

_USERS = {"ops": "Ops!Pass42", "viewer": "View!Pass42"}
_failed: dict[str, int] = {}          # in-RAM only, lost on restart


class LoginRequest(BaseModel):
    username: str
    password: str


class RememberRequest(BaseModel):
    username: str


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/login")
def login(req: LoginRequest, response: Response):
    if _USERS.get(req.username) != req.password:
        return {"status": "denied"}                 # BUG: no counter, no 429, silent fail
    sid = weak_session_token(req.username)          # BUG: weak PRNG, low entropy
    response.set_cookie("session", sid)             # BUG: fixation — pre-auth sid kept
    return {"status": "ok"}


@app.post("/remember")
def remember(req: RememberRequest, response: Response):
    response.set_cookie("remember", req.username)   # BUG: no max_age, unsigned
    return {"status": "ok"}
