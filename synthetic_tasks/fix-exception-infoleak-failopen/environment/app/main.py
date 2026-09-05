import logging
import traceback

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

import store

logging.basicConfig(level=logging.INFO)

VALID_TOKENS = {"tok-admin-001": "admin", "tok-view-002": "viewer"}

app = FastAPI(title="order-tracking")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.exception_handler(Exception)
async def raw_error(request: Request, exc: Exception):
    # BUG 1: leaks exception text + traceback to the client
    return JSONResponse(status_code=500,
                        content={"error": str(exc), "trace": traceback.format_exc()})


@app.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path.startswith("/orders"):
        try:
            tok = request.headers.get("Authorization", "").removeprefix("Bearer ")
            role = VALID_TOKENS[tok]
        except Exception:
            # BUG 2: fail-OPEN — malformed/missing token errors fall through as admin
            role = "admin"
        request.state.role = role
    return await call_next(request)


@app.get("/orders")
async def list_orders(request: Request, sort: str | None = None):
    if request.state.role not in {"admin", "viewer"}:
        raise HTTPException(status_code=403)
    return {"orders": store.all_orders(sort)}
