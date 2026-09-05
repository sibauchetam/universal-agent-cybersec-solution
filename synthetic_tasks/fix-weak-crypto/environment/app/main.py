import logging

from fastapi import FastAPI

import db
from routers.auth import router as auth_router

logging.basicConfig(level=logging.INFO)

db.init_db()

app = FastAPI(title="identity-service")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(auth_router)
