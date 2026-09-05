from fastapi import FastAPI

import logging_setup
from routers.auth import router as auth_router
from routers.admin import router as admin_router

logging_setup.setup_logging()

app = FastAPI(title="user-service")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(admin_router)
