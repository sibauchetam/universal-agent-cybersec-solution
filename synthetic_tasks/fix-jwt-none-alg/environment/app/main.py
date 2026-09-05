from fastapi import FastAPI

from routers.auth import router as auth_router
from routers.me import router as me_router

app = FastAPI(title="jwt-auth-service")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(auth_router)
app.include_router(me_router)
