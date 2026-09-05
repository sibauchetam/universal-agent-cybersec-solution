from fastapi import FastAPI

from routers.comments import router as comments_router
from routers.profile import router as profile_router

app = FastAPI(title="comment-wall")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(comments_router)
app.include_router(profile_router)
