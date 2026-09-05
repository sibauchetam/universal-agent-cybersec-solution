from fastapi import FastAPI

from routers.jobs import router as jobs_router

app = FastAPI(title="job-runner")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(jobs_router)
