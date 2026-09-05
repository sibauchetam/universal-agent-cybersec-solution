from pathlib import Path

from fastapi import FastAPI

from routers.export import router as export_router

EXPORT_DIR = Path("/tmp/exports")
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="report-exporter")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(export_router)
