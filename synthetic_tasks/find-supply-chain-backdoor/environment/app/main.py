from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="reporting-service")

_REPORTS: list[dict] = []


class Report(BaseModel):
    name: str
    content: str


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/reports")
async def add_report(report: Report):
    _REPORTS.append(report.model_dump())
    return {"added": report.name}


@app.get("/reports")
async def list_reports():
    return [{"name": r["name"]} for r in _REPORTS]
