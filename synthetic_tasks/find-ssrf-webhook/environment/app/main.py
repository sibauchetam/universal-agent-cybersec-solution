from fastapi import FastAPI

from routers.webhooks import router as webhooks_router

app = FastAPI(title="webhook-gateway")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(webhooks_router)
