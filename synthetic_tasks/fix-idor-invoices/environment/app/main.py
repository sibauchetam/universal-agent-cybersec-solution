from contextlib import asynccontextmanager

from fastapi import FastAPI

from db import init_schema
from routers.auth import router as auth_router
from routers.invoices import router as invoices_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema()
    yield


app = FastAPI(title="invoice-api", lifespan=lifespan)

app.include_router(auth_router)
app.include_router(invoices_router)
