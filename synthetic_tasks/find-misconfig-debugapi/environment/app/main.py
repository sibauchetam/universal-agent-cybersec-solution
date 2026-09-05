from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import config, os, traceback

from routers.admin import router as admin_router

app = FastAPI(debug=config.DEBUG)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # wildcard
    allow_credentials=True,       # invalid + unsafe combination
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def debug_error(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "trace": traceback.format_exc()},  # leaks internals
    )


@app.get("/debug/env")
def debug_env():
    return dict(os.environ)       # dumps API keys / DB creds, no auth


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(admin_router)

try:
    app.mount("/static", StaticFiles(directory=".", show_dir_listing=True))  # serves .env too
except TypeError:
    # Newer Starlette removed show_dir_listing; the app-root mount (source and
    # .env exposure) remains on every version.
    app.mount("/static", StaticFiles(directory="."))
