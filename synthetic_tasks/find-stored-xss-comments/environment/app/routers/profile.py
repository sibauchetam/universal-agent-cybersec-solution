from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["profile"])


@router.get("/profile/{username}")
async def get_profile(username: str):
    return HTMLResponse(f"<h1>Profile: {username}</h1>")  # VULNERABLE: reflected XSS (unescaped interpolation)
