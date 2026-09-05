from fastapi import APIRouter, HTTPException, Request

import jwtauth

router = APIRouter(tags=["me"])


@router.get("/me")
async def me(request: Request):
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        payload = jwtauth.verify(header.removeprefix("Bearer "))
    except Exception:
        raise HTTPException(status_code=401, detail="invalid token")
    return {"sub": payload.get("sub")}
