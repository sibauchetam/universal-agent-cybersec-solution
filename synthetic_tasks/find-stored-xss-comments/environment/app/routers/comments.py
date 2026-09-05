from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["comments"])

_COMMENTS: list[dict] = []


@router.get("/comments", response_class=HTMLResponse)
async def list_comments():
    items = "".join(
        f"<li><b>{c['author']}</b>: {c['body']}</li>"  # VULNERABLE: unescaped interpolation (stored XSS)
        for c in _COMMENTS
    )
    return HTMLResponse(f"<html><body><h1>Comments</h1><ul>{items}</ul></body></html>")


@router.post("/comments")
async def add_comment(author: str = Form(...), body: str = Form(...)):
    _COMMENTS.append({"author": author, "body": body})
    return HTMLResponse("<html><body>Comment added. <a href='/comments'>View comments</a></body></html>")
