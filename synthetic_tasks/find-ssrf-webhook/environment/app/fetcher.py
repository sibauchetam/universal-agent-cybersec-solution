import httpx

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


async def fetch_url(url: str) -> httpx.Response:
    # Best-effort internal host denylist.
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
    if host.lower().strip() in _BLOCKED_HOSTS:
        raise ValueError("blocked host")
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=5.0, follow_redirects=True)
    return resp
