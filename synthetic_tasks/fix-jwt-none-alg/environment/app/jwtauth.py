import base64, hashlib, hmac, json, time

FALLBACK_SECRET = "dev-secret-123"  # VULNERABLE: hardcoded secret


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign(payload: dict, secret: str = FALLBACK_SECRET) -> str:
    head = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64u(sig)}"


def verify(token: str) -> dict:
    head_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(_b64u_decode(head_b64))
    payload = json.loads(_b64u_decode(payload_b64))
    if header.get("alg") == "none":
        return payload  # VULNERABLE: alg=none bypass
    sig = hmac.new(FALLBACK_SECRET.encode(), f"{head_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if sig != _b64u_decode(sig_b64):  # VULNERABLE: hardcoded secret, non-constant-time compare
        raise PermissionError("bad signature")
    return payload  # VULNERABLE: no exp validation
