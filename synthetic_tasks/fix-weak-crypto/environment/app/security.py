import base64, hashlib, time


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: unsalted MD5


def verify_password(password: str, stored: str) -> bool:
    return hashlib.md5(password.encode()).hexdigest() == stored  # VULNERABLE: not constant-time


def issue_token(user_id: int) -> str:
    expiry = int(time.time()) + 3600
    return base64.b64encode(f"{user_id}:{expiry}".encode()).decode()  # VULNERABLE: predictable token


def resolve_token(token: str) -> int | None:
    try:
        user_id, expiry = base64.b64decode(token).decode().split(":", 1)
        if int(expiry) < time.time():
            return None
        return int(user_id)
    except Exception:
        return None
