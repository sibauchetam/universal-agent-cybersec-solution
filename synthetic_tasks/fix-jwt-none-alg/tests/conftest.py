import base64
import hashlib
import hmac
import json
import os
import time

import httpx
import pytest

SECRET = os.environ["JWT_SECRET"]  # grading harness sets JWT_SECRET=verifier-test-secret


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, secret: str = SECRET, alg: str = "HS256") -> str:
    head = _b64u(json.dumps(header, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    if alg == "none":
        return f"{head}.{body}."
    digest = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), digest).digest()
    return f"{head}.{body}.{_b64u(sig)}"


@pytest.fixture
def client():
    return httpx.Client(base_url="http://127.0.0.1:8000", timeout=30.0)
