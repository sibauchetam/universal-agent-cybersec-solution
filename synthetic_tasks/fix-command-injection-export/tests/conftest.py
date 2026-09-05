import httpx
import pytest


@pytest.fixture
def client():
    return httpx.Client(base_url="http://127.0.0.1:8000", timeout=30.0)
