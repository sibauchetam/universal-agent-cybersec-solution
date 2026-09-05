import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import sys
    sys.path.insert(0, ".")
    from main import app
    return TestClient(app)
