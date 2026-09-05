import os
import sqlite3

import httpx
import pytest

APP_DIR = os.environ.get("APP_DIR", "/app")


@pytest.fixture
def client() -> httpx.Client:
    return httpx.Client(base_url="http://127.0.0.1:8000", timeout=30.0)


@pytest.fixture
def db():
    """Scalar-query helper against the app's SQLite database.

    The app under test and this fixture MUST resolve the same database file:
    APP_DB if set, otherwise <APP_DIR>/app.db (mirrors environment/app/db.py).
    """
    path = os.environ.get("APP_DB", os.path.join(APP_DIR, "app.db"))

    def _scalar(query: str):
        con = sqlite3.connect(path, timeout=10)
        try:
            row = con.execute(query).fetchone()
        finally:
            con.close()
        assert row is not None, f"no row returned for query: {query}"
        return row[0]

    return _scalar
