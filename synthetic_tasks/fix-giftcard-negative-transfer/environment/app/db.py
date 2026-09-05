"""SQLite storage helpers (no ORM).

The database location comes from the environment so the app and the verifier
always talk to the same file:
    APP_DIR -- application root (default /app)
    APP_DB  -- sqlite database file (default $APP_DIR/app.db)
"""
import os
import sqlite3

APP_DIR = os.environ.get("APP_DIR", "/app")
DB_PATH = os.environ.get("APP_DB", os.path.join(APP_DIR, "app.db"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
