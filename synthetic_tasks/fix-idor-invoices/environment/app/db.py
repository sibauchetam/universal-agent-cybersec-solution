"""SQLite storage for the invoice service.

The database location comes from the environment so the app and the verifier
always talk to the same file:
    APP_DIR -- application root (default /app)
    APP_DB  -- sqlite database file (default $APP_DIR/app.db)
"""
import os
import sqlite3

APP_DIR = os.environ.get("APP_DIR", "/app")
DB_PATH = os.environ.get("APP_DB", os.path.join(APP_DIR, "app.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
    id           INTEGER PRIMARY KEY,
    owner_id     INTEGER NOT NULL REFERENCES users(id),
    client_name  TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    status       TEXT NOT NULL
);
"""

_SEED_USERS = [(1, "alice"), (2, "bob"), (9, "admin")]
_SEED_INVOICES = [
    (101, 1, "Acme Corp", 125000, "open"),
    (102, 1, "Globex", 89000, "open"),
    (201, 2, "Initech", 45000, "open"),
    (202, 2, "Umbrella", 76000, "open"),
]


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema() -> None:
    conn = get_conn()
    try:
        conn.executescript(_SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.executemany("INSERT INTO users (id, username) VALUES (?, ?)", _SEED_USERS)
        if conn.execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO invoices (id, owner_id, client_name, amount_cents, status) "
                "VALUES (?, ?, ?, ?, ?)",
                _SEED_INVOICES,
            )
        conn.commit()
    finally:
        conn.close()
