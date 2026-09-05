import os
import sqlite3
from datetime import datetime, timezone

APP_DIR = os.environ.get("APP_DIR", "/app")
DB_PATH = os.environ.get("APP_DB", os.path.join(APP_DIR, "app.db"))

# Legacy seed users (unsalted MD5 of the password — vulnerable on purpose).
SEED_USERS = [
    # md5("AlicePass7!")
    ("alice@example.com", "5bc47a5d8941ad4fce902984d13f4cd1"),
    # md5("LegacyPass9!")
    ("carol@example.com", "ec6b77b99c274f803358001c0ec9dccf"),
]


def connect() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH, timeout=10)


def init_db() -> None:
    con = connect()
    try:
        con.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "email TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, "
            "created_at TEXT NOT NULL)"
        )
        now = datetime.now(timezone.utc).isoformat()
        for email, password_hash in SEED_USERS:
            con.execute(
                "INSERT OR IGNORE INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
                (email, password_hash, now),
            )
        con.commit()
    finally:
        con.close()


def fetch_user(email: str) -> dict | None:
    con = connect()
    try:
        row = con.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()
    finally:
        con.close()
    if row is None:
        return None
    return {"id": row[0], "email": row[1], "password_hash": row[2]}


def fetch_user_by_id(user_id: int) -> dict | None:
    con = connect()
    try:
        row = con.execute(
            "SELECT id, email, password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        con.close()
    if row is None:
        return None
    return {"id": row[0], "email": row[1], "password_hash": row[2]}


def create_user(email: str, password_hash: str) -> None:
    con = connect()
    try:
        con.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, datetime.now(timezone.utc).isoformat()),
        )
        con.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError("email already registered") from exc
    finally:
        con.close()


def update_password_hash(user_id: int, password_hash: str) -> None:
    con = connect()
    try:
        con.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        con.commit()
    finally:
        con.close()


init_db()
