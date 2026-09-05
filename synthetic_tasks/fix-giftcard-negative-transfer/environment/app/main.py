from contextlib import asynccontextmanager

from fastapi import FastAPI

from db import get_db
from routers import checkout, wallets


def init_schema() -> None:
    con = get_db()
    try:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS wallets (
                user    TEXT PRIMARY KEY,
                balance REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS giftcards (
                code  TEXT PRIMARY KEY,
                value REAL NOT NULL,
                used  INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        if con.execute("SELECT COUNT(*) FROM wallets").fetchone()[0] == 0:
            con.executemany(
                "INSERT INTO wallets (user, balance) VALUES (?, ?)",
                [("alice", 1000), ("bob", 250), ("carol", 40)],
            )
        if con.execute("SELECT COUNT(*) FROM giftcards").fetchone()[0] == 0:
            con.executemany(
                "INSERT INTO giftcards (code, value, used) VALUES (?, ?, ?)",
                [("GIFT-SPRING-10", 10, 0), ("GIFT-DEAD-5", 5, 1)],
            )
        con.commit()
    finally:
        con.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema()
    yield


app = FastAPI(title="payments-demo", lifespan=lifespan)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


app.include_router(wallets.router)
app.include_router(checkout.router)
