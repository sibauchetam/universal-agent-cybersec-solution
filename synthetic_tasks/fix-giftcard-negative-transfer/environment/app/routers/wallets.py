from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from db import get_db

router = APIRouter(tags=["wallets"])


class TransferRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from")   # {from, to, amount: float, request_id: str|None}
    to: str
    amount: float
    request_id: str | None = None


class RedeemRequest(BaseModel):
    code: str
    for_user: str


@router.get("/wallets/{user}")
def get_wallet(user: str):
    con = get_db()
    try:
        row = con.execute("SELECT balance FROM wallets WHERE user=?", (user,)).fetchone()
    finally:
        con.close()
    if not row:
        raise HTTPException(404, "unknown user")
    return {"user": user, "balance": row[0]}


@router.post("/transfer")
def transfer(req: TransferRequest):
    con = get_db()
    try:
        sender = con.execute("SELECT balance FROM wallets WHERE user=?", (req.from_,)).fetchone()
        if not sender:
            raise HTTPException(404, "unknown sender")
        new_balance = sender[0] - req.amount   # negative amount => balance INCREASES
        con.execute("UPDATE wallets SET balance=? WHERE user=?", (new_balance, req.from_))
        con.execute("UPDATE wallets SET balance=balance+? WHERE user=?", (req.amount, req.to))
        con.commit()
        return {"status": "ok", "balance": new_balance}
    finally:
        con.close()


@router.post("/giftcard/redeem")
def redeem(req: RedeemRequest):
    con = get_db()
    try:
        row = con.execute("SELECT value, used FROM giftcards WHERE code=?", (req.code,)).fetchone()
        if not row:
            raise HTTPException(404, "unknown card")
        con.execute("UPDATE wallets SET balance=balance+? WHERE user=?", (row[0], req.for_user))
        # BUG: `used` is never set; GIFT-DEAD-5's seed `used=1` is never checked either
        con.commit()
        return {"status": "ok", "value": row[0]}
    finally:
        con.close()
