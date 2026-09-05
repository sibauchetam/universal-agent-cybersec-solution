from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["checkout"])

CATALOG = {"tshirt": 25.0, "mug": 12.5}    # server-side prices


class CheckoutRequest(BaseModel):
    item: str
    discount_pct: float


@router.post("/checkout")
def checkout(req: CheckoutRequest):        # {item, discount_pct: float} <- client-controlled
    price = CATALOG[req.item]
    total = price * (1 - req.discount_pct / 100.0)   # discount_pct=150 => negative total
    return {"total": round(total, 2)}
