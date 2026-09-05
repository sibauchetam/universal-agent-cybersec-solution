from fastapi import APIRouter, Header, HTTPException

from db import get_conn
from models import Invoice

router = APIRouter(tags=["invoices"])


@router.get("/invoices/{invoice_id}", response_model=Invoice)
async def get_invoice(invoice_id: int, x_user_id: int = Header(...)):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id, owner_id, client_name, amount_cents, status "
            "FROM invoices WHERE id = ?",
            (invoice_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return dict(row)  # VULNERABLE: no ownership check (IDOR)


@router.get("/invoices", response_model=list[Invoice])
async def list_invoices(x_user_id: int = Header(...)):
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, owner_id, client_name, amount_cents, status FROM invoices"
        ).fetchall()  # VULNERABLE: returns every tenant's invoices
    finally:
        conn.close()
    return [dict(r) for r in rows]


@router.post("/invoices/{invoice_id}/pay")
async def pay_invoice(invoice_id: int, x_user_id: int = Header(...)):
    conn = get_conn()
    try:
        cur = conn.execute(
            "UPDATE invoices SET status = 'paid' WHERE id = ?",
            (invoice_id,),
        )
        conn.commit()
        affected = cur.rowcount
    finally:
        conn.close()
    if affected == 0:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return {"status": "paid"}
