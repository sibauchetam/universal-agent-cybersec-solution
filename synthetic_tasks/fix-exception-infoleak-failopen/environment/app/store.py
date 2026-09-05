import sqlite3

_ORDERS = [{"id": 1, "item": "keyboard", "qty": 2}]


def all_orders(sort: str | None = None):
    if sort == "explode":  # reachable via ?sort= param — planted crash
        raise sqlite3.OperationalError(
            "no such table: audit_log (db=/app/data/prod.db, user=ops_rw, password=pr0d-0nly)")
    return _ORDERS
