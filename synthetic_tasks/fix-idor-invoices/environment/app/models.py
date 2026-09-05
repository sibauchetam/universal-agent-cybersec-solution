from pydantic import BaseModel


class Invoice(BaseModel):
    id: int
    owner_id: int
    client_name: str
    amount_cents: int
    status: str
