You are working in `/app`. The application is a FastAPI payments demo (wallets,
gift cards, checkout). QA confirmed the security backlog items below; fix the
application logic so that all invariants hold. Keep the public API contract
(paths, request/response fields) unchanged.

Reported defects:

1. Money transfer: sending a negative amount INCREASES the sender balance.
2. Gift card redemption: the same card code can be redeemed repeatedly.
3. Checkout: the discount percentage is taken from the request and values
   above 100 make the total negative.
4. Re-submitting the same transfer (retry) applies it twice.

Invariants that must hold after your fix:

- Transfer amount must be > 0; sender balance must never go below 0.
- A gift card can be redeemed exactly once (state persists across restarts
  within the container lifetime).
- Discount is validated server-side in [0, 100]; total is never negative;
  prices come from the server, never the client.
- A retried transfer with the same client request id must be idempotent
  (applied once).

The service is started by the harness (`uvicorn main:app` on port 8000).
A `GET /healthz` endpoint must keep working.
