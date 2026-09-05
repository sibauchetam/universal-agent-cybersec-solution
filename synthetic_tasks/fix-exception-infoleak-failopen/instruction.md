You are working in `/app`. The application is a FastAPI order-tracking service
protected by a bearer token. A pentest found two classes of issues:

1. Error responses disclose internals: raw exception text, stack traces,
   filesystem paths and DB credentials are returned to clients on 500s.
2. The token-authorization path fails OPEN: if any internal error occurs
   while validating a token, the request is processed as if the token were
   valid.

Fix the application so that:

- All unhandled errors return `{"detail": "Internal server error"}` with
  status 500 and nothing else; full details must be written to the
  server-side log only (stderr is fine).
- Token validation must fail CLOSED: any internal error during token
  verification results in 401 for the protected endpoint, never 200.
- Existing happy-path behavior must not change (the hidden regression suite
  checks the public API contract, including `GET /healthz`).

The service is started by the harness (`uvicorn main:app` on port 8000).
