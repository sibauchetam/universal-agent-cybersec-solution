You are working in `/app`. The application is a FastAPI service with cookie
sessions. A security review flagged the login flow:

1. No throttling/lockout: password guessing is unlimited.
2. Session tokens are generated with a weak PRNG (`random`) and are
   predictable/short.
3. Session fixation: the pre-auth anonymous session id is kept after login.
4. The "remember me" cookie never expires.

Fix the application so that:

- After 5 FAILED logins for the same username, further attempts for that
  username return 429 (per-attempt; window: any 5 failures). Successful
  login resets the counter. The lockout state must survive service restart
  within the container lifetime.
- Session tokens after login MUST be freshly generated with a CSPRNG,
  at least 128 bits of entropy (32 hex chars) and different between two
  logins of the same user.
- Remember-me cookie lifetime MUST be at most 7 days (max_age seconds,
  integer in response Set-Cookie).
- Keep the public API contract unchanged (paths, fields, `/healthz`).

Users are seeded in-memory: `ops` / `Ops!Pass42`, `viewer` / `View!Pass42`.
The service is started by the harness (`uvicorn main:app` on port 8000).
