# AGENTS.md

## Project Context

FastAPI payments demo: wallets, gift cards, checkout. Storage is a single
SQLite file (`sqlite3` stdlib only, no ORM). The DB file location comes from
the environment: `APP_DB` (default `$APP_DIR/app.db`, `APP_DIR` default
`/app`). Wallet and gift-card seed data is created at service startup when
the database is empty.

## Public API Contract (keep unchanged)

| Method | Path | Request body | Response |
|---|---|---|---|
| GET | `/healthz` | - | `{"status": "ok"}` (200) |
| GET | `/wallets/{user}` | - | `{"user": ..., "balance": ...}` (200) / 404 |
| POST | `/transfer` | `{"from", "to", "amount": float, "request_id": str\|null}` | `{"status": "ok", "balance": ...}` (200) |
| POST | `/giftcard/redeem` | `{"code", "for_user"}` | `{"status": "ok", "value": ...}` (200) |
| POST | `/checkout` | `{"item", "discount_pct": float}` | `{"total": ...}` (200) |

Do not break `/healthz`. Keep paths and request/response fields unchanged.

## Required Verification

- After code changes, run `pytest tests/`.
- Treat a change as complete only when the test suite passes.
- Do not add new dependencies unless explicitly required.

## Runtime and Process Management

The service may already be running in the environment.
If tests unexpectedly reflect old behavior, assume a stale process first.

- Check running processes:
  - `ps -ef | grep uvicorn`
- If a stale server is running, stop it before validating behavior:
  - `pkill -f "uvicorn main:app" || true`
- Start the service only when needed for manual HTTP checks:
  - `uvicorn main:app --host 127.0.0.1 --port 8000`
- When starting the service yourself, keep `APP_DIR`/`APP_DB` pointing at
  this project directory so you exercise the same database as the API.

## Validation Discipline

- Prefer validating fixes against the same runtime path used by the API.
- Do not "fix tests" to bypass runtime/process issues.
- If a failure is caused by stale runtime state, resolve the runtime issue first, then re-run tests.

## Data and State Hygiene

- SQLite state persists across service restarts: gift-card `used` flags and
  transfer idempotency records must survive a restart (do not keep them only
  in RAM).
- If behavior depends on fresh state, stop the service, remove the DB file,
  and restart so the seed data is recreated before concluding.
- Keep changes minimal and directly tied to the identified defect.
