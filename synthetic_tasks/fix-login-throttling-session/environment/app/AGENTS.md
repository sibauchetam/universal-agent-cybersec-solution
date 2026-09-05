# AGENTS.md

## Project Context

FastAPI demo with cookie sessions. Users are seeded in-memory; lockout state
MUST be persisted so it survives a service restart - use the SQLite file
whose location comes from the environment: `APP_DB` (default
`$APP_DIR/app.db`, `APP_DIR` default `/app`).
Additional hidden tests will harden auth after your fix; keep the public
contract stable.

## Public API Contract (keep unchanged)

| Method | Path | Request body | Response |
|---|---|---|---|
| GET | `/healthz` | - | `{"status": "ok"}` (200) |
| POST | `/login` | `{"username", "password"}` | 200 `{"status": "ok"}` + `session` cookie, or 200 `{"status": "denied"}` |
| POST | `/remember` | `{"username"}` | 200 `{"status": "ok"}` + `remember` cookie |

Do not break `/healthz`. Keep paths and fields unchanged.

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

- Lockout counters live in the SQLite DB file and must survive a service
  restart (do not keep them only in RAM).
- If behavior depends on fresh state, stop the service, remove the DB file,
  and restart before concluding.
- Keep changes minimal and directly tied to the identified defect.
