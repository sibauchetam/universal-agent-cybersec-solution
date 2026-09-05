# AGENTS.md

## Project Context

This repository contains a FastAPI service backed by a SQLite database file
(no ORM). The DB file location comes from the environment: `APP_DB`
(default `$APP_DIR/app.db`, `APP_DIR` default `/app`); schema and seed data
are created automatically at service startup when the database is empty.
Your task is to make code fixes safely while preserving existing behavior.

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

- SQLite state persists in the DB file across service restarts.
- If behavior depends on fresh state, stop the service, remove the DB file,
  and restart so the seed data is recreated before concluding.
- Keep changes minimal and directly tied to the identified defect.
