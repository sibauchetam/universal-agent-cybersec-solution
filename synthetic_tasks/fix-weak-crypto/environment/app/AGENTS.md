# AGENTS.md

## Project Context

This repository contains a FastAPI identity service backed by **SQLite** (stdlib
`sqlite3`). The database is a single file: the `APP_DB` environment variable if set,
otherwise `<app dir>/app.db`.
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
  - `python3 -m uvicorn main:app --host 127.0.0.1 --port 8000`
- The grading harness starts the service itself and captures its stdout/stderr into a
  log file (the `APP_LOG` environment variable points to that file). Application
  logging goes to stderr.

## Validation Discipline

- Prefer validating fixes against the same runtime path used by the API.
- Do not "fix tests" to bypass runtime/process issues.
- If a failure is caused by stale runtime state, resolve the runtime issue first,
  then re-run tests.

## Data and State Hygiene

- SQLite state persists in the database file across restarts. Seed users
  (`alice@example.com`, `carol@example.com`, legacy password hashes) are created at
  startup if missing.
- The grading harness recreates the database from scratch before grading. If behavior
  depends on fresh state, stop the service, remove the database file and restart
  before concluding.
- Keep changes minimal and directly tied to the identified defect.
