# AGENTS.md

## Project Context

This repository contains a FastAPI order-tracking service protected by a bearer
token. Data lives in an in-memory list (`store.py`); there is no database.
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
- The grading harness starts the service itself (`uvicorn main:app` on port 8000)
  and captures its stdout/stderr into a log file (the `APP_LOG` environment
  variable points to that file). Server-side logging goes to stderr.

## Validation Discipline

- Prefer validating fixes against the same runtime path used by the API.
- Do not "fix tests" to bypass runtime/process issues.
- If a failure is caused by stale runtime state, resolve the runtime issue first,
  then re-run tests.

## Data and State Hygiene

- Orders are held in memory; a service restart resets them. If behavior depends
  on fresh state, restart the service before concluding.
- Keep changes minimal and directly tied to the identified defect.
