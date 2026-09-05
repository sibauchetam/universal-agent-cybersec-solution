# AGENTS.md

## Project Context

This repository contains a FastAPI service that authenticates users with HS256 JWT
bearer tokens via a stdlib-only implementation (`jwtauth.py`, no PyJWT). There is no
database; users are a fixed in-code dict. Your task is to make code fixes safely
while preserving existing behavior.

## Required Verification

- After code changes, run `pytest tests/`.
- Treat a change as complete only when the test suite passes.
- Do not add new dependencies unless explicitly required.

## Runtime Environment

- The token secret comes from the `JWT_SECRET` environment variable.
- The grading harness starts the service with `JWT_SECRET=verifier-test-secret`.
- When you start the service yourself — or import the application in-process
  (e.g. when running `pytest tests/`) after changing auth code — replicate that
  environment (`export JWT_SECRET=verifier-test-secret`); a fail-closed app refuses
  to boot without the variable.

## Runtime and Process Management

The service may already be running in the environment.
If tests unexpectedly reflect old behavior, assume a stale process first.

- Check running processes:
  - `ps -ef | grep uvicorn`
- If a stale server is running, stop it before validating behavior:
  - `pkill -f "uvicorn main:app" || true`
- Start the service only when needed for manual HTTP checks:
  - `JWT_SECRET=verifier-test-secret python3 -m uvicorn main:app --host 127.0.0.1 --port 8000`
- The grading harness starts the service itself and captures its stdout/stderr into a
  log file (the `APP_LOG` environment variable points to that file).

## Validation Discipline

- Prefer validating fixes against the same runtime path used by the API.
- Do not "fix tests" to bypass runtime/process issues.
- If a failure is caused by stale runtime state, resolve the runtime issue first,
  then re-run tests.

## Data and State Hygiene

- No persistent state; all users are in code.
- Keep changes minimal and directly tied to the identified defect.
