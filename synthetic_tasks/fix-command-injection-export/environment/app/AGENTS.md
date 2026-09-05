# AGENTS.md

## Project Context

This repository contains a FastAPI report-exporter that shells out to a small local
rendering tool (`tools/render.py`). Rendered files land in `/tmp/exports`.
There is no database. Your task is to make code fixes safely while preserving
existing behavior.

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
  log file (the `APP_LOG` environment variable points to that file).

## Validation Discipline

- Prefer validating fixes against the same runtime path used by the API.
- Do not "fix tests" to bypass runtime/process issues.
- If a failure is caused by stale runtime state, resolve the runtime issue first,
  then re-run tests.

## Data and State Hygiene

- Rendered exports persist in `/tmp/exports` and artifacts under `/tmp` may persist
  across runs; clean them (`rm -f /tmp/pwned*`, `rm -rf /tmp/exports`) if a check
  depends on fresh state.
- Keep changes minimal and directly tied to the identified defect.
