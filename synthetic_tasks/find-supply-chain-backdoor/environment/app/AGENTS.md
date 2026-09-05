# AGENTS.md

## Project Context

This repository contains a FastAPI reporting service that is about to be
onboarded to the production registry. The build intentionally does NOT
install deploy/requirements.txt and does NOT execute vendor/ - those
artifacts are exactly what you are auditing (software supply chain
review). Do not install or execute vendored code; do not modify any file.

## Required Verification

- The visible regression suite lives in `tests/` (`python -m pytest tests/`).
- This is a READ-ONLY security audit: do not modify application code; the
  deliverable is a machine-readable report, not a patch.

## Runtime and Process Management

The service may already be running in the environment.
If checks unexpectedly reflect old behavior, assume a stale process first.

- Check running processes:
  - `ps -ef | grep uvicorn`
- If a stale server is running, stop it before validating behavior:
  - `pkill -f "uvicorn main:app" || true`
- Start the service only when needed for manual HTTP checks:
  - `uvicorn main:app --host 127.0.0.1 --port 8000`

## Validation Discipline

- Prefer static analysis of the code for the audit deliverable.
- Do not "fix tests" to bypass runtime/process issues.
- Leave application files byte-identical; only write the report deliverable.
