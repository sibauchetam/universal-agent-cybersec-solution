You are working in `/app`. The application is a FastAPI report-exporter that shells out
to a rendering tool.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. In particular:

- Legitimate exports (report ids like `weekly-42`, `q2-financials`) must keep working.
- Client-controlled values must never be interpreted by a shell.
- Invalid input must be rejected with a 4xx response.

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`.
