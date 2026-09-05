You are working in `/app`. The application is a FastAPI service backed by SQLite.

The API trusts an `X-User-Id` header that is set by the edge gateway after authentication
(seed users: `alice=1`, `bob=2`, `admin=9`).

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. Authorization
requirements:

- A user must only be able to read, list, and pay **their own** invoices.
- Responses about objects a user does not own must not reveal their existence (use 404).
- Do not introduce new dependencies beyond what is already declared in `pyproject.toml`.
