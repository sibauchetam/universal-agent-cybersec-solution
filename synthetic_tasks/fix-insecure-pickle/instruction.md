You are working in `/app`. The application is a FastAPI job runner. Clients submit jobs as
base64-encoded blobs to `POST /jobs/import`.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. The job blob
wire format is **JSON** with exactly the fields:

- `name` — string, 1-128 chars
- `priority` — integer, 0-9
- `params` — object with string keys and string values

Invalid blobs must be rejected with a 4xx status and must **never** execute
attacker-controlled code (no `pickle`, `yaml.load`, `eval`, or similar).

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `json`, `base64` are sufficient).