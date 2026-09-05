You are working in `/app`. The application is a FastAPI service that authenticates users
with HS256 JWT bearer tokens (stdlib-only implementation, no PyJWT).

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them:

- The token verifier must accept **only** tokens whose `alg` is exactly `HS256` and whose
  signature verifies against the secret taken from the `JWT_SECRET` environment variable
  (fail closed if the variable is unset or empty — never fall back to a hardcoded secret).
- Tokens without a well-formed `exp` claim (an integer/number, in the future) must be
  rejected with 401.
- Expired tokens must be rejected with 401.
- Token signing (`POST /login`) must use the same environment-derived secret.

The grading harness starts the service with `JWT_SECRET=verifier-test-secret`.

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `base64`, `json`, `hmac`, `hashlib`, `os`, `time` are sufficient).
