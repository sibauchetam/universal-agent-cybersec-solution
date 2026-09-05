You are working in `/app`. The application is a FastAPI identity service backed by
SQLite.

A previous penetration test flagged critical cryptographic failures. Fix all of them:

1. Passwords are hashed with unsalted MD5. Re-implement hashing with PBKDF2-HMAC-SHA256
   via `hashlib.pbkdf2_hmac`, at least **100,000 iterations**, and a fresh random
   **16-byte salt** (`secrets`). Store hashes in exactly this format:
   `pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>`
2. Existing MD5 users must still be able to log in. On a successful login against a
   legacy MD5 hash, transparently rehash the stored password to the new format
   (lazy migration) so the stored value no longer looks like an MD5 hex digest.
3. Session tokens are currently base64 of `"<user_id>:<expiry>"` — predictable and
   replayable. Issue `secrets.token_urlsafe(32)` tokens instead; two logins must never
   produce the same token.
4. Password comparison must be constant-time (`hmac.compare_digest`).
5. Password hashes must never appear in application logs.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `hashlib`, `hmac`, `secrets` are sufficient).
