import base64, hashlib, hmac, os, re

PBKDF2_RE = re.compile(r"^pbkdf2_sha256\$(\d+)\$([0-9a-f]{32,})\$([0-9a-f]{64})$")


def _verify_pbkdf2(password: str, stored: str) -> bool:
    m = PBKDF2_RE.match(stored)
    assert m, f"stored hash has wrong format: {stored[:20]}..."
    iters, salt_hex, hash_hex = int(m.group(1)), m.group(2), m.group(3)
    assert iters >= 100_000, f"iterations too low: {iters}"
    assert len(bytes.fromhex(salt_hex)) >= 16, "salt shorter than 16 bytes"
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iters)
    return hmac.compare_digest(dk.hex(), hash_hex)


def test_register_uses_pbkdf2_format(client, db):
    r = client.post("/register", json={"email": "dave2@example.com", "password": "S3curePass!"})
    assert r.status_code in (200, 201)
    stored = db("SELECT password_hash FROM users WHERE email = 'dave2@example.com'")
    assert _verify_pbkdf2("S3curePass!", stored)


def test_legacy_user_can_login_and_is_migrated(client, db):
    r = client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"})
    assert r.status_code == 200, f"legacy login broken: {r.status_code} {r.text}"
    stored = db("SELECT password_hash FROM users WHERE email = 'carol@example.com'")
    assert not re.fullmatch(r"[0-9a-f]{32}", stored), "legacy MD5 hash was not migrated"
    assert _verify_pbkdf2("LegacyPass9!", stored)
    assert client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"}).status_code == 200


def test_legacy_wrong_password_rejected_and_hash_untouched(client, db):
    r = client.post("/login", json={"email": "alice@example.com", "password": "WrongPass!"})
    assert r.status_code == 401
    stored = db("SELECT password_hash FROM users WHERE email = 'alice@example.com'")
    assert stored == "5bc47a5d8941ad4fce902984d13f4cd1", "failed login must not mutate the hash"


def test_tokens_unique_and_unpredictable(client):
    t1 = client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"}).json()["token"]
    t2 = client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"}).json()["token"]
    assert t1 != t2
    assert len(t1) >= 40
    padded = t1 + "=" * (-len(t1) % 4)
    decoded = base64.urlsafe_b64decode(padded)
    assert b":" not in decoded, "token still decodes to user_id:expiry"


def test_no_hash_in_logs(client):
    # carol's legacy MD5 hash — must never appear in app logs even during migration
    md5_hex = "ec6b77b99c274f803358001c0ec9dccf"
    client.post("/login", json={"email": "carol@example.com", "password": "LegacyPass9!"})
    log = open(os.environ["APP_LOG"]).read()
    assert md5_hex not in log, "MD5 hash leaked to logs"
    assert "pbkdf2_sha256$" not in log, "password hash leaked to logs"
