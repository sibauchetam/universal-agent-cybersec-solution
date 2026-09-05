import hashlib
import os
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))
FLAG = "FLAG{p4rt1-3nv_h1st0ry_auth0r1z3d}"
ENV_SHA256 = "6fae93815e7dc29c37cc6e8330dd5a7459c1023435b25e88ed143b785913ecd3"


def test_flag_file_exact():
    got = (APP / "recovered_flag.txt").read_text().strip()
    assert got == FLAG


def test_target_home_unmodified():
    want = hashlib.sha256((APP / "target_home" / ".env").read_bytes()).hexdigest()
    assert want == ENV_SHA256
