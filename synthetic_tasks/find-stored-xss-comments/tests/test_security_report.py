"""Hidden audit verifier (batch A).

Official image semantics: report at /app/security_report.json, code under /app.
Local adaptation (deliberate): every path is resolved from the APP_DIR
environment variable so the same suite runs against a harness workdir;
APP_DIR defaults to /app for fidelity with the official image.
"""
import hashlib, json, os
from pathlib import Path
from typing import Any

APP_DIR = Path(os.environ.get("APP_DIR", "/app"))
REPORT_PATH = APP_DIR / "security_report.json"


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def _has_any(text: str, needles: list[str]) -> bool:
    return any(n in text for n in needles)


COMMENTS_PATH = APP_DIR / "routers" / "comments.py"
PROFILE_PATH = APP_DIR / "routers" / "profile.py"


def test_report_exists_and_valid():
    data = json.loads(REPORT_PATH.read_text())
    assert isinstance(data, dict)
    assert isinstance(data.get("findings"), list) and data["findings"]


def test_report_contains_xss_finding():
    data = json.loads(REPORT_PATH.read_text())
    xss_signals = ["xss", "cross-site scripting", "cross site scripting", "cwe-79"]
    location_signals = ["comments", "/comments", "comments.py", "comment"]
    detail_signals = [
        "<script>", "stored", "escape", "html escape", "autoescape", "htmlresponse",
        "f-string", "interpolation", "markup", "untrusted",
    ]
    matching = [
        f for f in data.get("findings", [])
        if _has_any(_flatten(f).lower(), xss_signals)
        and _has_any(_flatten(f).lower(), location_signals)
        and _has_any(_flatten(f).lower(), detail_signals)
    ]
    assert matching, "expected a finding describing XSS on the comment wall with a concrete detail"


def test_report_mentions_stored_persistence():
    data = json.loads(REPORT_PATH.read_text())
    xss_signals = ["xss", "cross-site scripting", "cross site scripting", "cwe-79"]
    persistence_needles = ["stored", "persist", "every visitor", "other users"]
    assert any(
        _has_any(_flatten(f).lower(), xss_signals)
        and _has_any(_flatten(f).lower(), persistence_needles)
        for f in data.get("findings", [])
    ), "expected an XSS finding noting stored/persistence"


def test_app_code_unmodified():
    # sha256 of pristine comments.py / profile.py pinned at packaging time
    # by scripts/build_batch_a.py.
    PRISTINE_SHA256 = {"routers/comments.py": "31c62599956a678fa1d717fc6442b6b33f8881bb5f930ce32fa8aed60c8194fa", "routers/profile.py": "891bbbbd349f14cff5613a55e0777d8b5330c3840dec69fceaa2269e49b4750f"}
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256((APP_DIR / rel).read_bytes()).hexdigest() == want, rel
