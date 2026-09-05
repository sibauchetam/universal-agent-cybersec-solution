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


FETCHER_PATH = APP_DIR / "fetcher.py"
WEBHOOKS_PATH = APP_DIR / "routers" / "webhooks.py"


def test_security_report_exists():
    assert REPORT_PATH.exists()


def test_security_report_is_valid_json_object():
    data = json.loads(REPORT_PATH.read_text())
    assert isinstance(data, dict) and "findings" in data
    assert isinstance(data["findings"], list) and data["findings"]


def test_report_contains_ssrf_finding():
    data = json.loads(REPORT_PATH.read_text())
    ssrf_signals = ["ssrf", "server-side request forgery", "server side request forgery", "cwe-918"]
    target_signals = ["169.254", "metadata", "internal", "private", "loopback", "127.0.0.1", "localhost"]
    detail_signals = [
        "fetcher.py", "import/fetch", "webhooks/register", "follow_redirects", "redirect",
        "denylist", "blocklist", "allowlist", "2130706433", "0x7f", "hex", "decimal", "rebind",
    ]
    matching = [
        f for f in data.get("findings", [])
        if _has_any(_flatten(f).lower(), ssrf_signals)
        and _has_any(_flatten(f).lower(), target_signals)
        and _has_any(_flatten(f).lower(), detail_signals)
    ]
    assert matching, "expected a finding describing SSRF with a concrete bypass detail"


def test_app_code_unmodified():
    # sha256 of the pristine files pinned at packaging time by
    # scripts/build_batch_a.py (files are fully specified in the spec).
    PRISTINE_SHA256 = {"fetcher.py": "aee0358350b279768111ea93826ee4e5a6ceeb242de2791caa8e30db9ad1ba87", "routers/webhooks.py": "bef9c163eae3fa640f4aaf8b61fa884a098cb7f7bdfb51c126a1ca6c5f3261e5"}
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256((APP_DIR / rel).read_bytes()).hexdigest() == want, rel
