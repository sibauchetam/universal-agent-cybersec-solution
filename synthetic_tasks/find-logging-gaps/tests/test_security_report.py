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


def test_report_valid():
    data = json.loads(REPORT_PATH.read_text())
    assert isinstance(data.get("findings"), list) and data["findings"]


def test_failed_auth_logging_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["failed login", "failed auth", "auth failure",
                                              "denied", "brute", "not logged", "no log"])
               for f in data["findings"])


def test_sensitive_data_in_logs_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["password", "plaintext", "cleartext", "cwe-532"])
               and _has_any(_flatten(f).lower(), ["log", "logger", "auth.py"])
               for f in data["findings"])


def test_timestamp_or_level_finding():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    assert any(_has_any(t, ["timestamp", "asctime", "no time", "correlat"]) for t in flat) or \
           any(_has_any(t, ["debug", "warning", "level", "filtered", "audit trail"]) for t in flat)


def test_injection_or_privileged_gap_finding():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    assert any(_has_any(t, ["injection", "newline", "cwe-117", "forge"]) for t in flat) or \
           any(_has_any(t, ["grant-role", "grant role", "privileged", "reset-password"]) for t in flat)


def test_app_code_unmodified():
    # sha256 of pristine routers/auth.py / logging_setup.py pinned at packaging
    # time by scripts/build_batch_a.py.
    PRISTINE_SHA256 = {"routers/auth.py": "7bb6bfb6d5f2078f62556461b89aade85b76b09a3625196a5724ba823932af13", "logging_setup.py": "e961807f4edef0176cbcf752de7191deadbf62bf0f9ca0477142ee4df3d03835"}
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256((APP_DIR / rel).read_bytes()).hexdigest() == want, rel
