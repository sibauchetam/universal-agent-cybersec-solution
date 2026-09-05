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


def test_at_least_four_distinct_misconfigs():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    groups_hit = sum(
        1 for needles in SIGNAL_GROUPS.values()
        if any(_has_any(t, needles) for t in flat)
    )
    assert groups_hit >= 4, f"only {groups_hit} misconfiguration groups covered"


def test_default_credential_finding_has_location():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["admin123", "default credential"])
               and _has_any(_flatten(f).lower(), ["config.py", "readme.md", "routers/admin.py"])
               for f in data["findings"])


def test_app_code_unmodified():
    # sha256 of pristine config.py / main.py pinned at packaging time by
    # scripts/build_batch_a.py.
    PRISTINE_SHA256 = {"config.py": "c3e6025185e08551d0dabbcd3c97cf70ae1edad77f408667285fd9260d381a68", "main.py": "d17bf96d71a2b7461ba0e0a53221f6a6c5e54c081c2fdd0ae61711a713cd3b0a"}
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256((APP_DIR / rel).read_bytes()).hexdigest() == want, rel


SIGNAL_GROUPS = {
    "debug": ["debug", "traceback", "stack trace", "verbose error", "cwe-489", "cwe-209"],
    "cors": ["cors", "cross-origin", "cwe-942", "allow_origins", "wildcard"],
    "creds": ["default credential", "admin123", "hardcoded password", "seeded", "cwe-798"],
    "envdump": ["debug/env", "environment", "os.environ", "secret", "cwe-200"],
    "listing": ["directory listing", "show_dir_listing", "staticfiles", "cwe-548"],
    "cookie": ["cookie", "httponly", "secure flag", "cwe-614"],
}
