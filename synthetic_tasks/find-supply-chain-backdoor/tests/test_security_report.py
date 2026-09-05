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


def test_typosquat_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["reqeusts", "typosquat", "typo-squat", "typo"])
               and _has_any(_flatten(f).lower(), ["requirements", "deploy"])
               for f in data["findings"])


def test_setuppy_backdoor_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["setup.py", "vendor", "acme"])
               and _has_any(_flatten(f).lower(), ["base64", "subprocess", "curl", "post-install",
                                                  "install-time", "backdoor"])
               for f in data["findings"])


def test_index_and_pinning_findings():
    data = json.loads(REPORT_PATH.read_text())
    flat = [_flatten(f).lower() for f in data["findings"]]
    assert any(_has_any(t, ["http://", "extra-index", "plaintext", "mitm"]) for t in flat)
    assert any(_has_any(t, ["unpinned", "no version pin", "not pinned", "fastapi"]) for t in flat)


def test_constraint_drift_finding():
    data = json.loads(REPORT_PATH.read_text())
    assert any(_has_any(_flatten(f).lower(), ["jinja2"]) and
               _has_any(_flatten(f).lower(), ["2.11.3", "constraints", "drift", "baseline"])
               for f in data["findings"])


def test_no_files_modified():
    # sha256 of pristine audit targets pinned at packaging time by
    # scripts/build_batch_a.py.
    PRISTINE_SHA256 = {
        "deploy/requirements.txt": "0331c89b0dd00ee865f1ecab5e628d5f4c3b667a721df7115499548a4e9e8b7e",
        "vendor/acme_jsonrpc/setup.py": "43e8aba147e3b93dd44f3960cef7953e68d70f3003e3583a9e79ab88b50ffe54",
        "scripts/install.sh": "64b9e781a56902cc0bfd5ed94c4acb3af1b9d84e72067428431ec072127e729a",
    }
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256((APP_DIR / rel).read_bytes()).hexdigest() == want, rel
