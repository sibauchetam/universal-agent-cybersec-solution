# TASK-01 — find-ssrf-webhook

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A10 Server-Side Request Forgery (SSRF)** (CWE-918) |
| Difficulty | medium |
| Deliverable | `/app/security_report.json` (audit report; **no code changes**) |
| Pattern cloned from | `local_task/find-sqli-login` (audit → findings[] JSON) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/find-ssrf-webhook"
description = "Audit a FastAPI webhook gateway for server-side request forgery and report findings in machine-readable JSON."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "ssrf", "owasp-a10", "fastapi", "bug-bounty", "audit", "report"]

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

[verifier.env]

[environment.env]

[solution.env]
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app`. The application is a FastAPI webhook gateway that performs
server-side HTTP requests on behalf of clients.

Perform a security audit focused on server-side request behavior. Do not modify
application code.

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
      "location": "Affected file, function, endpoint, or component",
      "evidence": "Concrete code or behavior that demonstrates the issue",
      "impact": "Security impact",
      "recommendation": "Recommended remediation"
    }
  ]
}
```

Include enough detail for each finding to be useful to an engineer triaging a bug
bounty report.
````

## 3. `environment/` composition

No database — pure FastAPI + httpx, in-memory state.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY app/ .`, `RUN /app/.venv/bin/uv pip install --python /app/.venv/bin/python .`, `COPY entrypoint.sh /entrypoint.sh`, `EXPOSE 8000`, `ENTRYPOINT ["/entrypoint.sh"]` (same as `find-sqli-login`) |
| `environment/entrypoint.sh` | `uvicorn main:app --host 0.0.0.0 --port 8000 &` then `tail -f /dev/null` (keep-alive so the verifier owns restarts) |
| `environment/app/pyproject.toml` | deps: `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `httpx>=0.27`, `pytest>=8`; `[tool.setuptools] packages = ["routers"]` |
| `environment/app/AGENTS.md` | Same structure as `find-sqli-login/app/AGENTS.md` (project context, stale-process discipline) |
| `environment/app/main.py` | `FastAPI()` app, includes `routers.webhooks.router`, `GET /healthz` → `{"status": "ok"}` |
| `environment/app/fetcher.py` | **Vulnerable SSRF helper** — see below |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/routers/webhooks.py` | **Vulnerable endpoints** — see below |
| `environment/app/tests/test_api.py` | regression: `/healthz` returns 200; `POST /import/fetch` with `{"url": "http://example.invalid/"}` returns a 4xx/5xx-or-dict (no crash); `POST /webhooks/register` accepts a well-formed body |

`environment/app/fetcher.py` (key vulnerable fragment):

```python
import httpx

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


async def fetch_url(url: str) -> httpx.Response:
    # Best-effort internal host denylist.
    host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
    if host.lower().strip() in _BLOCKED_HOSTS:
        raise ValueError("blocked host")
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=5.0, follow_redirects=True)
    return resp
```

`environment/app/routers/webhooks.py` (key fragments):

```python
@router.post("/webhooks/register")
async def register(req: RegisterRequest):
    resp = await fetch_url(req.url)  # server probes the client-supplied URL
    return {"status": resp.status_code}


@router.post("/import/fetch")
async def import_fetch(req: FetchRequest):
    resp = await fetch_url(req.url)
    return {"status": resp.status_code, "length": len(resp.text), "prefix": resp.text[:200]}
```

Vulnerability design (what a correct audit must surface):

1. **Denylist bypass** — `_BLOCKED_HOSTS` only matches literal `localhost/127.0.0.1/0.0.0.0/::1`.
   Bypasses: cloud metadata `http://169.254.169.254/latest/meta-data/`; private ranges
   `10.x/192.168.x/172.16.x`; alternative IP encodings that resolve to loopback
   (`http://2130706433/`, `http://0x7f000001/`, `http://017700000001/`); attacker-controlled
   DNS names resolving to internal addresses (rebinding).
2. **Redirect bypass** — `follow_redirects=True`: a public attacker URL can 302 to an internal
   target after the denylist check.
3. **Readable SSRF / data leak** — `/import/fetch` returns `prefix` (first 200 bytes) and
   `length` of the internal response → exfiltration channel (e.g. metadata credentials).

## 4. Verifier (`tests/`)

`tests/test.sh`: harness identical in spirit to `fix-sqli-login/tests/test.sh` — but since the
app is read-only for this task it simply verifies the service is up (start `uvicorn main:app`
from `/app` if not running, wait for `/healthz`), writes reward 0/1 to `/logs/verifier/reward.txt`,
and runs `$PYTHON -m pytest /tests -v`.

`tests/test_security_report.py` (hidden verifier — mirrors `find-sqli-login` signal style):

```python
import hashlib, json
from pathlib import Path
from typing import Any

REPORT_PATH = Path("/app/security_report.json")
FETCHER_PATH = Path("/app/fetcher.py")


def _flatten(value: Any) -> str: ...
def _has_any(text: str, needles: list[str]) -> bool: ...


def test_security_report_exists(): assert REPORT_PATH.exists()

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
    # Pin the sha256 of the pristine files at packaging time (files are fully
    # specified above, so the hashes are computable before the image build).
    PRISTINE_SHA256 = {"fetcher.py": "<pin-at-build-time>", "routers/webhooks.py": "<pin-at-build-time>"}
    assert hashlib.sha256(FETCHER_PATH.read_bytes()).hexdigest() == PRISTINE_SHA256["fetcher.py"]
```

**Exact grading semantics:** binary 0/1 — report must exist, be valid JSON, contain ≥1 finding
matching all three signal lists, and the app code must be byte-identical to pristine.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PYEOF'
import json, pathlib
report = {
  "findings": [
    {
      "title": "SSRF via /import/fetch denylist bypass (CWE-918)",
      "severity": "critical",
      "category": "Server-Side Request Forgery (SSRF)",
      "location": "app/fetcher.py: fetch_url; app/routers/webhooks.py: POST /import/fetch",
      "evidence": "_BLOCKED_HOSTS only contains localhost/127.0.0.1/0.0.0.0/::1; host is parsed from the raw URL string. Requests to http://169.254.169.254/latest/meta-data/, private 10.x/192.168.x ranges, or decimal/hex IP encodings (http://2130706433/, http://0x7f000001/) bypass the check. follow_redirects=True also lets a public URL 302-redirect into the internal network after validation.",
      "impact": "Unauthenticated server-side requests to internal services and cloud metadata (169.254.169.254); /import/fetch reflects the first 200 bytes of the internal response, leaking secrets such as metadata IAM credentials.",
      "recommendation": "Replace the denylist with a strict allowlist of approved public hosts; resolve hostnames and reject private/link-local/loopback IPs (ipaddress module) at connect time; disable or sandbox redirect following; do not reflect internal response bodies to the caller."
    },
    {
      "title": "SSRF probe in /webhooks/register",
      "severity": "high",
      "category": "Server-Side Request Forgery (SSRF)",
      "location": "app/routers/webhooks.py: POST /webhooks/register",
      "evidence": "Endpoint fetches any client-supplied URL server-side via fetch_url with no scheme/host validation (http://, gopher-style abuse, internal hosts).",
      "impact": "Internal network port/proxy scanning through the gateway; blind SSRF to internal admin panels.",
      "recommendation": "Validate webhook URLs against an allowlist of customer-owned public endpoints; enforce https scheme; egress through a proxy that blocks RFC1918/link-local ranges."
    },
    {
      "title": "Internal response body reflected to clients",
      "severity": "medium",
      "category": "Information Disclosure via SSRF",
      "location": "app/routers/webhooks.py: POST /import/fetch (prefix/length fields)",
      "evidence": "Response returns resp.text[:200] and content length of the fetched resource to the caller.",
      "impact": "Turns blind SSRF into readable SSRF: internal banners, tokens, or metadata documents can be exfiltrated.",
      "recommendation": "Never return fetched body content for client-supplied URLs; return only a fixed ack."
    }
  ]
}
pathlib.Path("/app/security_report.json").write_text(json.dumps(report, indent=2))
PYEOF
python3 -c "import json; json.load(open('/app/security_report.json')); print('report OK')"
```

## 6. Expected agent difficulty profile

- **Steps:** ~8–14 tool calls (list dir, read 3 files, optionally one failed live-probe attempt,
  write JSON, validate JSON).
- **Small-model failure modes:**
  - Produces malformed JSON (trailing commas, unescaped newlines in `evidence`).
  - Writes a generic "SSRF is bad" finding but misses one of the three required signal groups in
    the *same* finding (must literally contain an SSRF term + a target term like `169.254`/`metadata`
    + a bypass detail like `follow_redirects`/`denylist`/`fetcher.py`).
  - Wastes steps attempting live exploitation of `169.254.169.254` (no metadata service and no
    internet in the sandbox) instead of writing the static-analysis report.
  - Accidentally "fixes" the code despite `Do not modify application code` → trips
    `test_app_code_unmodified`.
