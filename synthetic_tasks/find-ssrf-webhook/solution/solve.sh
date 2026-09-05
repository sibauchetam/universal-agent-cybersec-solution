#!/usr/bin/env bash
set -euo pipefail
export APP_DIR="${APP_DIR:-/app}"
python3 - <<'PYEOF'
import json, os, pathlib

app = pathlib.Path(os.environ.get("APP_DIR", "/app"))
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

(app / "security_report.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"wrote {app / 'security_report.json'}")
PYEOF
python3 -c "import json,os; json.load(open(os.path.join(os.environ.get('APP_DIR','/app'),'security_report.json'))); print('report OK')"
