#!/usr/bin/env bash
set -euo pipefail
export APP_DIR="${APP_DIR:-/app}"
python3 - <<'PYEOF'
import json, os, pathlib

app = pathlib.Path(os.environ.get("APP_DIR", "/app"))
report = {
  "findings": [
    {
      "title": "Debug mode and verbose exception pages enabled for production (CWE-489 / CWE-209)",
      "severity": "high",
      "category": "Security Misconfiguration / Verbose Errors",
      "location": "app/config.py (DEBUG), app/main.py: FastAPI(debug=config.DEBUG), debug_error exception handler",
      "evidence": "config.py sets DEBUG = True and it is passed to FastAPI(debug=config.DEBUG). The global Exception handler returns {'error': str(exc), 'trace': traceback.format_exc()} to clients, so any unhandled error discloses full stack traces, file paths and internals. The service ships a development configuration rather than a hardened production one.",
      "impact": "Attackers learn framework versions, source paths and internal structure from stack traces, enabling targeted exploitation.",
      "recommendation": "Set DEBUG=False in production, return generic error pages, log tracebacks server-side only."
    },
    {
      "title": "Wildcard CORS combined with allow_credentials (CWE-942)",
      "severity": "high",
      "category": "Security Misconfiguration / CORS",
      "location": "app/main.py: CORSMiddleware(allow_origins=['*'], allow_credentials=True)",
      "evidence": "CORSMiddleware is configured with allow_origins=['*'] (wildcard) together with allow_credentials=True, allow_methods=['*'], allow_headers=['*'] - an invalid and unsafe combination for credentialed requests.",
      "impact": "Any origin can interact with credentialed endpoints; cross-origin data theft from authenticated admin sessions.",
      "recommendation": "Allowlist explicit trusted origins; never combine wildcard origins with credentials."
    },
    {
      "title": "Default admin credentials committed and documented (CWE-798)",
      "severity": "critical",
      "category": "Security Misconfiguration / Default Credentials",
      "location": "app/config.py (ADMIN_USER/ADMIN_PASSWORD), app/README.md (seeded credentials), app/routers/admin.py: login",
      "evidence": "config.py hardcodes ADMIN_USER='admin' and ADMIN_PASSWORD='admin123' (default credential, never rotated); the committed README.md documents 'first login: admin / admin123'; routers/admin.py grants a session when these constants match.",
      "impact": "Anyone with repository or documentation access logs into the admin dashboard with well-known default credentials.",
      "recommendation": "Remove seeded credentials from code and docs; require per-user accounts with strong passwords; force rotation on first login."
    },
    {
      "title": "Unauthenticated /debug/env endpoint dumps the full process environment (CWE-200)",
      "severity": "critical",
      "category": "Security Misconfiguration / Sensitive Data Exposure",
      "location": "app/main.py: GET /debug/env (debug_env)",
      "evidence": "The debug_env handler returns dict(os.environ) with no authentication, exposing every environment variable including API keys, secrets and DB credentials.",
      "impact": "Unauthenticated secret disclosure: all deployment secrets are readable by anyone who can reach the service.",
      "recommendation": "Remove the endpoint from production builds; gate any diagnostics behind authentication."
    },
    {
      "title": "Static file mount exposes directory listing and application source (CWE-548)",
      "severity": "high",
      "category": "Security Misconfiguration / Information Exposure",
      "location": "app/main.py: app.mount('/static', StaticFiles(directory='.', show_dir_listing=True))",
      "evidence": "StaticFiles is mounted on the application root directory with show_dir_listing=True, so /static/ lists files and serves source files such as config.py (and any committed .env) to anyone.",
      "impact": "Source code, configuration and secret files are downloadable; directory listing simplifies attacker reconnaissance.",
      "recommendation": "Serve only a dedicated static assets directory, disable directory listing, never mount the app root."
    },
    {
      "title": "Insecure session cookies with static predictable token (CWE-614 / CWE-330)",
      "severity": "high",
      "category": "Security Misconfiguration / Session Management",
      "location": "app/config.py (SESSION_COOKIE_SECURE/HTTPONLY), app/routers/admin.py: response.set_cookie('session', ...)",
      "evidence": "config.py sets SESSION_COOKIE_SECURE=False and SESSION_COOKIE_HTTPONLY=False (readable from JS); routers/admin.py issues a static token 'fixed-session-token-0001' via set_cookie without secure/httponly/samesite flags.",
      "impact": "Sessions are guessable/impersonatable and stealable via XSS; cookies travel over plain HTTP.",
      "recommendation": "Issue cryptographically random per-session tokens; set Secure, HttpOnly and SameSite flags."
    },
    {
      "title": "Hardcoded development SECRET_KEY fallback (CWE-1188)",
      "severity": "medium",
      "category": "Security Misconfiguration / Insecure Default",
      "location": "app/config.py: SECRET_KEY",
      "evidence": "SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me') falls back to a public well-known development value when the environment variable is unset.",
      "impact": "Tokens/cookies signed with a publicly known key can be forged if deployment forgets to set SECRET_KEY.",
      "recommendation": "Fail startup when SECRET_KEY is not provided; never ship a default secret."
    }
  ]
}

(app / "security_report.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"wrote {app / 'security_report.json'}")
PYEOF
python3 -c "import json,os; json.load(open(os.path.join(os.environ.get('APP_DIR','/app'),'security_report.json'))); print('report OK')"
