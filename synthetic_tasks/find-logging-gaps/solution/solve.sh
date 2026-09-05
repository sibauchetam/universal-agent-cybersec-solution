#!/usr/bin/env bash
set -euo pipefail
export APP_DIR="${APP_DIR:-/app}"
python3 - <<'PYEOF'
import json, os, pathlib

app = pathlib.Path(os.environ.get("APP_DIR", "/app"))
report = {
  "findings": [
    {
      "title": "Failed login attempts are never logged (CWE-223 / CWE-778)",
      "severity": "high",
      "category": "Insufficient Logging & Alerting",
      "location": "app/routers/auth.py: login (both denied branches)",
      "evidence": "Both deny branches in POST /login return {'status': 'denied'} silently: unknown usernames and wrong passwords produce no log record at all - failed login/auth failure events are invisible, so brute force cannot be detected.",
      "impact": "Password guessing and credential stuffing proceed undetected; incident responders cannot answer who attacked which account.",
      "recommendation": "Log every failed authentication with username, source IP, timestamp and reason; alert on spikes."
    },
    {
      "title": "Plaintext passwords written to logs (CWE-532)",
      "severity": "critical",
      "category": "Sensitive Data in Logs",
      "location": "app/routers/auth.py: login (logger.info 'login ok user=%s password=%s')",
      "evidence": "logger.info('login ok user=%s password=%s', req.username, req.password) records the cleartext password on every successful login; the logger/auth.py line leaks credentials to anyone with log access.",
      "impact": "Credential exposure via log files, log shippers and backups; password reuse makes it worse.",
      "recommendation": "Never log credentials; log user id only; scrub/redact sensitive fields at the logging layer."
    },
    {
      "title": "No timestamps or logger names in log format (CWE-778)",
      "severity": "medium",
      "category": "Insufficient Logging & Alerting",
      "location": "app/logging_setup.py: setup_logging (format='%(message)s')",
      "evidence": "logging.basicConfig(format='%(message)s') - no asctime/timestamp, no logger name, no level in the output, so events cannot be correlated with other sources.",
      "impact": "Without timestamps, log entries cannot be ordered or correlated during an investigation.",
      "recommendation": "Use a structured format including asctime, level, logger name and process info."
    },
    {
      "title": "Production log level filters out security events; audit trail fed from DEBUG (CWE-223)",
      "severity": "high",
      "category": "Insufficient Logging & Alerting",
      "location": "app/config/logging.prod.json (root level WARNING), app/logging_setup.py (level=ERROR), app/routers/admin.py: audit_trail",
      "evidence": "The root logger is configured at WARNING (prod config) while setup_logging() raises the threshold to ERROR; audit trail records are emitted via logger.debug('audit trail dump requested'), so the level filter drops them and GET /audit-trail can never produce entries - the level filter suppresses audit events.",
      "impact": "Audit trail is permanently empty in production; privileged activity is unrecorded.",
      "recommendation": "Emit audit records on a dedicated INFO+ audit logger/handler that is never filtered by the root level."
    },
    {
      "title": "Log injection via user-controlled note (CWE-117)",
      "severity": "medium",
      "category": "Log Injection",
      "location": "app/routers/auth.py: reset_password (logger.info ... note=%s)",
      "evidence": "The user-supplied note string is logged raw, including newlines, so an attacker can forge additional log entries (newline injection) and corrupt the log stream.",
      "impact": "Attackers can forge audit entries, hide their activity or inject misleading records.",
      "recommendation": "Sanitize/encode user-controlled values before logging (strip newlines, use structured JSON logging)."
    },
    {
      "title": "Privileged actions leave no durable record (CWE-778)",
      "severity": "high",
      "category": "Insufficient Logging & Alerting",
      "location": "app/routers/admin.py: grant_role (no log entry at all), app/routers/auth.py: reset_password (info-level only, filtered out)",
      "evidence": "POST /grant-role (privileged role grant) leaves no log entry at all; POST /reset-password logs only at INFO which the ERROR-level root logger filters, so privileged actions are unlogged and no durable timestamped record exists.",
      "impact": "Privilege escalation and account takeover cannot be reconstructed after an incident.",
      "recommendation": "Log all privileged actions to a dedicated append-only audit log with actor, target, timestamp and outcome."
    }
  ]
}

(app / "security_report.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"wrote {app / 'security_report.json'}")
PYEOF
python3 -c "import json,os; json.load(open(os.path.join(os.environ.get('APP_DIR','/app'),'security_report.json'))); print('report OK')"
