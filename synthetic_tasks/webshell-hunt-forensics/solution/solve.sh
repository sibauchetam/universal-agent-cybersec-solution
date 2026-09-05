#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
INC="$APP_DIR/incident"
[ -d "$INC" ] || { echo "solve: missing $INC" >&2; exit 1; }

REPORT=$(APP_DIR="$APP_DIR" python3 - <<'PY'
import os, re
from datetime import datetime, timezone
from pathlib import Path

inc = Path(os.environ["APP_DIR"]) / "incident"

# 1. second stage: reverse hex -> unhex -> flag
py = next(p for p in (inc / "www/uploads").glob("*.py"))
src = py.read_text()
hexstr = re.search(r"_s\s*=\s*'([0-9a-fA-F]+)'", src).group(1)
stage2 = bytes.fromhex(hexstr[::-1]).decode()
flag = re.search(r"FLAG\{[^}]*\}", stage2).group(0)

# 2. activation timeline from access.log
shell = py.name
post_re = re.compile(r'^(\S+) - - \[([^\]]+)\] "POST (\S+) HTTP/1\.1" (\d{3}) ')
get_re = re.compile(r'^(\S+) - - \[([^\]]+)\] "GET (\S+) HTTP/1\.1" (\d{3}) ')
first_post = None
cmds = 0
for ln in (inc / "access.log").read_text().splitlines():
    m = post_re.match(ln) or get_re.match(ln)
    if not m:
        continue
    ip, ts, path, status = m.groups()
    if shell not in path:
        continue
    if ln.split('"')[1].startswith("POST") and status == "200" and first_post is None:
        first_post = (ip, ts)
    if "cmd=" in path:
        cmds += 1
ip, raw_ts = first_post
dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
first_activated = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
print(f"attacker_ip={ip}")
print(f"commands_run={cmds}")
print(f"first_activated={first_activated}")
print(f"flag={flag}")
print(f"webshell_path=/app/incident/www/uploads/{shell}")
PY
)

# Ground truth from the spec
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^attacker_ip=//p')" = "203.0.113.66" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^commands_run=//p')" = "3" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^first_activated=//p')" = "2025-03-11T09:41:22Z" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^flag=//p')" = "FLAG{w3bsh3ll_av4t4r_9f3c_p0sted_0905}" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^webshell_path=//p')" = "/app/incident/www/uploads/avatar_8f3c.py" ]

# Format validation: exactly 5 non-empty key=value lines, C-sorted
[ "$(printf '%s\n' "$REPORT" | grep -cve '^$')" -eq 5 ]
[ "$(printf '%s\n' "$REPORT" | grep -cE '^[a-z_]+=.+$')" -eq 5 ]
[ "$(printf '%s\n' "$REPORT" | LC_ALL=C sort)" = "$(printf '%s\n' "$REPORT")" ]
printf '%s\n' "$REPORT" > "$APP_DIR/incident_report.txt"
echo "solve: wrote 5-line incident report to $APP_DIR/incident_report.txt"
