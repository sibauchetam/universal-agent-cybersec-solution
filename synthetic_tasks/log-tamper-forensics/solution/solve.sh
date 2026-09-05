#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
INC="$APP_DIR/incident"
[ -d "$INC" ] || { echo "solve: missing $INC" >&2; exit 1; }

REPORT=$(APP_DIR="$APP_DIR" python3 - <<'PY'
import ast, os, re
from pathlib import Path

inc = Path(os.environ["APP_DIR"]) / "incident"
audit = (inc / "auditd_exec.log").read_text().splitlines()
recs = []
for ln in audit:
    m = re.match(r"^(\S+) execve argv=(\[.*\])$", ln)
    if m:
        recs.append((m.group(1), ast.literal_eval(m.group(2))))
# first destructive command: echo > redirection onto an existing file => truncate (normative)
destructive = [(ts, argv) for ts, argv in recs if any(re.search(r"echo\s*>\s*/", a) for a in argv)]
first_ts, first_argv = destructive[0]
target = re.search(r"echo\s*>\s*(\S+)", [a for a in first_argv if "echo" in a][0]).group(1)
# timestomp: touch -d <backdated> <path>
touch = [(ts, argv) for ts, argv in recs if argv and argv[0] == "touch" and "-d" in argv][0]
tstomped = touch[1][-1]
siem = {l for l in (inc / "siem_auth_snapshot.log").read_text().splitlines() if l}
disk = {l for l in (inc / "auth.log").read_text().splitlines() if l}
removed = len(siem - disk)
print(f"tampered_log={target}")
print("cleared_method=truncate")
print(f"first_tamper_utc={first_ts}")
print(f"timestomped_file={tstomped}")
print(f"removed_lines={removed}")
PY
)

# Ground truth from the spec
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^tampered_log=//p')" = "/var/log/auth.log" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^cleared_method=//p')" = "truncate" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^first_tamper_utc=//p')" = "2026-04-11T02:16:31.845Z" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^timestomped_file=//p')" = "/var/backups/ledger-export-manifest" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^removed_lines=//p')" = "133" ]

# Format validation: exactly 5 non-empty key=value lines, LC_ALL=C sorted, no ' = '
[ "$(printf '%s\n' "$REPORT" | grep -cve '^$')" -eq 5 ]
[ "$(printf '%s\n' "$REPORT" | grep -cE '^[a-z_]+=.+$')" -eq 5 ]
REPORT_SORTED="$(printf '%s\n' "$REPORT" | LC_ALL=C sort)"
printf '%s\n' "$REPORT_SORTED" > "$APP_DIR/incident_report.txt"
echo "solve: wrote 5-line incident report to $APP_DIR/incident_report.txt"
