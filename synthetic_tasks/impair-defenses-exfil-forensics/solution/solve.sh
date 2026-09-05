#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
INC="$APP_DIR/incident"
[ -d "$INC" ] || { echo "solve: missing $INC" >&2; exit 1; }

REPORT=$(APP_DIR="$APP_DIR" python3 - <<'PY'
import base64, os, re
from collections import Counter
from pathlib import Path

inc = Path(os.environ["APP_DIR"]) / "incident"

# impaired service: systemctl stop <svc> (earlier than the pkill)
svc, when = None, None
for ln in (inc / "process_audit.log").read_text().splitlines():
    m = re.search(r"^(\S+) .*cmd=/usr/bin/systemctl stop (\S+)$", ln)
    if m:
        ts, name = m.group(1), m.group(2)
        if when is None or ts < when:
            svc, when = name, ts

# exfil domain: domains observed as CONNECT in the surviving kernel channel
kernel = (inc / "kernel_audit.log").read_text()
domains = set(re.findall(r"CONNECT tcp \S+ \(([^)]+)\)", kernel))
proxy = (inc / "proxy_access.log").read_text().splitlines()
totals = Counter()
for ln in proxy:
    m = re.match(r"^\S+ CONNECT ([^: ]+):443 \S+ bytes_sent=(\d+)$", ln)
    if m and m.group(1) in domains:
        totals[m.group(1)] += int(m.group(2))
domain = max(totals, key=lambda d: totals[d])

# staged payload: echo <outer-b64> | base64 -d | sh  -> double decode
staging, flag = None, None
for ln in kernel.splitlines():
    m = re.search(r"cmd=echo ([A-Za-z0-9+/=]+) \| base64 -d \| sh", ln)
    if m:
        stage1 = base64.b64decode(m.group(1)).decode()
        staging = re.search(r"mkdir -p (\S+)", stage1).group(1)
        inner = re.search(r"echo ([A-Za-z0-9+/=]+)", stage1).group(1)
        flag = base64.b64decode(inner).decode()

print(f"exfil_bytes={totals[domain]}")
print(f"exfil_domain={domain}")
print(f"flag={flag}")
print(f"impaired_service={svc}")
print(f"impair_time={when}")
print(f"staging_dir={staging}")
PY
)

# Ground truth from the spec
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_bytes=//p')" = "657083" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_domain=//p')" = "cdn-backup-sync.evil-repo-cdn.com" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^flag=//p')" = "FLAG{1mp41r_th3n_3xf1l}" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^impaired_service=//p')" = "auditd" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^impair_time=//p')" = "2025-03-14T22:07:19Z" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^staging_dir=//p')" = "/tmp/.s" ]

# Format validation: exactly 6 non-empty key=value lines, C-sorted
[ "$(printf '%s\n' "$REPORT" | grep -cve '^$')" -eq 6 ]
[ "$(printf '%s\n' "$REPORT" | grep -cE '^[a-z_]+=.+$')" -eq 6 ]
REPORT_SORTED="$(printf '%s\n' "$REPORT" | LC_ALL=C sort)"
printf '%s\n' "$REPORT_SORTED" > "$APP_DIR/incident_report.txt"
echo "solve: wrote 6-line incident report to $APP_DIR/incident_report.txt"
