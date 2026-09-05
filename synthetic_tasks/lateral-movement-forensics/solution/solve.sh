#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
INC="$APP_DIR/incident"
[ -d "$INC" ] || { echo "solve: missing $INC" >&2; exit 1; }

REPORT=$(APP_DIR="$APP_DIR" python3 - <<'PY'
import os, re
from collections import Counter
from pathlib import Path

inc = Path(os.environ["APP_DIR"]) / "incident"

year = int(re.search(r"(\d{4})", (inc / "README.txt").read_text()).group(1))
host_map = dict(re.findall(r"(\d+\.\d+\.\d+\.\d+)=(\S+)", (inc / "README.txt").read_text()))
months = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

def ts(key):
    mo, d, hms, _ = key
    return (year, months[mo], int(d), hms)

# accepted publickey events across all three auth logs
accepts = []
for f in sorted(inc.glob("auth_*.log")):
    host = re.match(r"auth_(\S+)\.log", f.name).group(1)
    for ln in f.read_text().splitlines():
        m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d:\d\d:\d\d) \S+ sshd\[\d+\]: "
                     r"Accepted publickey for \S+ from (\d+\.\d+\.\d+\.\d+) port \d+ ssh2: \S+ (SHA256:\S+)$", ln)
        if m:
            accepts.append(((m.group(1), m.group(2), m.group(3), host), host, m.group(4), m.group(5)))

fps = Counter(fp for _, _, _, fp in accepts)
fingerprint, successful = fps.most_common(1)[0]
# lateral accepts come from the compromised host's IP; earliest one is the first target
lat = sorted((k for k, host, src, fp in accepts
              if fp == fingerprint and host_map.get(src) is not None and host_map[src] != host),
             key=ts)
first_target = lat[0][3]
# compromised host is the SOURCE IP of the lateral accepts (derived above as
# host_map[src]); it is intentionally not part of the 6-line report.

# discovery: process snapshot filename carries the host; scan binary from its command line
snap = next(inc.glob("process_snapshot_*.txt"))
discovery_host = re.match(r"process_snapshot_(\S+)\.txt", snap.name).group(1)
scan_tool = None
for ln in snap.read_text().splitlines():
    m = re.search(r"pid=\d+\s+(\S+).*10\.0\.5\.0/24", ln)
    if m:
        scan_tool = m.group(1)

# flag: exit-gift in the staging notes on the pivot host
notes = (inc / "staging_db01/.ssh_notes").read_text()
flag = re.search(r"exit-gift: (FLAG\{[^}]*\})", notes).group(1)

print(f"discovery_source_host={discovery_host}")
print(f"first_lateral_target={first_target}")
print(f"flag={flag}")
print(f"key_fingerprint={fingerprint}")
print(f"scan_tool={scan_tool}")
print(f"successful_logins={successful}")
PY
)

# Ground truth from the spec
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^discovery_source_host=//p')" = "ci-runner" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^first_lateral_target=//p')" = "db01" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^flag=//p')" = "FLAG{l4t3r4l_v1a_sh4r3d_k3y}" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^key_fingerprint=//p')" = "SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^scan_tool=//p')" = "nmap" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^successful_logins=//p')" = "3" ]

# Format validation: exactly 6 non-empty key=value lines, C-sorted
[ "$(printf '%s\n' "$REPORT" | grep -cve '^$')" -eq 6 ]
[ "$(printf '%s\n' "$REPORT" | grep -cE '^[a-z_]+=.+$')" -eq 6 ]
REPORT_SORTED="$(printf '%s\n' "$REPORT" | LC_ALL=C sort)"
printf '%s\n' "$REPORT_SORTED" > "$APP_DIR/incident_report.txt"
echo "solve: wrote 6-line incident report to $APP_DIR/incident_report.txt"
