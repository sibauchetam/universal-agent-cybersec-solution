#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
INC="$APP_DIR/incident"
[ -d "$INC" ] || { echo "solve: missing $INC" >&2; exit 1; }

REPORT=$(APP_DIR="$APP_DIR" python3 - <<'PY'
import os, re
from pathlib import Path

inc = Path(os.environ["APP_DIR"]) / "incident"
domain = "d7data.example.net"
seqs = {}
for ln in (inc / "dns_queries.log").read_text().splitlines():
    m = re.search(r"q=(\d+)-(\d+)-([0-9a-f]+)\." + re.escape(domain), ln)
    if m:
        seq, total, hx = m.groups()
        seqs.setdefault(int(seq), hx)  # retransmissions are exact duplicates
data = b"".join(bytes.fromhex(seqs[k]) for k in sorted(seqs))
flag = re.search(rb"flag\{[^}]*\}", data).group(0).decode()
audit = (inc / "auditd_exec.log").read_text()
staged = re.search(r'"cp","([^"]+)","([^"]+)"', audit).group(2)
print(f"exfil_domain={domain}")
print(f"exfil_file={staged}")
print(f"exfil_chunks={len(seqs)}")
print(f"exfil_bytes={len(data)}")
print(f"exfil_flag={flag}")
PY
)

# Ground truth from the spec
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_chunks=//p')" = "16" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_bytes=//p')" = "512" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_flag=//p')" = "flag{dn5_3xf1l_h4rd}" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_file=//p')" = "/tmp/.archive/dbexport.bin" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^exfil_domain=//p')" = "d7data.example.net" ]

# Format validation: exactly 5 non-empty key=value lines, LC_ALL=C sorted, no ' = '
[ "$(printf '%s\n' "$REPORT" | grep -cve '^$')" -eq 5 ]
[ "$(printf '%s\n' "$REPORT" | grep -cE '^[a-z_]+=.+$')" -eq 5 ]
REPORT_SORTED="$(printf '%s\n' "$REPORT" | LC_ALL=C sort)"
printf '%s\n' "$REPORT_SORTED" > "$APP_DIR/incident_report.txt"
echo "solve: wrote 5-line incident report to $APP_DIR/incident_report.txt"
