#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
INC="$APP_DIR/incident"
[ -d "$INC" ] || { echo "solve: missing $INC" >&2; exit 1; }

REPORT=$(APP_DIR="$APP_DIR" python3 - <<'PY'
import base64, os, re
from pathlib import Path

inc = Path(os.environ["APP_DIR"]) / "incident"

# uid-0 accounts -> rogue = the one that is not root
rogue, uid = None, None
for ln in (inc / "etc/passwd.snapshot").read_text().splitlines():
    f = ln.split(":")
    if len(f) > 2 and f[2] == "0" and f[0] != "root":
        rogue, uid = f[0], int(f[2])

# account creation from auth.log (syslog dates need the snapshot year from README)
year = int(re.search(r"(\d{4})", (inc / "README.txt").read_text()).group(1))
months = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
created = None
for ln in (inc / "var/log/auth.log").read_text().splitlines():
    m = re.search(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d:\d\d:\d\d) \S+ useradd\[\d+\]: "
                  r"new account: user=svc-update, uid=0", ln)
    if m:
        created = f"{year}-{months[m.group(1)]:02d}-{int(m.group(2)):02d}T{m.group(3)}Z"

# masquerade binary: cron-invoked /usr/local/sbin path whose listed mtime is >= account creation
created_dt = created
cands = set()
for cf in (inc / "etc/cron.d").iterdir():
    for cmd in re.findall(r"/usr/local/sbin/\S+", cf.read_text()):
        cands.add(cmd.rstrip())
binary = None
for ln in (inc / "usr_local_sbin_listing.txt").read_text().splitlines():
    m = re.match(r"([^,]+),(\d+),(\d+),(\S+)", ln)
    if not m:
        continue
    name, _size, _mode, mtime = m.groups()
    full = f"/usr/local/sbin/{name}"
    if full in cands and mtime >= created_dt:
        binary = full

# flag: decode the base64 blob the rogue binary drops
bin_text = (inc / "usr_local_sbin/systemd-updat").read_text()
blob = re.search(r"printf '([A-Za-z0-9+/=]+)'", bin_text).group(1)
flag = base64.b64decode(blob).decode()

print(f"account_created={created}")
print(f"flag={flag}")
print(f"masquerade_binary={binary}")
print(f"rogue_account={rogue}")
print(f"rogue_uid={uid}")
PY
)

# Ground truth from the spec
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^account_created=//p')" = "2025-03-12T02:11:43Z" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^flag=//p')" = "FLAG{masquerade_syst3md_updat}" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^masquerade_binary=//p')" = "/usr/local/sbin/systemd-updat" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^rogue_account=//p')" = "svc-update" ]
[ "$(printf '%s\n' "$REPORT" | sed -n 's/^rogue_uid=//p')" = "0" ]

# Format validation: exactly 5 non-empty key=value lines, C-sorted
[ "$(printf '%s\n' "$REPORT" | grep -cve '^$')" -eq 5 ]
[ "$(printf '%s\n' "$REPORT" | grep -cE '^[a-z_]+=.+$')" -eq 5 ]
[ "$(printf '%s\n' "$REPORT" | LC_ALL=C sort)" = "$(printf '%s\n' "$REPORT")" ]
printf '%s\n' "$REPORT" > "$APP_DIR/incident_report.txt"
echo "solve: wrote 5-line incident report to $APP_DIR/incident_report.txt"
