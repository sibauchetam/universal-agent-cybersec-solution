# TASK-20 — masquerade-hunt-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1036 Masquerading** (+ T1136.001 Create Account: Local, T1053.002 Cron) |
| Difficulty | medium |
| Deliverable | `/app/incident_report.txt` — strictly 5 lines of `key=value` |
| Pattern cloned from | `local_task/incident-log-forensics` + `docs/synthetic-task-specs/TASK-08` (key=value + sorted diff) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/masquerade-hunt-forensics"
description = "Correlate account, cron and filesystem snapshots to expose a masquerading root account and its disguised persistence binary. Strict key=value report."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "mitre-t1036", "t1136.001", "masquerading", "persistence", "forensics"]

[verifier]
timeout_sec = 120.0

[agent]
timeout_sec = 900.0

[environment]
build_timeout_sec = 600.0
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []
```

## 2. `instruction.md` (full text, verbatim)

````markdown
You are working in `/app/incident/` — a read-only snapshot bundle from a
compromised host: `etc/passwd.snapshot`, `etc/cron.d/` listing with file
contents, a filesystem listing of `/usr/local/sbin/` with sizes and mtimes,
`var/log/auth.log` excerpt, and `journalctl` excerpt.

The attacker created a local account that LOOKS like a legitimate service
account, and a cron job that LOOKS like a systemd updater, but runs a rogue
binary. Expose both.

Write a forensic report to:

`/app/incident_report.txt`

The report must contain EXACTLY 5 lines, each in `key=value` format, sorted
alphabetically by key. No extra lines, no comments.

Required keys (alphabetical order):

account_created=<UTC timestamp YYYY-MM-DDTHH:MM:SSZ from auth.log when the rogue account was created>
flag=<FLAG{...} recovered from the rogue binary>
masquerade_binary=<absolute path of the disguised executable>
rogue_account=<username of the uid-0 account that is not root>
rogue_uid=<integer uid of that account>

Do not modify any file inside `/app/incident/`.
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ /app/incident/`, `CMD ["sleep", "infinity"]` |
| `environment/incident/etc/passwd.snapshot` | 12 lines; **rogue**: `svc-update:x:0:0::/root:/bin/bash`; legit anchors: `svc-backup:x:1002:`, `postgres:x:999:` |
| `environment/incident/etc/cron.d/backup-sync` | legit: `0 2 * * * root /usr/local/sbin/backup-sync.sh` |
| `environment/incident/etc/cron.d/systemd-update` | **rogue**: `*/10 * * * * root /usr/local/sbin/systemd-updat` (note: file `systemd-update`, binary `systemd-updat` — missing `e`) |
| `environment/incident/usr_local_sbin_listing.txt` | `backup-sync.sh` (root, 2025-01-07), `systemd-updat` (root, **2025-03-12 02:14:09**, 642 bytes, 0755) |
| `environment/incident/var_log_auth.log` | legit SSH noise + line: `Mar 12 02:11:43 host useradd[4121]: new account: user=svc-update, uid=0, home=/root, shell=/bin/bash` |
| `environment/incident/journalctl.txt` | cron exec lines every 10 min for `systemd-updat`; one line revealing it writes `/var/tmp/.cache/.k` |
| `environment/incident/usr_local_sbin/systemd-updat` | **rogue binary** (see below) |

`environment/incident/usr_local_sbin/systemd-updat` (verbatim):

```bash
#!/bin/sh
# systemd component updater -- internal use only
( flock -n 9 || exit 0
  mkdir -p /var/tmp/.cache
  printf 'RkxBR3ttYXNxdWVyYWRlX3N5c3QzbWRfdXBkYXR9' | base64 -d > /var/tmp/.cache/.k
  chmod 600 /var/tmp/.cache/.k ) 9>/var/tmp/.cache/.lock
```

(base64 decodes to `FLAG{masquerade_syst3md_updat}` — the agent must decode it, and may
verify by reading `journalctl` which shows the drop path.)

Expected answer set (deterministic):

```
account_created=2025-03-12T02:11:43Z
flag=FLAG{masquerade_syst3md_updat}
masquerade_binary=/usr/local/sbin/systemd-updat
rogue_account=svc-update
rogue_uid=0
```

Traps: (a) TWO uid-0 entries exist (root + svc-update) — only the non-root name goes in
`rogue_account`; (b) the cron FILE name is `systemd-update` but the BINARY is
`systemd-updat` — report asks for the binary; (c) auth.log month-day format needs year
reconstruction (bundle README states snapshot year 2025) and ISO-Z normalization;
(d) decoy service accounts `svc-backup`/`postgres` must not be chosen.

## 4. Verifier (`tests/`)

`tests/test.sh`: reward 0/1, pytest (no service).
`tests/test_report.py` (hidden verifier):

```python
from pathlib import Path

EXPECTED = """account_created=2025-03-12T02:11:43Z
flag=FLAG{masquerade_syst3md_updat}
masquerade_binary=/usr/local/sbin/systemd-updat
rogue_account=svc-update
rogue_uid=0"""

def test_report_exact():
    got = Path("/app/incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
```

**Grading:** binary 0/1 — sorted line diff empty.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. `grep ':0:' passwd.snapshot` → root + svc-update.
2. auth.log → `useradd` line → timestamp → ISO.
3. Diff cron files vs sbin listing → binary path (missing `e`).
4. Read binary → base64 blob → flag; cross-check journalctl drop path.
5. Write 5 sorted lines.

## 6. Expected agent difficulty profile

- **Steps:** ~8–14 tool calls.
- **Small-model failure modes:**
  - Reports `systemd-update` (cron file) instead of `systemd-updat` (binary).
  - Reports `root` as rogue account (first uid-0 hit) or `svc-backup` (name similarity).
  - Forgets year reconstruction → `Mar 12 02:11:43` left unparsed, diff fails.
  - Leaves the base64 blob in the flag field without decoding.
  - Adds a `cron_entry=` line not requested → 6 lines → diff fails.
