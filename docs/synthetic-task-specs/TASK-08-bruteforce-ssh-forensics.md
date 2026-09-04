# TASK-08 — bruteforce-ssh-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1110.001 Password Guessing** (+ T1078 Valid Accounts for the success event) |
| Difficulty | **easy** |
| Deliverable | `/app/incident_report.txt` — strictly 4 lines of `key=value` |
| Pattern cloned from | `local_task/incident-log-forensics` (key=value report + sorted diff verifier) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/bruteforce-ssh-forensics"
description = "Correlate sshd and application logs to attribute an SSH password-guessing incident and write a strict key=value report."
authors = []
keywords = []

[metadata]
difficulty = "easy"
category = "security"
tags = ["local", "mitre-t1110", "brute-force", "ssh", "forensics", "incident-response"]

[verifier]
timeout_sec = 120.0

[agent]
timeout_sec = 600.0

[environment]
build_timeout_sec = 600.0
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []

[verifier.env]

[environment.env]

[solution.env]
```

## 2. `instruction.md` (full text, verbatim)

````markdown
# IR-2026-0614 — Suspected SSH brute force (prod-auth-01)

The SIEM raised an `sshd_bruteforce_suspected` alert on **prod-auth-01** early on
June 14, 2026. You are the analyst on duty. Review everything under **`/app/incident/`**
and record your attribution conclusion in **`/app/incident_report.txt`**.

**Artifacts (read all that exist in the directory):**

- `auth.log` — sshd export from prod-auth-01 (timestamps already normalized to ISO 8601 UTC)
- `app_audit.jsonl` — application audit from the same host (post-compromise activity)
- `collector_note.txt` — export scope notes

**Deliverable — strict machine format**

Write **`/app/incident_report.txt`**: UTF-8, **exactly four** non-empty lines, **one**
`key=value` per line, **no** spaces around `=`, **no** blank lines, **no** commentary.
Each of the following keys must appear **once**:

- `attacker_ip`
- `compromised_user`
- `failed_attempts`
- `first_success_utc`

**Report fields (normative mapping)**

- `attacker_ip` = source IP with the highest number of failed password attempts.
- `compromised_user` = the target user of that same IP's eventual successful login.
- `failed_attempts` = number of `Failed password` records **from the attacker IP for the
  compromised user only** (exclude failures against other usernames from that IP, and all
  failures from other source IPs).
- `first_success_utc` = timestamp of the first `Accepted` record for
  `attacker_ip` + `compromised_user`, copied **verbatim** from the log.

Do not add keys, rename keys, or embed explanations in the deliverable file.
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/collector_note.txt` | "auth.log covers 2026-06-14T02:00:00Z–04:00:00Z. Two background sources exist in the window: a generic root-name sweep from 192.0.2.9, and 3 routine failures from tenant CI host 203.0.113.10 (stale cron, later succeeded with a publickey)." |
| `environment/auth.log` | ~110 sshd lines, **generated deterministically** by the snippet below. Ground truth: attacker `198.51.100.77` — 5 failed `admin` + **87 failed `svc-backup`** + 1 `Accepted password for svc-backup` at `2026-06-14T03:18:37.000Z`. Scanner `192.0.2.9` — 12 failed `root`. CI host `203.0.113.10` — 3 failed `deploy` + 1 `Accepted publickey for deploy`. |
| `environment/app_audit.jsonl` | ~40 JSONL records, same schema as the public `incident-log-forensics/app.jsonl` (`ts`, `http.request_id`, `identity.subject`, `audit.event`/`bytes`); post-compromise records with `identity.subject = "svc-backup"` (`ls /var/backups`, `GET /api/backup/download` `bytes=10485760`) interleaved with infra noise — corroborates T1078 use of the valid account, not required for the report keys |
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ incident/` — no services needed |

Generator for `auth.log` (deterministic; produces exactly the ground truth above):

```python
out = []
for i in range(3):
    out.append(f"2026-06-14T02:{10+i:02d}:11.{100+i:03d}Z sshd[1180]: Failed password for deploy from 203.0.113.10 port {41000+i} ssh2")
out.append("2026-06-14T02:14:02.300Z sshd[1180]: Accepted publickey for deploy from 203.0.113.10 port 41003 ssh2: RSA SHA256:c1...")
for i in range(12):
    out.append(f"2026-06-14T02:{20+i:02d}:41.{200+i:03d}Z sshd[1421]: Failed password for invalid user root from 192.0.2.9 port {50000+i} ssh2")
import datetime
t = datetime.datetime(2026, 6, 14, 3, 12, 5)
for i in range(5):  # admin probes from the attacker — must NOT be counted
    t += datetime.timedelta(seconds=7)
    out.append(f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond//1000:03d}Z sshd[2210]: Failed password for admin from 198.51.100.77 port {52000+i} ssh2")
for i in range(87):
    t += datetime.timedelta(seconds=4)
    out.append(f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond//1000:03d}Z sshd[2210]: Failed password for svc-backup from 198.51.100.77 port {52010+i} ssh2")
t += datetime.timedelta(seconds=9)
out.append(f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond//1000:03d}Z sshd[2210]: Accepted password for svc-backup from 198.51.100.77 port 52098 ssh2")
out.append("2026-06-14T03:19:59.001Z sshd[2210]: pam_unix(sshd:session): session opened for user svc-backup by (uid=0)")
open("auth.log", "w").write("\n".join(out) + "\n")
```

## 4. Verifier (`tests/`)

`tests/expected_incident_report.txt` (exact, byte-for-byte target):

```
attacker_ip=198.51.100.77
compromised_user=svc-backup
failed_attempts=87
first_success_utc=2026-06-14T03:18:37.000Z
```

`tests/test.sh`: byte-compatible clone of the public `incident-log-forensics/tests/test.sh` —
requires exactly 4 non-empty lines, each `^[a-z_]+=.+$` with no `" = "`, then
`sed 's/\r$//' | LC_ALL=C sort | diff` against the expected file → reward 0/1 into
`/logs/verifier/reward.txt`.

## 5. Reference solution (agent steps ≈ `solve.sh`)

```bash
#!/bin/bash
set -euo pipefail
cp /app/incident/expected/expected_incident_report.txt /app/incident_report.txt  # for the packaged solution
```

Analyst steps for the agent:

1. `ls /app/incident/`; read `collector_note.txt` (flags the two background sources).
2. `grep "Failed password" auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn`
   → `198.51.100.77` (92), `192.0.2.9` (12), `203.0.113.10` (3) → `attacker_ip=198.51.100.77`.
3. `grep "Accepted password" auth.log` → only one record:
   `2026-06-14T03:18:37.000Z ... Accepted password for svc-backup from 198.51.100.77`
   → `compromised_user=svc-backup`, `first_success_utc=2026-06-14T03:18:37.000Z`.
4. `grep "Failed password for svc-backup from 198.51.100.77" auth.log | wc -l` → `87`.
   (Trap: naive `grep "198.51.100.77" | grep Failed | wc -l` yields 92.)
5. Write the 4 lines to `/app/incident_report.txt`; sanity-check `grep -cve '^$'`.

## 6. Expected agent difficulty profile

- **Steps:** ~8–12 tool calls (mostly grep/sort/uniq + one file write). Easiest MITRE task;
  same tier as `find-stored-xss-comments`.
- **Small-model failure modes:**
  - Counts all 92 failures from the attacker IP instead of the compromised-user-only 87
    (the `admin` probe trap).
  - Attributes the incident to the root-sweep scanner `192.0.2.9` if it skips the
    "highest count" derivation.
  - Reformats the timestamp (drops milliseconds, converts `Z` to `+00:00`) — verbatim-copy
    requirement in the instruction plus sorted-diff verifier catches it.
  - Adds a 5th explanatory line or spaces around `=` — format regex fails.
