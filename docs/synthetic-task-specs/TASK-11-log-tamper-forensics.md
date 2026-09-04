# TASK-11 — log-tamper-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1070.002 Clear Linux or Mac System Files** + **T1070.006 Timestomp** |
| Difficulty | **hard** |
| Deliverable | `/app/incident_report.txt` — strictly 5 lines of `key=value` (cross-artifact reasoning) |
| Pattern cloned from | `local_task/incident-log-forensics` (key=value report + sorted diff verifier), extended to 5 keys |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/log-tamper-forensics"
description = "Reconstruct an insider's anti-forensics activity: cleared sshd log, timestomped manifest file, and exact removed-line count from a SIEM snapshot."
authors = []
keywords = []

[metadata]
difficulty = "hard"
category = "security"
tags = ["local", "mitre-t1070", "indicator-removal", "timestomp", "forensics", "incident-response"]

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

[verifier.env]

[environment.env]

[solution.env]
```

## 2. `instruction.md` (full text, verbatim)

````markdown
# IR-2026-0411 — Log integrity incident (finance-app-01)

An integrity monitor fired after detecting a sudden drop in log volume on
**finance-app-01**. A forensic snapshot is under **`/app/incident/`**. Determine what the
insider did to cover their tracks and record it in **`/app/incident_report.txt`**.

**Artifacts (read all that exist in the directory):**

- `auditd_exec.log` — auditd `execve` records (the insider's shell activity, timestamped,
  ISO 8601 UTC).
- `auth.log` — the **current, post-tamper** sshd log as found on disk.
- `siem_auth_snapshot.log` — the SIEM's pre-tamper copy of the **same** sshd log stream.
- `files_stat.txt` — `stat` output captured for the suspicious files after the incident.

**Deliverable — strict machine format**

Write **`/app/incident_report.txt`**: UTF-8, **exactly five** non-empty lines, **one**
`key=value` per line, **no** spaces around `=`, **no** blank lines, **no** commentary:

- `tampered_log` — absolute path of the log file that was cleared on disk.
- `cleared_method` — exactly one of: `truncate`, `delete`, `edit`
  (normative: an `echo >` / redirection onto an **existing** file ⇒ `truncate`).
- `first_tamper_utc` — timestamp of the **first destructive shell command** from the auditd
  records, copied **verbatim** (that is the auditd timestamp, not the backdated value).
- `timestomped_file` — absolute path of the file whose mtime was manually backdated.
- `removed_lines` — number of sshd log lines present in the SIEM snapshot but missing from
  the on-disk log.

Do not add keys, rename keys, or embed explanations in the deliverable file.
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/auditd_exec.log` | 12 auditd records, generated to the exact spec below. Key records: `2026-04-11T02:16:31.845Z` `argv=["bash","-c","echo > /var/log/auth.log"]` (first destructive command) and `2026-04-11T02:17:02.110Z` `argv=["touch","-d","2026-03-29 08:00:00","/var/backups/ledger-export-manifest"]` (timestomp). Non-destructive noise: `tail -f /var/log/app.log`, `vim /etc/app/config.yml`, `grep -i payments /var/log/app.log`, `ls -la /var/backups`, `history -c` at the end (T1070.003 flavor) |
| `environment/auth.log` | the **on-disk** post-tamper sshd log — exactly **4** lines (boot banner, daemon start, one failed root probe, one accepted deploy login) |
| `environment/siem_auth_snapshot.log` | the SIEM pre-tamper copy — exactly **137** lines: 4 lines that survive on disk + 133 lines of night-session activity (failed/successful internal logins, sudo invocations of the insider `mreese`) |
| `environment/files_stat.txt` | stat outputs: `/var/log/auth.log` → `Modify: 2026-04-11 02:16:31.844…` (matches the destructive command, size 612), `/var/backups/ledger-export-manifest` → `Modify: 2026-03-29 08:00:00.000…` but `Change: 2026-04-11 02:17:02.110…` (mtime≠ctime ⇒ timestomping evidence) |
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ incident/` |

Generator (deterministic; asserts exact counts):

```python
surviving = [
    "2026-04-11T00:00:01.001Z sshd[901]: Server listening on 0.0.0.0 port 22.",
    "2026-04-11T00:00:02.100Z sshd[901]: Received signal 15; terminating.",
    "2026-04-11T00:01:00.220Z sshd[1102]: Failed password for root from 192.0.2.9 port 51000 ssh2",
    "2026-04-11T00:01:41.330Z sshd[1180]: Accepted publickey for deploy from 203.0.113.10 port 41003 ssh2",
]
tampered_tail = []
t = datetime.datetime(2026, 4, 10, 22, 0, 0)
for i in range(133):  # the removed history
    t += datetime.timedelta(seconds=37)
    user = "mreese" if i % 7 == 0 else "deploy"
    tampered_tail.append(
        f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond//1000:03d}Z "
        f"sshd[2210]: Failed password for {user} from 203.0.113.44 port {53000+i} ssh2"
    )
siem = sorted(surviving + tampered_tail)          # 137 lines
assert len(siem) == 137
open("siem_auth_snapshot.log", "w").write("\n".join(siem) + "\n")
open("auth.log", "w").write("\n".join(surviving) + "\n")   # 4 lines on disk
# auditd_exec.log: fixed records — the two above + 10 noise records around them
```

## 4. Verifier (`tests/`)

`tests/expected_incident_report.txt` (exact):

```
tampered_log=/var/log/auth.log
cleared_method=truncate
first_tamper_utc=2026-04-11T02:16:31.845Z
timestomped_file=/var/backups/ledger-export-manifest
removed_lines=133
```

`tests/test.sh`: the public `incident-log-forensics` verifier with the line-count check changed
from 4 to **5**; key regex `^[a-z_]+=.+$`, no `" = "`; normalize (`sed 's/\r$//'`),
`LC_ALL=C sort`, `diff` against expected → reward 0/1 into `/logs/verifier/reward.txt`.

## 5. Reference solution (agent steps ≈ `solve.sh`)

```bash
#!/bin/bash
set -euo pipefail
printf 'tampered_log=/var/log/auth.log\ncleared_method=truncate\nfirst_tamper_utc=2026-04-11T02:16:31.845Z\ntimestomped_file=/var/backups/ledger-export-manifest\nremoved_lines=133\n' > /app/incident_report.txt
```

Analyst steps for the agent:

1. Read `auditd_exec.log` end-to-end → identify `echo > /var/log/auth.log` (destructive,
   `truncate` per the normative mapping) and `touch -d` (timestomping).
   → `tampered_log=/var/log/auth.log`, `cleared_method=truncate`,
   `first_tamper_utc=2026-04-11T02:16:31.845Z`, `timestomped_file=/var/backups/ledger-export-manifest`.
2. Cross-check `files_stat.txt`: auth.log Modify == destructive ts; manifest mtime (2026-03-29)
   ≠ ctime (2026-04-11 02:17:02) — confirms the timestomp target and the ordering.
3. `wc -l siem_auth_snapshot.log auth.log` → 137 vs 4 → `removed_lines=133`.
4. Write the 5 key=value lines; verify exactly 5 non-empty lines.

## 6. Expected agent difficulty profile

- **Steps:** ~18–30 tool calls (4 artifacts, careful mapping, a couple of counts).
- **Small-model failure modes:**
  - `cleared_method=delete` (log looks "cleared") or `edit` (SIEM-vs-disk diff suggests editing)
    — the normative `echo >` ⇒ `truncate` rule in the instruction must be followed.
  - Copies the **backdated** time `2026-03-29 08:00:00` into `first_tamper_utc` instead of the
    auditd timestamp — the instruction calls this out explicitly.
  - `removed_lines` computed as 137 (SIEM total) or 137−4−1 (trailing-newline off-by-one)
    instead of 133 — needs careful `wc -l`/diff discipline.
  - Picks `timestomped_file=/var/log/auth.log` (mtime there also changed) instead of the
    manifest — the mtime≠ctime evidence in `files_stat.txt` is the discriminator.
  - `history -c` record tempts the model into reporting bash-history clearing as
    `tampered_log=/home/mreese/.bash_history` (a plausible but wrong answer; the SIEM/disk
    diff only exists for auth.log).
