# TASK-22 — impair-defenses-exfil-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1562.001 Impair Defenses: Disable Tools** (+ T1041 Exfiltration Over C2 Channel) |
| Difficulty | **hard** |
| Deliverable | `/app/incident_report.txt` — strictly 6 lines of `key=value` |
| Pattern cloned from | `local_task/incident-log-forensics` + `docs/synthetic-task-specs/TASK-10` (multi-log key=value) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/impair-defenses-exfil-forensics"
description = "Correlate a process-audit log, a surviving kernel-audit channel and a proxy log: identify which defense was impaired, when, the HTTPS exfiltration destination, exact bytes sent and a staged flag. Strict key=value report."
authors = []
keywords = []

[metadata]
difficulty = "hard"
category = "security"
tags = ["local", "mitre-t1562.001", "t1041", "impair-defenses", "exfiltration", "proxy", "forensics"]

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
You are working in `/app/incident/` — a read-only evidence bundle:

- `process_audit.log` — EDR agent's process telemetry (STOPPED mid-incident).
- `kernel_audit.log` — a SECOND, independent telemetry channel that kept
  recording after the first one was killed.
- `proxy_access.log` — egress proxy: CONNECT sessions with byte counters.

A compromised CI account impaired defenses, staged data, then exfiltrated it
over HTTPS. Reconstruct the incident.

Write a forensic report to:

`/app/incident_report.txt`

The report must contain EXACTLY 6 lines, each in `key=value` format, sorted
alphabetically by key. No extra lines, no comments.

Required keys (alphabetical order):

exfil_bytes=<integer: total bytes SENT to the exfiltration domain across all CONNECT sessions, from proxy counters>
exfil_domain=<the domain the data was exfiltrated to>
flag=<FLAG{...} from the attacker's staged payload, visible only in the surviving channel>
impaired_service=<name of the defense service that was stopped>
impair_time=<UTC timestamp YYYY-MM-DDTHH:MM:SSZ of the stop command>
staging_dir=<absolute path of the staging directory>

Do not modify any file inside `/app/incident/`.
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ /app/incident/`, `CMD ["sleep", "infinity"]` |
| `environment/incident/process_audit.log` | EDR telemetry, 40 lines; ends with impairment (see below) |
| `environment/incident/kernel_audit.log` | surviving channel; contains the staged payload echo (see below) |
| `environment/incident/proxy_access.log` | 60 lines; legit CONNECTs (github.com, pypi.org) + exfil sessions |
| `environment/incident/README.txt` | snapshot metadata: year 2025, timezone UTC |

`environment/incident/process_audit.log` (key lines):

```
2025-03-14T21:58:02Z pid=8800 user=dev-ci cmd=/usr/bin/git fetch origin
2025-03-14T22:07:19Z pid=8831 user=dev-ci cmd=/usr/bin/systemctl stop auditd
2025-03-14T22:07:44Z pid=8840 user=dev-ci cmd=/usr/bin/pkill -f filebeat
2025-03-14T22:08:11Z pid=8855 user=dev-ci cmd=/usr/bin/tar czf /tmp/.s/cache.tar.gz /var/cache/app
<telemetry ends — EDR halted by auditd stop>
```

`environment/incident/kernel_audit.log` (key lines):

```
2025-03-14T22:09:37Z SYSCALL execve pid=8902 user=dev-ci cmd=echo bWtkaXIgLXAgL3RtcC8ucyAmJiBlY2hvIFJreEJSM3N4YlhBME1YSmZkR2d6Ymw4emVHWXhiSDA9ID4gL3RtcC8ucy9wYXlsb2Fk | base64 -d | sh
2025-03-14T22:11:03Z CONNECT tcp 10.0.4.51:443 (cdn-backup-sync.evil-repo-cdn.com)
... (further FS events in /tmp/.s/) ...
```

(the base64 pipeline decodes to `mkdir -p /tmp/.s && echo RkxBR3ttYXNxdWVyYWRlX...` —
actually to `echo <inner-b64> > /tmp/.s/payload`; the inner base64 decodes to the flag
`FLAG{1mp41r_th3n_3xf1l}` — a two-layer decode the agent must perform mechanically.)

`environment/incident/proxy_access.log` (key lines; `bytes_sent` column):

```
2025-03-14T22:11:03Z CONNECT cdn-backup-sync.evil-repo-cdn.com:443 user=dev-ci bytes_sent=131072
2025-03-14T22:16:47Z CONNECT cdn-backup-sync.evil-repo-cdn.com:443 user=dev-ci bytes_sent=131072
2025-03-14T22:23:15Z CONNECT cdn-backup-sync.evil-repo-cdn.com:443 user=dev-ci bytes_sent=65536
2025-03-14T22:31:58Z CONNECT cdn-backup-sync.evil-repo-cdn.com:443 user=dev-ci bytes_sent=131072
2025-03-14T22:47:22Z CONNECT cdn-backup-sync.evil-repo-cdn.com:443 user=dev-ci bytes_sent=98304
2025-03-14T23:48:55Z CONNECT cdn-backup-sync.evil-repo-cdn.com:443 user=dev-ci bytes_sent=100027
2025-03-14T22:50:01Z CONNECT pypi.org:443 user=dev-ci bytes_sent=4211        <- decoy, legit
2025-03-14T23:02:33Z CONNECT github.com:443 user=dev-ci bytes_sent=18432     <- decoy, legit
```

Total exfil bytes (deterministic): 131072+131072+65536+131072+98304+100027 = **657083**.

Expected answer set:

```
exfil_bytes=657083
exfil_domain=cdn-backup-sync.evil-repo-cdn.com
flag=FLAG{1mp41r_th3n_3xf1l}
impaired_service=auditd
impair_time=2025-03-14T22:07:19Z
staging_dir=/tmp/.s
```

Traps: (a) the EDR channel DIES at 22:08 — the staging payload is only in the surviving
kernel channel; agents that stop reading after the first log miss the flag; (b) `pkill -f
filebeat` is also impairment, but the report wants the STOPPED SERVICE (`auditd`, from
`systemctl stop`), at the earlier timestamp; (c) byte counters include two legit CONNECT
sessions — must be excluded by domain; (d) double base64 decode required; (e) decoy
domain `evil-repo-cdn.net` (one-legit-looking typo domain) appears in kernel log as DNS
denial — only `.com` actually carried bytes.

## 4. Verifier (`tests/`)

`tests/test.sh`: reward 0/1, pytest (no service).
`tests/test_report.py` (hidden verifier):

```python
from pathlib import Path

EXPECTED = """exfil_bytes=657083
exfil_domain=cdn-backup-sync.evil-repo-cdn.com
flag=FLAG{1mp41r_th3n_3xf1l}
impaired_service=auditd
impair_time=2025-03-14T22:07:19Z
staging_dir=/tmp/.s"""

def test_report_exact():
    got = Path("/app/incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
```

**Grading:** binary 0/1 — sorted line diff empty.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read README (year/TZ) → normalize timestamps.
2. Grep `systemctl stop` → `auditd` @ 22:07:19Z.
3. Extract CONNECT lines for the recurring domain; sum `bytes_sent` → 657083.
4. In `kernel_audit.log`: extract the base64 pipeline → decode twice → flag.
5. Staging dir from the decoded first command (`/tmp/.s`).
6. Write 6 sorted lines.

## 6. Expected agent difficulty profile

- **Steps:** ~12–22 tool calls (3 logs + 2-layer decode + arithmetic).
- **Small-model failure modes:**
  - Sums bytes over ALL proxy sessions (incl. pypi/github) → wrong total.
  - Picks `filebeat` or `filebeat`/`auditd` in wrong order for impaired_service/time.
  - Single decodes the pipeline and reports the intermediate base64 as flag.
  - Reports `/tmp/.s/cache.tar.gz` (file) instead of `/tmp/.s` (dir).
  - Misses that telemetry ended — never opens `kernel_audit.log`.
