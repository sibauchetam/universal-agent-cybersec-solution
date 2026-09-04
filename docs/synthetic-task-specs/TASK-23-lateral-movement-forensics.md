# TASK-23 — lateral-movement-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1021.004 Remote Services: SSH** (+ T1046 Network Service Discovery, T1552.004 Private Keys) |
| Difficulty | medium |
| Deliverable | `/app/incident_report.txt` — strictly 6 lines of `key=value` |
| Pattern cloned from | `local_task/incident-log-forensics` + `docs/synthetic-task-specs/TASK-08` (key=value + sorted diff) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/lateral-movement-forensics"
description = "Correlate SSH auth logs from three hosts and a process snapshot to reconstruct an attacker's lateral movement: discovery tooling, source host, shared key fingerprint, pivot order. Strict key=value report."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "mitre-t1021.004", "t1046", "ssh", "lateral-movement", "forensics"]

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
You are working in `/app/incident/` — a read-only bundle from a three-host
segment: `web01`, `db01`, `ci-runner`. For each host there is an SSH
`auth.log`; additionally `process_snapshot_ci-runner.txt` and
`netflow_sample.csv` capture what ran and what flowed during the window.

The attacker compromised `ci-runner`, discovered the segment, then moved
laterally with a key that was (wrongly) shared across hosts. Reconstruct
the movement.

Write a forensic report to:

`/app/incident_report.txt`

The report must contain EXACTLY 6 lines, each in `key=value` format, sorted
alphabetically by key. No extra lines, no comments.

Required keys (alphabetical order):

discovery_source_host=<host where the segment scan was executed>
first_lateral_target=<first OTHER host that accepted the shared key from the compromised host, chronologically>
flag=<FLAG{...} found in the attacker's staging on the last pivoted host>
key_fingerprint=<the SHA256:... fingerprint of the reused SSH key>
scan_tool=<binary name used for segment discovery>
successful_logins=<integer: total number of successful key-based logins with the reused key across ALL hosts in the window>

Do not modify any file inside `/app/incident/`.
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ /app/incident/`, `CMD ["sleep", "infinity"]` |
| `environment/incident/auth_web01.log` | sshd noise + accepted keys (see below) |
| `environment/incident/auth_db01.log` | sshd noise + accepted keys + staging flag trace |
| `environment/incident/auth_ci-runner.log` | compromise origin: brute-force → shell → scan |
| `environment/incident/process_snapshot_ci-runner.txt` | `nmap -p 22 10.0.5.0/24` invocation, `ssh -i` commands |
| `environment/incident/netflow_sample.csv` | flows web01↔db01↔ci-runner (decoy noise) |
| `environment/incident/staging_db01/.ssh_notes` | attacker notes with flag (see below) |

`environment/incident/process_snapshot_ci-runner.log` (key lines):

```
2025-04-02T03:12:09Z  pid=2210  nmap -p 22 --open 10.0.5.0/24 -oN /tmp/.scan
2025-04-02T03:14:41Z  pid=2215  ssh -i /home/ci/.ssh/id_rsa_ci deploy@10.0.5.22
2025-04-02T03:15:52Z  pid=2221  ssh -i /home/ci/.ssh/id_rsa_ci deploy@10.0.5.30
```

`environment/incident/auth_web01.log` (key lines):

```
Apr  2 03:15:11 web01 sshd[7312]: Accepted publickey for deploy from 10.0.5.14 port 51022 ssh2: ED25519 SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64
Apr  2 03:15:20 web01 sshd[7330]: Accepted publickey for deploy from 10.0.5.14 port 51024 ssh2: ED25519 SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64
Apr  1 21:44:02 web01 sshd[6102]: Accepted publickey for deploy from 10.0.5.2 port 49111 ssh2: ED25519 SHA256:qZ8xExampleNotReusedKey0000000000000000000000000
```

`environment/incident/auth_db01.log` (key lines):

```
Apr  2 03:14:44 db01 sshd[9110]: Accepted publickey for deploy from 10.0.5.14 port 40012 ssh2: ED25519 SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64
Apr  2 03:14:58 db01 systemd[1]: Started Session c2 of user deploy.
Apr  2 03:21:07 db01 sudo: deploy : TTY=pts/0 ; PWD=/tmp/.stg ; USER=root ; COMMAND=/bin/cat /tmp/.stg/.ssh_notes
```

(10.0.5.14 = ci-runner, 10.0.5.22 = db01, 10.0.5.30 = web01 per bundle README.)

`environment/incident/staging_db01/.ssh_notes` (verbatim):

```
# working notes
shared key -> fp J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64 (id_rsa_ci everywhere, lol)
next: dump pg_creds from /etc/postgresql/15/main/pgpass
exit-gift: FLAG{l4t3r4l_v1a_sh4r3d_k3y}
```

Expected answer set (deterministic):

```
discovery_source_host=ci-runner
first_lateral_target=db01
flag=FLAG{l4t3r4l_v1a_sh4r3d_k3y}
key_fingerprint=SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64
scan_tool=nmap
successful_logins=3
```

Traps: (a) `first_lateral_target` requires IP→host mapping from README (03:14:44 db01
is EARLIER than 03:15:11 web01 despite web01 being alphabetically first); (b)
`successful_logins` counts ONLY the reused-fingerprint key (3: two to web01, one to
db01) — the 21:44:02 login from 10.0.5.2 with a different key is a decoy and must NOT
be counted; (c) fingerprint appears with and without the `SHA256:` prefix in different
artifacts — report wants the sshd form; (d) flag lives on db01 (the FIRST pivot), but
the key says "last pivoted host" — the bundle shows only two pivots, so db01's notes
are the exit point; agents over-thinking the "last" wording chase web01 and fail.

## 4. Verifier (`tests/`)

`tests/test.sh`: reward 0/1, pytest (no service).
`tests/test_report.py` (hidden verifier):

```python
from pathlib import Path

EXPECTED = """discovery_source_host=ci-runner
first_lateral_target=db01
flag=FLAG{l4t3r4l_v1a_sh4r3d_k3y}
key_fingerprint=SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64
scan_tool=nmap
successful_logins=3"""

def test_report_exact():
    got = Path("/app/incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
```

**Grading:** binary 0/1 — sorted line diff empty.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. Read README → IP↔host map.
2. Process snapshot → `nmap` → scan_tool; source host ci-runner.
3. Grep all three auth logs for the reused fingerprint → count 3.
4. Sort accepted-key events by timestamp → db01 first.
5. Read `.ssh_notes` on db01 → flag.
6. Write 6 sorted lines.

## 6. Expected agent difficulty profile

- **Steps:** ~10–16 tool calls (4 artifacts + cross-host chronology).
- **Small-model failure modes:**
  - Picks web01 as first target (alphabetical, not chronological).
  - Counts 4 successful logins (includes the decoy different-key login).
  - Fingerprint without `SHA256:` prefix or copied from the notes (no prefix) — diff fails.
  - Scan tool reported as `ssh` or `masscan` (nmap appears verbatim once).
  - Misses the flag file because it only reads auth logs.
