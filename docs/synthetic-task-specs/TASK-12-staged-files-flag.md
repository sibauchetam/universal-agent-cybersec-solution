# TASK-12 — staged-files-flag

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1005 Data from Local System** (data staging) |
| Difficulty | **easy** |
| Deliverable | `/app/flag.txt` containing exactly `flag{st4g3d_1005_xx9}` |
| Pattern cloned from | CTF-flag style (flag string in file, verifier exact match) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/staged-files-flag"
description = "Find the intruder's hidden staging directory on a build-node filesystem snapshot and recover the IR recovery flag while avoiding decoys."
authors = []
keywords = []

[metadata]
difficulty = "easy"
category = "security"
tags = ["local", "mitre-t1005", "data-staging", "threat-hunt", "ctf"]

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
# Data staging hunt — build-node-12

Before leaving the network, an intruder collected files from **build-node-12** and staged
them in a hidden directory for later exfiltration. A filesystem snapshot is mounted under
**`/app/host/`** (layout mirrors the live host).

Find the staging directory and the recovery flag (format `flag{...}`) inside it, then write
the flag to **`/app/flag.txt`** — the file must contain exactly the flag string and nothing
else.

Warning: decoy `flag{...}` strings exist elsewhere on the host (left by the IR team to
detect lazy greps); the real flag is only inside the staging directory.
````

## 3. `environment/` composition

Static snapshot under `environment/host/`; container just copies it (`COPY host/ /app/host/`).

| Path | Contents |
|---|---|
| `host/home/jenkins/.jenkins/config.xml`, `host/home/jenkins/workspace/*/build.xml` | CI noise (real build configs, no secrets) |
| `host/var/log/jenkins/jenkins.log`, `host/var/log/auth.log` | log noise |
| `host/home/vagrant/Desktop/notes.txt` | **decoy 1**: ends with `flag{n0t_th3_r34l_0n3}` |
| `host/var/www/html/old-index.html` | **decoy 2**: HTML comment `<!-- flag{grep_f1rst_th1nk_l8er} -->` |
| `host/var/tmp/.stage/` | **the staging directory** (hidden, 0700): `payroll_2026Q2.csv` (5 rows), `customers_export.sql` (3 INSERTs), `.manifest.json` (see below), `README.txt` (see below) |
| `host/var/tmp/.stage/.manifest.json` | `{"collected_by": "svc-deploy", "collected_utc": "2026-08-19T02:41:12Z", "files": ["payroll_2026Q2.csv", "customers_export.sql", "README.txt"], "destination": "pending", "note": "passphrase material in README"}` |
| `host/var/tmp/.stage/README.txt` | 3 lines: `Collected per ticket OPS-4417.`, `Archive before transfer; delete after upload.`, `IR-RECOVERY-FLAG: flag{st4g3d_1005_xx9}` |

Real flag: **`flag{st4g3d_1005_xx9}`** (exists only in `host/var/tmp/.stage/README.txt`).

## 4. Verifier (`tests/`)

`tests/test.sh` (same tripwire pattern as TASK-09):

```bash
#!/bin/bash
set -e
REWARD=/logs/verifier/reward.txt
FLAG_FILE=/app/flag.txt
REAL="flag{st4g3d_1005_xx9}"
DECOYS="flag{n0t_th3_r34l_0n3}|flag{grep_f1rst_th1nk_l8er}"
GOT="$(cat "$FLAG_FILE" 2>/dev/null | tr -d '[:space:]')"
if [ "$GOT" = "$REAL" ]; then
  echo 1 > "$REWARD"
else
  echo 0 > "$REWARD"   # includes explicit fail if GOT matches either decoy
fi
```

**Exact grading semantics:** binary 0/1; stripped content of `/app/flag.txt` must equal
`flag{st4g3d_1005_xx9}` byte-for-byte; any decoy value is a 0.

## 5. Reference solution (agent steps ≈ `solve.sh`)

```bash
#!/bin/bash
set -euo pipefail
printf 'flag{st4g3d_1005_xx9}' > /app/flag.txt
```

Analyst steps for the agent:

1. `ls -la /app/host/var/tmp/` → notice hidden `.stage/`.
2. `ls -la /app/host/var/tmp/.stage/` → payroll CSV, SQL export, `.manifest.json`, `README.txt`.
3. `cat /app/host/var/tmp/.stage/README.txt` → `IR-RECOVERY-FLAG: flag{st4g3d_1005_xx9}`.
4. `printf 'flag{st4g3d_1005_xx9}' > /app/flag.txt`.

## 6. Expected agent difficulty profile

- **Steps:** ~6–10 tool calls (one or two `ls -la`, one `cat`, one write). Deliberately the
  "easy CTF" tier alongside the `hello-file` tasks, but with a decoy tripwire so blind
  `grep -r flag{` alone can pass only by luck.
- **Small-model failure modes:**
  - Greps for `flag{` host-wide, takes the first hit (`flag{n0t_th3_r34l_0n3}`) → explicit 0.
  - Writes the whole `README.txt` or the `IR-RECOVERY-FLAG:` line instead of the bare flag.
  - Writes the flag with quotes or a trailing newline — handled by the strip in the verifier,
    but quotes are not.
  - Overthinks: tries to crack/decrypt the CSV/SQL files that are just inert data.
