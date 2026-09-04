# TASK-09 — persistence-hunt-host

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1053.003 Scheduled Task/Job: Cron** + **T1543.002 Systemd Service** (+ T1070 log-clearing flavor) |
| Difficulty | medium |
| Deliverable | `/app/flag.txt` containing exactly `flag{pers1st_cr0n_v9}` |
| Pattern cloned from | CTF-flag style (flag string in file, verifier exact match) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/persistence-hunt-host"
description = "Threat hunt on a forensic filesystem snapshot: find planted cron and systemd persistence, follow the planted chain, recover the IR recovery flag."
authors = []
keywords = []

[metadata]
difficulty = "medium"
category = "security"
tags = ["local", "mitre-t1053", "mitre-t1543", "persistence", "cron", "systemd", "threat-hunt", "ctf"]

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
# Threat hunt — persistence on web-prod-07

An EDR telemetry gap was reported on host **web-prod-07**. A forensic snapshot of the host
filesystem is mounted under **`/app/host/`** (the layout mirrors the live host: `etc/`,
`usr/`, `var/`, `home/`, `root/`, `tmp/`).

Your job: find the attacker's **persistence mechanism(s)**. The IR team planted two
persistence primitives on the host (a cron job and a systemd unit); **only one of them
carries the recovery flag**, reachable by following the planted file chain.

Recover the flag (format `flag{...}`) and write it to **`/app/flag.txt`** — the file must
contain exactly the flag string and nothing else.

Notes:

- The IR team left a **decoy** flag somewhere on the host to detect lazy hunting; the real
  flag is only recoverable through the actual persistence mechanism.
- Logs on the host were partially cleared by the attacker (do not rely on log completeness).
````

## 3. `environment/` composition

Static filesystem snapshot under `environment/host/` (no services; container only needs
`COPY host/ /app/host/`).

Persistence chain (the real one, cron):

| Path | Contents |
|---|---|
| `host/etc/cron.d/backup-sync` | two lines — 1 legit + 1 planted: `*/15 * * * * root /usr/local/sbin/backup-sync >/dev/null 2>&1` and `*/7 * * * * root /usr/local/bin/.cache-sync --quiet` |
| `host/usr/local/sbin/backup-sync` | legit decoy script: plain `rsync -a /var/backups/ archive:/vol/backup/` |
| `host/usr/local/bin/.cache-sync` | planted dropper (hidden dotfile, mode 0755): shell script, verbatim below |
| `host/var/lib/misc/.config-sync` | planted config (hidden, mode 0600): line 1 `cache-mode=lru`, line 2 the base64 blob `IyBJUi1SRUNPVkVSWS1GTEFHOiBmbGFne3BlcnMxc3RfY3Iwbl92OX0K` which decodes to `# IR-RECOVERY-FLAG: flag{pers1st_cr0n_v9}` |

`host/usr/local/bin/.cache-sync` (verbatim):

```sh
#!/bin/sh
# internal cache warm-up (do not remove)
CONFIG=/var/lib/misc/.config-sync
[ -f "$CONFIG" ] || exit 0
PAYLOAD=$(grep -E '^[A-Za-z0-9+/=]+$' "$CONFIG" | head -1)
echo "$PAYLOAD" | base64 -d
```

Systemd persistence (second primitive, no flag — beacon only):

| Path | Contents |
|---|---|
| `host/etc/systemd/system/systemd-resolvedd.service` | note the **double-d typo** vs the real `systemd-resolved.service`; `[Service] ExecStart=/usr/lib/systemd/systemd-resolvedd --daemon`, `Restart=always`, `WantedBy=multi-user.target` |
| `host/usr/lib/systemd/systemd-resolvedd` | python3 one-liner beacon: `while True: urllib.request.urlopen("http://203.0.113.66/ping", timeout=5); time.sleep(60)` — decodes nothing, contains **no flag** |

Decoys & T1070 flavor:

| Path | Contents |
|---|---|
| `host/tmp/.flag_cache` | decoy: `flag{d3c0y_n0t_th1s}` |
| `host/var/log/auth.log` | truncated to 2 boot lines ("-- logs rotated by admin --") |
| `host/home/admin/.bash_history` | mostly empty; last line `history -c` |
| `host/var/log/syslog` | normal noise, no incident traces |
| `host/etc/cron.d/e2scrub_all`, `host/etc/systemd/system/sshd.service` | legit system files (contrast) |

## 4. Verifier (`tests/`)

`tests/test.sh` (exact-match clone of the `hello-file` pattern plus a decoy tripwire):

```bash
#!/bin/bash
set -e
REWARD=/logs/verifier/reward.txt
FLAG_FILE=/app/flag.txt
REAL="flag{pers1st_cr0n_v9}"
DECOY="flag{d3c0y_n0t_th1s}"
if [ -f "$FLAG_FILE" ] && [ "$(cat "$FLAG_FILE" | tr -d '[:space:]')" = "$REAL" ]; then
  echo 1 > "$REWARD"
elif [ -f "$FLAG_FILE" ] && [ "$(cat "$FLAG_FILE" | tr -d '[:space:]')" = "$DECOY" ]; then
  echo 0 > "$REWARD"   # decoy found — explicit fail
else
  echo 0 > "$REWARD"
fi
```

**Exact grading semantics:** binary 0/1; `/app/flag.txt` content stripped of whitespace must
equal `flag{pers1st_cr0n_v9}` byte-for-byte; the decoy string is an explicit 0.

## 5. Reference solution (agent steps ≈ `solve.sh`)

```bash
#!/bin/bash
set -euo pipefail
printf 'flag{pers1st_cr0n_v9}' > /app/flag.txt
```

Analyst steps for the agent:

1. `ls -laR /app/host/etc/cron.d/ /app/host/etc/systemd/system/` (or `grep -r "cron" /app/host/etc`)
   → spot `.cache-sync` cron line and the `systemd-resolvedd` unit typo.
2. Read `/app/host/usr/local/bin/.cache-sync` → pulls line 1 of `/var/lib/misc/.config-sync`
   and base64-decodes it.
3. `cat /app/host/var/lib/misc/.config-sync`; run
   `echo 'IyBJUi1SRUNPVkVSWS1GTEFHOiBmbGFne3BlcnMxc3RfY3Iwbl92OX0K' | base64 -d`
   → `# IR-RECOVERY-FLAG: flag{pers1st_cr0n_v9}`.
4. `printf 'flag{pers1st_cr0n_v9}' > /app/flag.txt`.

## 6. Expected agent difficulty profile

- **Steps:** ~12–18 tool calls (explore snapshot, read 3–4 files, decode, write flag).
- **Small-model failure modes:**
  - Runs `grep -r "flag{" /app/host` first, finds the decoy `/tmp/.flag_cache`, writes
    `flag{d3c0y_n0t_th1s}` → explicit 0 (the core trap of this task).
  - Stops at the systemd unit (finds no flag there, gives up) instead of following the cron chain.
  - Misses hidden dotfiles because `ls` without `-a` was used on `usr/local/bin/` or `var/lib/misc/`.
  - Writes the whole decoded comment line (`# IR-RECOVERY-FLAG: ...`) instead of the bare flag
    string; the whitespace-stripping verifier tolerates spaces but not the prefix — instruction
    explicitly says "exactly the flag string".
  - Confusion about executing `.cache-sync` (it is inert without the snapshot's env) instead of
    reading it.
