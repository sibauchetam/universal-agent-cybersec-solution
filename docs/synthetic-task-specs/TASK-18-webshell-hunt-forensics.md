# TASK-18 — webshell-hunt-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1505.003 Server Software Component: Web Shell** (+ T1190 initial access evidence) |
| Difficulty | **hard** |
| Deliverable | `/app/incident_report.txt` — strictly 5 lines of `key=value` |
| Pattern cloned from | `local_task/incident-log-forensics` (key=value report + sorted diff verifier) |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/webshell-hunt-forensics"
description = "Forensically analyze a compromised mini web root: locate an obfuscated Python web shell, reconstruct its activation timeline from access logs, identify the attacker and recover the hidden flag. Strict key=value report."
authors = []
keywords = []

[metadata]
difficulty = "hard"
category = "security"
tags = ["local", "mitre-t1505.003", "webshell", "forensics", "incident-response", "logs"]

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
You are working in `/app/incident/`. This is a read-only evidence bundle from a
compromised web server (mini web root `www/`, nginx-style `access.log`, a
process snapshot, and a crontab snapshot). A web shell was uploaded through the
public file upload endpoint and later used by the attacker.

Investigate and write a forensic report to:

`/app/incident_report.txt`

The report must contain EXACTLY 5 lines, each in `key=value` format, sorted
alphabetically by key. No extra lines, no comments, no trailing whitespace.

Required keys (alphabetical order):

commands_run=<integer: how many requests to the web shell carried a cmd argument>
flag=<FLAG{...} hidden by the attacker inside the web shell's second stage>
first_activated=<UTC timestamp YYYY-MM-DDTHH:MM:SSZ of the first successful POST to the web shell>
attacker_ip=<the IP that activated and used the shell>
webshell_path=<absolute path of the web shell file, as stored in the bundle>

Do not modify any file inside `/app/incident/`.
````

## 3. `environment/` composition

Static evidence bundle; nothing runs.

| Path | Contents |
|---|---|
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ /app/incident/`, `CMD ["sleep", "infinity"]` |
| `environment/incident/www/index.html` | legit landing page |
| `environment/incident/www/upload.php` | legit upload form (source of the compromise story) |
| `environment/incident/www/uploads/avatar_9d2c.png` | legit PNG upload (1×1) |
| `environment/incident/www/uploads/debug_info.php` | **decoy**: `<?php phpinfo();` — suspicious but not the shell |
| `environment/incident/www/uploads/avatar_8f3c.py` | **the web shell** — see below |
| `environment/incident/access.log` | ~180 lines nginx combined format, 5 real IPs; attack sequence from 203.0.113.66 |
| `environment/incident/process_snapshot.txt` | `ps aux` snapshot incl. `python3 uploads/avatar_8f3c.py`-style noise |
| `environment/incident/crontab.txt` | two legit cron entries (decoys) |

`environment/incident/www/uploads/avatar_8f3c.py` (verbatim):

```python
import base64
_s = 'd753039303f5465647370307f536336693f5274347436716f5c6c6338637263377b77414c464'
exec(bytes.fromhex(_s[::-1]).decode())
```

(The decoded stage 2 is the flag source: reversing the hex string and unhexing yields the
UTF-8 text `FLAG{w3bsh3ll_av4t4r_9f3c_p0sted_0905}` — the agent must decode, not guess.)

`environment/incident/access.log` — attack sequence (embedded among noise; IPs:
198.51.100.9, 198.51.100.77, 192.0.2.14 legit; attacker 203.0.113.66):

```
203.0.113.66 - - [11/Mar/2025:09:38:57 +0000] "POST /upload.php HTTP/1.1" 200 412 "http://target.example/" "Mozilla/5.0"
203.0.113.66 - - [11/Mar/2025:09:40:12 +0000] "GET /uploads/debug_info.php HTTP/1.1" 200 8152 "-" "curl/8.5.0"
203.0.113.66 - - [11/Mar/2025:09:41:22 +0000] "POST /uploads/avatar_8f3c.py HTTP/1.1" 200 96 "-" "python-requests/2.31"
203.0.113.66 - - [11/Mar/2025:09:44:05 +0000] "GET /uploads/avatar_8f3c.py?cmd=id HTTP/1.1" 200 41 "-" "python-requests/2.31"
203.0.113.66 - - [11/Mar/2025:09:46:33 +0000] "GET /uploads/avatar_8f3c.py?cmd=cat+/etc/hostname HTTP/1.1" 200 12 "-" "python-requests/2.31"
203.0.113.66 - - [11/Mar/2025:09:52:10 +0000] "GET /uploads/avatar_8f3c.py?cmd=env HTTP/1.1" 200 233 "-" "python-requests/2.31"
```

Expected answer set (deterministic):

```
attacker_ip=203.0.113.66
commands_run=3
first_activated=2025-03-11T09:41:22Z
flag=FLAG{w3bsh3ll_av4t4r_9f3c_p0sted_0905}
webshell_path=/app/incident/www/uploads/avatar_8f3c.py
```

Note the traps: (a) `commands_run` counts requests **with a `cmd` argument** (3 GETs),
NOT the activation POST; (b) `first_activated` is the first **successful (200) POST**,
not the upload event at 09:38:57 and not the decoy probe at 09:40:12; (c) the decoy
`debug_info.php` is phpinfo, not a shell; (d) timestamps in the log use `+0000` nginx
format but the report wants ISO `Z` form.

## 4. Verifier (`tests/`)

`tests/test.sh`: no service needed — write reward 0/1, pytest.
`tests/test_report.py` (hidden verifier):

```python
from pathlib import Path

EXPECTED = """attacker_ip=203.0.113.66
commands_run=3
first_activated=2025-03-11T09:41:22Z
flag=FLAG{w3bsh3ll_av4t4r_9f3c_p0sted_0905}
webshell_path=/app/incident/www/uploads/avatar_8f3c.py"""

def test_report_exact():
    got = Path("/app/incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
```

**Grading:** binary 0/1 — sorted line diff must be empty.

## 5. Reference solution (agent steps ≈ `solution/solve.sh`)

1. List the tree; grep `access.log` for non-200 IPs and for `.py`/`.php` hits.
2. Identify `avatar_8f3c.py`; read it; reverse hex → unhex → flag.
3. Count `cmd=` requests for the shell path; first 200 POST timestamp → ISO Z.
4. Write the 5-line report, sort, validate against the key list.

## 6. Expected agent difficulty profile

- **Steps:** ~10–18 tool calls (multi-artifact correlation + decoding chain).
- **Small-model failure modes:**
  - Counts the activation POST or the upload POST into `commands_run` (off-by-one/two).
  - Picks 09:38:57 (upload) or 09:40:12 (decoy probe) as `first_activated`.
  - Picks the decoy `debug_info.php` as the shell; or misses `.py` shell because it greps
    only for `.php`/`.jsp`.
  - Tries to decode the hex string without reversing → mojibake; gives up and invents a flag.
  - Writes 6+ lines or adds commentary → strict diff fails.
  - Modifies evidence (re-saving logs) — instruction says read-only.
