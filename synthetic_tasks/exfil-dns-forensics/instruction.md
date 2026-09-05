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
