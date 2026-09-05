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
