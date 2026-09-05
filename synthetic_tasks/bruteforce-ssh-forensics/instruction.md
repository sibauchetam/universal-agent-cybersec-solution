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