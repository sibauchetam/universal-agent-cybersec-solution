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
