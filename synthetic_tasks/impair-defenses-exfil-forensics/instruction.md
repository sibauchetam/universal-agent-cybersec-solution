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
