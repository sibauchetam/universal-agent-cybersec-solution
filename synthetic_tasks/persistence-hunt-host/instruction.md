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
