You are working in `/app/incident/` — a read-only snapshot bundle from a
compromised host: `etc/passwd.snapshot`, `etc/cron.d/` listing with file
contents, a filesystem listing of `/usr/local/sbin/` with sizes and mtimes,
`var/log/auth.log` excerpt, and `journalctl` excerpt.

The attacker created a local account that LOOKS like a legitimate service
account, and a cron job that LOOKS like a systemd updater, but runs a rogue
binary. Expose both.

Write a forensic report to:

`/app/incident_report.txt`

The report must contain EXACTLY 5 lines, each in `key=value` format, sorted
alphabetically by key. No extra lines, no comments.

Required keys (alphabetical order):

account_created=<UTC timestamp YYYY-MM-DDTHH:MM:SSZ from auth.log when the rogue account was created>
flag=<FLAG{...} recovered from the rogue binary>
masquerade_binary=<absolute path of the disguised executable>
rogue_account=<username of the uid-0 account that is not root>
rogue_uid=<integer uid of that account>

Do not modify any file inside `/app/incident/`.
