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
