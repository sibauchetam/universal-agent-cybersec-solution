# Data staging hunt — build-node-12

Before leaving the network, an intruder collected files from **build-node-12** and staged
them in a hidden directory for later exfiltration. A filesystem snapshot is mounted under
**`/app/host/`** (layout mirrors the live host).

Find the staging directory and the recovery flag (format `flag{...}`) inside it, then write
the flag to **`/app/flag.txt`** — the file must contain exactly the flag string and nothing
else.

Warning: decoy `flag{...}` strings exist elsewhere on the host (left by the IR team to
detect lazy greps); the real flag is only inside the staging directory.