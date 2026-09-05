#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
CONFIG="$APP_DIR/host/var/lib/misc/.config-sync"
[ -f "$CONFIG" ] || { echo "solve: missing $CONFIG" >&2; exit 1; }
# Follow the planted chain exactly as the dropper does: base64 line -> decode -> flag.
BLOB=$(grep -E '^[A-Za-z0-9+/=]+$' "$CONFIG" | head -1)
DECODED=$(printf '%s' "$BLOB" | base64 -d)
FLAG=$(printf '%s\n' "$DECODED" | grep -oE 'flag\{[^}]*\}' | head -1)
[ -n "$FLAG" ] || { echo "solve: no flag in decoded config" >&2; exit 1; }
# Ground truth from the spec
[ "$FLAG" = "flag{pers1st_cr0n_v9}" ] || { echo "solve: unexpected flag $FLAG" >&2; exit 1; }
printf '%s' "$FLAG" > "$APP_DIR/flag.txt"
# Validate deliverable format: exactly the flag string, no extra whitespace beyond nothing
[ "$(cat "$APP_DIR/flag.txt" | tr -d '[:space:]')" = "$FLAG" ]
echo "solve: wrote $FLAG to $APP_DIR/flag.txt"
