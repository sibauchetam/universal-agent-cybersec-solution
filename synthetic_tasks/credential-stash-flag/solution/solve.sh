#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
HOME_DIR="$APP_DIR/target_home"
[ -d "$HOME_DIR" ] || { echo "solve: missing $HOME_DIR" >&2; exit 1; }

# part1: comment in the cloud-secrets config
PART1=$(sed -nE 's/.*part1 *= *([^ ]+).*/\1/p' "$HOME_DIR/.env" | head -1)
# part2: base64 blob in shell history -> decode
PART2=$(sed -nE 's/.*echo ([A-Za-z0-9+/=]+).*/\1/p' "$HOME_DIR/.bash_history" | head -1 | base64 -d)
# part3: SSH metadata comment
PART3=$(sed -nE 's/.*part3=([^ ]+).*/\1/p' "$HOME_DIR/.ssh/authorized_keys" | head -1)
[ -n "$PART1" ] && [ -n "$PART2" ] && [ -n "$PART3" ] || { echo "solve: missing part(s): '$PART1' '$PART2' '$PART3'" >&2; exit 1; }

FLAG="FLAG{${PART1}_${PART2}_${PART3}}"
# Spec sha256 ground truth (of FLAG + trailing newline)
GOT=$(printf '%s\n' "$FLAG" | sha256sum | cut -d' ' -f1)
[ "$GOT" = "e857c2d03f4c082502c6530b8b2bb9481272535a9522b037e725e3f91737a121" ] \
  || { echo "solve: assembled flag sha mismatch: $FLAG ($GOT)" >&2; exit 1; }
printf '%s\n' "$FLAG" > "$APP_DIR/recovered_flag.txt"
echo "solve: wrote $FLAG to $APP_DIR/recovered_flag.txt"
