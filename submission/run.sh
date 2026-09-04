#!/bin/sh
# Universal Agent Competition submission entry point.
# Harbor runs: ./run.sh "<task instruction>" with env:
#   LOCAL_AGENT_MODEL, OPENAI_BASE_URL, OPENAI_API_KEY
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${LOCAL_AGENT_WORKDIR:-$(pwd)}"

if [ "$#" -lt 1 ]; then
  echo "Usage: ./run.sh PROMPT"
  exit 1
fi

PROMPT="$*"

exec env LOCAL_AGENT_WORKDIR="$WORKDIR" python3 "$SCRIPT_DIR/sec_agent.py" "$PROMPT"
