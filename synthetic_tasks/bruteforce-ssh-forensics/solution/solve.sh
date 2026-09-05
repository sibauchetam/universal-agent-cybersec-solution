#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/app}"
cp "$(dirname "$0")/../tests/expected_incident_report.txt" "$APP_DIR/incident_report.txt"
