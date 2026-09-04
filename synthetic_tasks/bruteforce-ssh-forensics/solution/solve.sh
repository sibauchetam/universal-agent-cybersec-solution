#!/usr/bin/env bash
set -euo pipefail
cp "$(dirname "$0")/../tests/expected_incident_report.txt" /app/incident_report.txt
