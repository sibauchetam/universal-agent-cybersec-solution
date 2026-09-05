import os
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))

EXPECTED = """attacker_ip=203.0.113.66
commands_run=3
first_activated=2025-03-11T09:41:22Z
flag=FLAG{w3bsh3ll_av4t4r_9f3c_p0sted_0905}
webshell_path=/app/incident/www/uploads/avatar_8f3c.py"""


def test_report_exact():
    got = (APP / "incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
