import os
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))

EXPECTED = """account_created=2025-03-12T02:11:43Z
flag=FLAG{masquerade_syst3md_updat}
masquerade_binary=/usr/local/sbin/systemd-updat
rogue_account=svc-update
rogue_uid=0"""


def test_report_exact():
    got = (APP / "incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
