import os
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))

EXPECTED = """exfil_bytes=657083
exfil_domain=cdn-backup-sync.evil-repo-cdn.com
flag=FLAG{1mp41r_th3n_3xf1l}
impaired_service=auditd
impair_time=2025-03-14T22:07:19Z
staging_dir=/tmp/.s"""


def test_report_exact():
    got = (APP / "incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
