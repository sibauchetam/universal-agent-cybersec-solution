import os
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))

EXPECTED = """discovery_source_host=ci-runner
first_lateral_target=db01
flag=FLAG{l4t3r4l_v1a_sh4r3d_k3y}
key_fingerprint=SHA256:J4gom6ZZTeBM+Q/+YMxhWWWKUeUuM0Pl6qFVdvPcA64
scan_tool=nmap
successful_logins=3"""


def test_report_exact():
    got = (APP / "incident_report.txt").read_text().strip()
    assert sorted(got.splitlines()) == sorted(EXPECTED.splitlines())
