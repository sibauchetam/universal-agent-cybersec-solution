#!/usr/bin/env python3
"""Build runnable synthetic tasks (from docs/synthetic-task-specs) into synthetic_tasks/.
Generates instruction/env/tests; solution/solve.sh files are written separately."""
from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


TOML_TMPL = """schema_version = "1.2"

[task]
name = "local/{name}"
description = "{description}"
authors = []
keywords = []

[metadata]
difficulty = "{difficulty}"
category = "security"
tags = [{tags}]

[verifier]
timeout_sec = 120.0

[agent]
timeout_sec = 600.0

[environment]
build_timeout_sec = 600.0
cpus = 2
memory_mb = 4096
storage_mb = 10240
gpus = 0
allow_internet = true
mcp_servers = []

[verifier.env]

[environment.env]

[solution.env]
"""

# ---------------------------------------------------------------- TASK-07 pickle
PICKLE_INSTRUCTION = """You are working in `/app`. The application is a FastAPI job runner. Clients submit jobs as
base64-encoded blobs to `POST /jobs/import`.

Run `pytest tests/` to verify normal functionality — **all tests must still pass** after
your changes.

Analyse the code, identify the most critical security issues, and fix them. The job blob
wire format is **JSON** with exactly the fields:

- `name` — string, 1-128 chars
- `priority` — integer, 0-9
- `params` — object with string keys and string values

Invalid blobs must be rejected with a 4xx status and must **never** execute
attacker-controlled code (no `pickle`, `yaml.load`, `eval`, or similar).

Do not introduce new dependencies beyond what is already declared in `pyproject.toml`
(stdlib `json`, `base64` are sufficient)."""

PICKLE_JOBS_PY = '''import base64, pickle
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["jobs"])

_JOBS: list[dict] = []


class ImportRequest(BaseModel):
    blob_b64: str


@router.post("/jobs/import")
async def import_job(req: ImportRequest):
    try:
        job = pickle.loads(base64.b64decode(req.blob_b64))  # VULNERABLE: CWE-502, RCE via __reduce__
    except Exception:
        raise HTTPException(status_code=400, detail="bad blob")
    _JOBS.append(job)
    return {"imported": job["name"]}


@router.post("/jobs")
async def create_job(name: str, priority: int, params: dict[str, str] | None = None):
    job = {"name": name, "priority": priority, "params": params or {}}
    _JOBS.append(job)
    return {"imported": job["name"]}


@router.get("/jobs")
async def list_jobs():
    return [{"name": j["name"], "priority": j["priority"]} for j in _JOBS]
'''

PICKLE_MAIN_PY = '''from fastapi import FastAPI

from routers.jobs import router as jobs_router

app = FastAPI(title="job-runner")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


app.include_router(jobs_router)
'''

PICKLE_VISIBLE_TESTS = '''import base64
import json

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").status_code == 200


def test_list_jobs_empty():
    assert client.get("/jobs").status_code == 200


def test_create_and_list_job():
    r = client.post("/jobs?name=build-a&priority=2")
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": "build-a"}
    names = [j["name"] for j in client.get("/jobs").json()]
    assert "build-a" in names


def test_import_valid_json_blob():
    blob = base64.b64encode(json.dumps({"name": "idx", "priority": 1, "params": {"t": "x"}}).encode()).decode()
    r = client.post("/jobs/import", json={"blob_b64": blob})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": "idx"}


def test_import_garbage_rejected():
    r = client.post("/jobs/import", json={"blob_b64": "!!!not-base64!!!"})
    assert r.status_code in (400, 422)
'''

PICKLE_HIDDEN_TESTS = '''import base64, json, pickle
from pathlib import Path


def _b64(obj) -> str:
    return base64.b64encode(obj).decode()


def _json_blob(job: dict) -> str:
    return _b64(json.dumps(job).encode())


def test_valid_json_blob_imported(client):
    blob = _json_blob({"name": "nightly-index", "priority": 3, "params": {"target": "idx"}})
    r = client.post("/jobs/import", json={"blob_b64": blob})
    assert r.status_code == 200, r.text
    assert r.json() == {"imported": "nightly-index"}
    names = [j["name"] for j in client.get("/jobs").json()]
    assert "nightly-index" in names


class _RCE:
    def __reduce__(self):
        import subprocess
        return (subprocess.run, (["touch", "/tmp/pwned"],))


def test_pickle_rce_payload_neutralized(client):
    Path("/tmp/pwned").unlink(missing_ok=True)
    r = client.post("/jobs/import", json={"blob_b64": _b64(pickle.dumps(_RCE()))})
    assert r.status_code in (400, 422), f"malicious blob accepted: {r.status_code}"
    assert not Path("/tmp/pwned").exists(), "pickle payload executed (RCE)"


def test_builtin_reduce_payload_neutralized(client):
    blob = _b64(pickle.dumps(("os", "system", ("touch /tmp/pwned2",))))
    r = client.post("/jobs/import", json={"blob_b64": blob})
    assert r.status_code in (400, 422)
    assert not Path("/tmp/pwned2").exists()


def test_wrong_types_rejected(client):
    blob = _json_blob({"name": 123, "priority": 3, "params": {}})
    assert client.post("/jobs/import", json={"blob_b64": blob}).status_code in (400, 422)


def test_extra_field_rejected(client):
    blob = _json_blob({"name": "x", "priority": 1, "params": {}, "admin": True})
    assert client.post("/jobs/import", json={"blob_b64": blob}).status_code in (400, 422)


def test_priority_out_of_range_rejected(client):
    blob = _json_blob({"name": "x", "priority": 42, "params": {}})
    assert client.post("/jobs/import", json={"blob_b64": blob}).status_code in (400, 422)


def test_garbage_bytes_rejected(client):
    assert client.post("/jobs/import", json={"blob_b64": _b64(b"\\x80\\x04garbage")}).status_code in (400, 422)
'''

PICKLE_HIDDEN_CONFTEST = '''import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import sys
    sys.path.insert(0, ".")
    from main import app
    return TestClient(app)
'''


def build_pickle() -> None:
    root = SYN / "fix-insecure-pickle"
    write(root / "task.toml", TOML_TMPL.format(
        name="fix-insecure-pickle",
        description="Replace pickle.loads on attacker-controlled job blobs with strict JSON validation.",
        difficulty="medium",
        tags='"local", "deserialization", "owasp-a08", "cwe-502", "fix"',
    ))
    write(root / "instruction.md", PICKLE_INSTRUCTION)
    write(root / "environment/app/pyproject.toml", '''[project]
name = "job-runner"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.30.0",
    "httpx>=0.28.1",
    "pytest>=8.0.0",
    "pydantic>=2.0.0",
]
''')
    write(root / "environment/app/AGENTS.md", "# job-runner\n\nFastAPI service. Tests run offline via in-process TestClient.\n")
    write(root / "environment/app/main.py", PICKLE_MAIN_PY)
    write(root / "environment/app/routers/__init__.py", "")
    write(root / "environment/app/routers/jobs.py", PICKLE_JOBS_PY)
    write(root / "environment/app/tests/test_api.py", PICKLE_VISIBLE_TESTS)
    write(root / "tests/test_deserialization.py", PICKLE_HIDDEN_TESTS)
    write(root / "tests/conftest.py", PICKLE_HIDDEN_CONFTEST)


# ---------------------------------------------------------------- TASK-08 forensics
FORENSICS_INSTRUCTION = """# IR-2026-0614 — Suspected SSH brute force (prod-auth-01)

The SIEM raised an `sshd_bruteforce_suspected` alert on **prod-auth-01** early on
June 14, 2026. You are the analyst on duty. Review everything under **`/app/incident/`**
and record your attribution conclusion in **`/app/incident_report.txt`**.

**Artifacts (read all that exist in the directory):**

- `auth.log` — sshd export from prod-auth-01 (timestamps already normalized to ISO 8601 UTC)
- `app_audit.jsonl` — application audit from the same host (post-compromise activity)
- `collector_note.txt` — export scope notes

**Deliverable — strict machine format**

Write **`/app/incident_report.txt`**: UTF-8, **exactly four** non-empty lines, **one**
`key=value` per line, **no** spaces around `=`, **no** blank lines, **no** commentary.
Each of the following keys must appear **once**:

- `attacker_ip`
- `compromised_user`
- `failed_attempts`
- `first_success_utc`

**Report fields (normative mapping)**

- `attacker_ip` = source IP with the highest number of failed password attempts.
- `compromised_user` = the target user of that same IP's eventual successful login.
- `failed_attempts` = number of `Failed password` records **from the attacker IP for the
  compromised user only** (exclude failures against other usernames from that IP, and all
  failures from other source IPs).
- `first_success_utc` = timestamp of the first `Accepted` record for
  `attacker_ip` + `compromised_user`, copied **verbatim** from the log.

Do not add keys, rename keys, or embed explanations in the deliverable file."""

FORENSICS_EXPECTED = """attacker_ip=198.51.100.77
compromised_user=svc-backup
failed_attempts=87
first_success_utc=2026-06-14T03:18:37.000Z"""


def build_forensics() -> None:
    root = SYN / "bruteforce-ssh-forensics"
    write(root / "task.toml", TOML_TMPL.format(
        name="bruteforce-ssh-forensics",
        description="Correlate sshd and application logs to attribute an SSH password-guessing incident.",
        difficulty="easy",
        tags='"local", "mitre-t1110", "brute-force", "ssh", "forensics"',
    ))
    write(root / "instruction.md", FORENSICS_INSTRUCTION)
    write(root / "tests/expected_incident_report.txt", FORENSICS_EXPECTED)
    write(root / "environment/incident/collector_note.txt",
          "auth.log covers 2026-06-14T02:00:00Z-04:00:00Z on prod-auth-01.\n"
          "Two background sources exist in the window: a generic root-name sweep from 192.0.2.9,\n"
          "and 3 routine failures from tenant CI host 203.0.113.10 (stale cron, later succeeded with a publickey).\n")

    # --- auth.log per spec generator (ground truth: 5 admin + 87 svc-backup fails from attacker, 1 accepted) ---
    out: list[str] = []
    for i in range(3):
        out.append(f"2026-06-14T02:{10 + i:02d}:11.{100 + i:03d}Z sshd[1180]: Failed password for deploy from 203.0.113.10 port {41000 + i} ssh2")
    out.append("2026-06-14T02:14:02.300Z sshd[1180]: Accepted publickey for deploy from 203.0.113.10 port 41003 ssh2: RSA SHA256:c1...")
    for i in range(12):
        out.append(f"2026-06-14T02:{20 + i:02d}:41.{200 + i:03d}Z sshd[1421]: Failed password for invalid user root from 192.0.2.9 port {50000 + i} ssh2")
    t = datetime.datetime(2026, 6, 14, 3, 12, 5)
    for i in range(5):
        t += datetime.timedelta(seconds=7)
        out.append(f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond // 1000:03d}Z sshd[2210]: Failed password for admin from 198.51.100.77 port {52000 + i} ssh2")
    for i in range(87):
        t += datetime.timedelta(seconds=4)
        out.append(f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond // 1000:03d}Z sshd[2210]: Failed password for svc-backup from 198.51.100.77 port {52010 + i} ssh2")
    t += datetime.timedelta(seconds=9)
    accepted = f"{t.strftime('%Y-%m-%dT%H:%M:%S')}.{t.microsecond // 1000:03d}Z sshd[2210]: Accepted password for svc-backup from 198.51.100.77 port 52098 ssh2"
    out.append(accepted)
    out.append("2026-06-14T03:19:59.001Z sshd[2210]: pam_unix(sshd:session): session opened for user svc-backup by (uid=0)")
    write(root / "environment/incident/auth.log", "\n".join(out) + "\n")
    assert accepted.startswith("2026-06-14T03:18:37.000Z"), accepted

    # --- app_audit.jsonl: noise + post-compromise svc-backup activity ---
    records: list[dict] = []
    base = datetime.datetime(2026, 6, 14, 2, 0, 0)
    for i in range(20):
        ts = (base + datetime.timedelta(minutes=i * 5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        records.append({"ts": ts, "http": {"request_id": f"req-{1000 + i}", "method": "GET", "path": "/api/health", "status": 200},
                        "identity": {"subject": "monitor-bot"}, "audit": {"event": "healthcheck", "bytes": 64}})
    for i in range(6):
        ts = (datetime.datetime(2026, 6, 14, 3, 19, 0) + datetime.timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        records.append({"ts": ts, "http": {"request_id": f"req-{2000 + i}", "method": "GET", "path": "/api/backup/download", "status": 200},
                        "identity": {"subject": "svc-backup"}, "audit": {"event": "file_download", "bytes": 1048576}})
    write(root / "environment/incident/app_audit.jsonl", "\n".join(json.dumps(r) for r in records) + "\n")


# ---------------------------------------------------------------- TASK-12 CTF flag hunt
FLAG_INSTRUCTION = """# Data staging hunt — build-node-12

Before leaving the network, an intruder collected files from **build-node-12** and staged
them in a hidden directory for later exfiltration. A filesystem snapshot is mounted under
**`/app/host/`** (layout mirrors the live host).

Find the staging directory and the recovery flag (format `flag{...}`) inside it, then write
the flag to **`/app/flag.txt`** — the file must contain exactly the flag string and nothing
else.

Warning: decoy `flag{...}` strings exist elsewhere on the host (left by the IR team to
detect lazy greps); the real flag is only inside the staging directory."""

REAL_FLAG = "flag{st4g3d_1005_xx9}"


def build_ctf() -> None:
    root = SYN / "staged-files-flag"
    write(root / "task.toml", TOML_TMPL.format(
        name="staged-files-flag",
        description="Find the intruder's hidden staging directory and recover the IR flag while avoiding decoys.",
        difficulty="easy",
        tags='"local", "mitre-t1005", "data-staging", "ctf"',
    ))
    write(root / "instruction.md", FLAG_INSTRUCTION)

    h = root / "environment/host"
    write(h / "home/jenkins/.jenkins/config.xml",
          '<?xml version="1.0"?>\n<jenkins><numExecutors>4</numExecutors><url>http://build-node-12:8080/</url></jenkins>\n')
    for ws in ("api-gateway", "web-frontend"):
        write(h / f"home/jenkins/workspace/{ws}/build.xml",
              f'<build><workspace>{ws}</workspace><lastSuccess>2026-08-18T21:15:03Z</lastSuccess></build>\n')
    write(h / "var/log/jenkins/jenkins.log",
          "2026-08-19T02:38:11Z INFO  hudson.model.Run - api-gateway #412 completed\n"
          "2026-08-19T02:41:09Z WARN  hudson.security - failed login attempt for user deploy-admin (svc-deploy lockout exempt)\n"
          "2026-08-19T02:44:30Z INFO  hudson.model.Run - web-frontend #617 completed\n")
    write(h / "var/log/auth.log",
          "2026-08-19T02:39:55.112Z sshd[3107]: Accepted publickey for svc-deploy from 10.20.4.31 port 51222 ssh2\n"
          "2026-08-19T02:41:12.004Z sudo: svc-deploy : TTY=pts/0 ; PWD=/var/tmp ; USER=root ; COMMAND=/bin/sh -c tar -czf /dev/null\n")
    write(h / "home/vagrant/Desktop/notes.txt",
          "Reminders:\n- rotate build agents keys this quarter\n- archive old workspaces\n"
          "flag{n0t_th3_r34l_0n3}\n")
    write(h / "var/www/html/old-index.html",
          "<html><body><h1>Build node 12</h1><!-- flag{grep_f1rst_th1nk_l8er} --></body></html>\n")
    write(h / "var/tmp/.stage/payroll_2026Q2.csv",
          "id,name,dept,salary,country\n1,Ivanov,eng,78000,BY\n2,Petrova,design,61000,BY\n3,Smith,eng,91000,US\n4,Doe,sales,57000,US\n5,Nguyen,eng,67000,SG\n")
    write(h / "var/tmp/.stage/customers_export.sql",
          "INSERT INTO customers (id, name, tier) VALUES (1, 'ACME Corp', 'gold');\n"
          "INSERT INTO customers (id, name, tier) VALUES (2, 'Globex', 'silver');\n"
          "INSERT INTO customers (id, name, tier) VALUES (3, 'Initech', 'bronze');\n")
    write(h / "var/tmp/.stage/.manifest.json", json.dumps({
        "collected_by": "svc-deploy",
        "collected_utc": "2026-08-19T02:41:12Z",
        "files": ["payroll_2026Q2.csv", "customers_export.sql", "README.txt"],
        "destination": "pending",
        "note": "passphrase material in README",
    }, indent=2) + "\n")
    write(h / "var/tmp/.stage/README.txt",
          "Collected per ticket OPS-4417.\nArchive before transfer; delete after upload.\n"
          f"IR-RECOVERY-FLAG: {REAL_FLAG}\n")


if __name__ == "__main__":
    build_pickle()
    build_forensics()
    build_ctf()
    print("built: fix-insecure-pickle, bruteforce-ssh-forensics, staged-files-flag")
