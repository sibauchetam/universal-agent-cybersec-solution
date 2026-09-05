#!/usr/bin/env python3
"""Batch B live-service verifiers for synthetic fix tasks (TASK-02 / 15 / 21).

Official fix-task verifier semantics (clone of local_task/fix-*/tests/test.sh,
adapted to sqlite): kill stale uvicorn processes left by the agent -> start
`uvicorn main:app` from the workdir under VERIFIER control with APP_DIR/APP_DB
pointing at the workdir and a FRESH database file (official test.sh recreates
the DB, so seed state is deterministic) -> wait /healthz -> run the hidden
pytest suite from the task's tests/ dir -> cleanup -> binary reward.

Registry entries follow harness.py TASKS format:
    instruction (str), workdir (callable), verify (callable -> (bool, str)),
    fidelity (str), timeout (int, agent budget from the spec task.toml).

Usage:
  python3 verifier_batch_b.py --task syn-fix-idor-invoices            # fresh copy + verify
  python3 verifier_batch_b.py --task syn-fix-idor-invoices --workdir D  # verify D as-is
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"
DB_FILENAME = "app.db"


def _fresh_db(workdir: Path) -> Path:
    """Official semantics: verifier recreates the database so the seed state is
    deterministic regardless of what the agent did at runtime."""
    db_path = workdir / DB_FILENAME
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = Path(str(db_path) + suffix)
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    return db_path


def v_live_service(workdir: Path, tests_dir: Path, wait_sec: int = 40) -> tuple[bool, str]:
    """Live-service verifier clone: pkill uvicorn -> start uvicorn from workdir
    (env APP_DIR=workdir, APP_DB=workdir/app.db) -> wait /healthz -> pytest
    tests_dir -> kill. Hidden pytest suite lives OUTSIDE the workdir (task
    tests/ dir), mirroring the official /tests mount."""
    subprocess.run(["pkill", "-f", "uvicorn main:app"], capture_output=True)
    time.sleep(1)
    db_path = _fresh_db(workdir)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(workdir)
    env["APP_DIR"] = str(workdir)
    env["APP_DB"] = str(db_path)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", "8000", "--log-level", "warning"],
        cwd=workdir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    healthy = False
    try:
        import urllib.request
        for _ in range(wait_sec):
            if app.poll() is not None:
                return False, "app process exited before becoming healthy"
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=2) as r:
                    if r.status == 200:
                        healthy = True
                        break
            except Exception:
                time.sleep(1)
        if not healthy:
            return False, "app did not become healthy within timeout"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests_dir), "-q", "--tb=short",
             "-p", "no:cacheprovider"],
            capture_output=True, text=True, env=env, cwd=workdir, timeout=300,
        )
        tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        if proc.returncode == 0 and "passed" in tail:
            return True, f"ok ({tail})"
        return False, f"hidden tests failed: {tail}"
    finally:
        try:
            app.terminate()
            app.wait(timeout=5)
        except Exception:
            try:
                app.kill()
            except Exception:
                pass


def _make_verify(task_dir_name: str):
    def _verify(workdir: Path) -> tuple[bool, str]:
        return v_live_service(workdir, SYN / task_dir_name / "tests")
    return _verify


def build_app_workdir(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst)


TASKS = {
    "syn-fix-idor-invoices": {
        "instruction": (SYN / "fix-idor-invoices/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(
            SYN / "fix-idor-invoices/environment/app", dst),
        "verify": _make_verify("fix-idor-invoices"),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
    "syn-fix-giftcard-negative-transfer": {
        "instruction": (SYN / "fix-giftcard-negative-transfer/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(
            SYN / "fix-giftcard-negative-transfer/environment/app", dst),
        "verify": _make_verify("fix-giftcard-negative-transfer"),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
    "syn-fix-login-throttling-session": {
        "instruction": (SYN / "fix-login-throttling-session/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(
            SYN / "fix-login-throttling-session/environment/app", dst),
        "verify": _make_verify("fix-login-throttling-session"),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", choices=sorted(TASKS), required=True)
    parser.add_argument("--workdir", type=Path, default=None,
                        help="verify an existing workdir as-is (no fresh copy)")
    args = parser.parse_args()
    cfg = TASKS[args.task]
    if args.workdir is not None:
        workdir = args.workdir
    else:
        workdir = Path("/tmp/verifier_batch_b") / args.task / "app"
        if workdir.parent.exists():
            shutil.rmtree(workdir.parent)
        cfg["workdir"](workdir)
    ok, msg = cfg["verify"](workdir)
    print(f"{args.task}: {'SOLVED' if ok else 'FAILED'} - {msg}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
