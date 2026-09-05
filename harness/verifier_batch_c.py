#!/usr/bin/env python3
"""Batch C live-service verifiers for synthetic fix tasks (TASK-03/05/06/16).

Style-compatible with scripts/harness.py:
- per-task `verify(workdir) -> (ok, msg)` functions,
- TASKS registry with instruction / workdir-builder / verify / fidelity /
  timeout entries (same shape as harness.TASKS),
- verify-after-kill semantics: the verifier starts the service itself, so a
  stale or dead uvicorn left by the agent never influences grading.

Protocol per task (mirrors official local_task/fix-*/tests/test.sh):
  1. pkill stale `uvicorn main:app` processes left by the agent;
  2. start `python -m uvicorn main:app` from the app workdir under verifier
     control with APP_DIR / APP_DB / APP_LOG exported (+ JWT_SECRET for the
     JWT task); the service's stdout+stderr are redirected into a temp
     APP_LOG file so log-content assertions read exactly what the service
     emitted during THIS run;
  3. recreate the SQLite database (official test.sh drops/recreates it);
  4. wait for GET /healthz;
  5. run the hidden pytest suite <SYN>/<task>/tests;
  6. kill the service.

Standalone usage:
  python scripts/verifier_batch_c.py --task syn-fix-weak-crypto [--workdir DIR]

Without --workdir a fresh app workdir is built from
synthetic_tasks/<task>/environment/app into /tmp/secagent_eval/<task>/app.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"
EVAL_ROOT = Path("/tmp/secagent_eval")
PY = sys.executable

HEALTH_URL = "http://127.0.0.1:8000/healthz"
UVICORN_PATTERN = "uvicorn main:app"


def _run_hidden_suite(task_dir_name: str, workdir: Path, *,
                      extra_env: dict[str, str] | None = None,
                      wait_sec: int = 30, pytest_timeout: int = 300) -> tuple[bool, str]:
    """Live-service verifier: pkill -> uvicorn from workdir (APP_DIR/APP_DB/APP_LOG
    env, stdout/stderr into temp APP_LOG) -> /healthz -> hidden pytest -> kill."""
    tests_dir = SYN / task_dir_name / "tests"
    if not tests_dir.is_dir():
        return False, f"hidden tests missing: {tests_dir}"
    subprocess.run(["pkill", "-f", UVICORN_PATTERN], capture_output=True)
    time.sleep(1)

    log_dir = EVAL_ROOT / task_dir_name
    log_dir.mkdir(parents=True, exist_ok=True)
    app_log = log_dir / "app.log"  # temp log for the duration of the run
    app_log.write_bytes(b"")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(workdir)
    env["APP_DIR"] = str(workdir)
    env["APP_DB"] = str(workdir / "app.db")
    env["APP_LOG"] = str(app_log)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra_env:
        env.update(extra_env)

    # Official harnesses recreate the database before grading.
    Path(env["APP_DB"]).unlink(missing_ok=True)

    with open(app_log, "ab") as log_fh:
        app = subprocess.Popen(
            [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000",
             "--log-level", "info"],
            cwd=workdir, env=env, stdout=log_fh, stderr=subprocess.STDOUT,
        )
        healthy = False
        try:
            for _ in range(wait_sec):
                if app.poll() is not None:
                    return False, "app process exited before becoming healthy (see app.log)"
                try:
                    with urllib.request.urlopen(HEALTH_URL, timeout=2) as r:
                        if r.status == 200:
                            healthy = True
                            break
                except Exception:
                    time.sleep(1)
            if not healthy:
                return False, "app did not become healthy within timeout"
            proc = subprocess.run(
                [PY, "-m", "pytest", str(tests_dir), "-q", "--tb=short",
                 "-p", "no:cacheprovider"],
                capture_output=True, text=True, env=env, cwd=workdir,
                timeout=pytest_timeout,
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


def _build_app(dst: Path, task_dir_name: str) -> None:
    shutil.copytree(SYN / task_dir_name / "environment" / "app", dst)


TASKS = {
    "syn-fix-weak-crypto": {
        "instruction": (SYN / "fix-weak-crypto/instruction.md").read_text().strip(),
        "workdir": lambda dst: _build_app(dst, "fix-weak-crypto"),
        "verify": lambda wd: _run_hidden_suite("fix-weak-crypto", wd),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
    "syn-fix-command-injection-export": {
        "instruction": (SYN / "fix-command-injection-export/instruction.md").read_text().strip(),
        "workdir": lambda dst: _build_app(dst, "fix-command-injection-export"),
        "verify": lambda wd: _run_hidden_suite("fix-command-injection-export", wd),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
    "syn-fix-jwt-none-alg": {
        "instruction": (SYN / "fix-jwt-none-alg/instruction.md").read_text().strip(),
        "workdir": lambda dst: _build_app(dst, "fix-jwt-none-alg"),
        "verify": lambda wd: _run_hidden_suite(
            "fix-jwt-none-alg", wd, extra_env={"JWT_SECRET": "verifier-test-secret"}),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
    "syn-fix-exception-infoleak-failopen": {
        "instruction": (SYN / "fix-exception-infoleak-failopen/instruction.md").read_text().strip(),
        "workdir": lambda dst: _build_app(dst, "fix-exception-infoleak-failopen"),
        "verify": lambda wd: _run_hidden_suite("fix-exception-infoleak-failopen", wd),
        "fidelity": "hidden-pytest-live-service",
        "timeout": 900,
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--task", required=True, choices=sorted(TASKS))
    parser.add_argument("--workdir", default=None,
                        help="existing app dir to verify; default: build a fresh one")
    args = parser.parse_args()

    cfg = TASKS[args.task]
    if args.workdir:
        workdir = Path(args.workdir).resolve()
        if not workdir.is_dir():
            print(f"workdir does not exist: {workdir}")
            sys.exit(2)
    else:
        task_dir = EVAL_ROOT / args.task
        if task_dir.exists():
            shutil.rmtree(task_dir)
        workdir = task_dir / "app"
        cfg["workdir"](workdir)

    ok, msg = cfg["verify"](workdir)
    print(json.dumps({"task": args.task, "solved": ok, "verifier": msg,
                      "workdir": str(workdir)}, ensure_ascii=False))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
