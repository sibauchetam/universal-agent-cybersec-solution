#!/usr/bin/env python3
"""Batch-A audit-task verifiers (synthetic TASK-01/04/13/14/17).

Registry style-compatible with scripts/harness.py (TASKS entries carry
instruction / workdir / verify / fidelity / timeout).

Integration contract with the harness:
- cfg["workdir"](dst) materializes the pristine app into a workdir
  (mirrors harness.build_app_workdir);
- the agent runs against that workdir (SEC_AGENT_WORKDIR / SEC_AGENT_PATH_REMAP);
- cfg["verify"](workdir) first applies the generic report-shape check
  (harness v_security_report adapted to the APP_DIR path), then runs the
  hidden pytest suite from synthetic_tasks/<task>/tests with
  env APP_DIR=<workdir> and cwd=<workdir>.

Single deliberate deviation from the official image: the hidden tests
resolve the report and pristine-code paths from
os.environ.get("APP_DIR", "/app") instead of hardcoding /app, so the same
suite runs both in the official image (APP_DIR unset -> /app) and locally
against a harness workdir.

Drop-in harness note: harness.run_task passes cfg["instruction"] as an
argv element, so the registry stores a Path; use instruction_text(key)
to get the instruction CONTENT for that call site.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"

PYTEST_TIMEOUT = 300  # pytest subprocess cap; official verifier.timeout_sec = 120

BATCH_A_TASKS = (
    "find-ssrf-webhook",
    "find-stored-xss-comments",
    "find-misconfig-debugapi",
    "find-supply-chain-backdoor",
    "find-logging-gaps",
)


def v_security_report(workdir: Path) -> tuple[bool, str]:
    """scripts/harness.py::v_security_report adapted to APP_DIR semantics.

    Generic shape check only (existence / valid JSON / non-empty findings[]);
    per-task signal matching lives in the hidden pytest suites.
    """
    report = workdir / "security_report.json"
    if not report.exists():
        return False, "security_report.json missing"
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"invalid JSON: {exc}"
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list) or not data["findings"]:
        return False, "missing non-empty findings[]"
    return True, "ok (shape)"


def _run_hidden_tests(workdir: Path, tests_dir: Path) -> tuple[bool, str]:
    env = os.environ.copy()
    env["APP_DIR"] = str(workdir)
    env["PYTHONPATH"] = str(workdir)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests_dir), "-q", "--tb=short",
             "-p", "no:cacheprovider"],
            capture_output=True, text=True, env=env, cwd=workdir, timeout=PYTEST_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return False, f"hidden tests timed out after {PYTEST_TIMEOUT}s"
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if proc.returncode == 0 and "passed" in tail:
        return True, f"ok ({tail})"
    return False, f"hidden tests failed: {tail}"


def _make_verify(tests_dir: Path):
    def verify(workdir: Path) -> tuple[bool, str]:
        shape_ok, shape_msg = v_security_report(workdir)
        if not shape_ok:
            return False, shape_msg
        return _run_hidden_tests(workdir, tests_dir)

    return verify


def _make_workdir(app_src: Path):
    def workdir(dst: Path) -> None:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(app_src, dst)

    return workdir


def _task(name: str) -> dict:
    root = SYN / name
    return {
        "instruction": root / "instruction.md",
        "workdir": _make_workdir(root / "environment/app"),
        "verify": _make_verify(root / "tests"),
        "fidelity": "hidden-pytest-audit (APP_DIR-adapted; official image pins /app)",
        "timeout": 600,
    }


TASKS = {f"syn-{n}": _task(n) for n in BATCH_A_TASKS}


def instruction_text(key: str) -> str:
    """Instruction CONTENT for harness.run_task-style call sites."""
    return TASKS[key]["instruction"].read_text(encoding="utf-8").strip()


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in TASKS:
        print(f"usage: verifier_batch_a.py <{'|'.join(TASKS)}> <workdir>")
        sys.exit(2)
    ok, msg = TASKS[sys.argv[1]]["verify"](Path(sys.argv[2]))
    print(("PASS " if ok else "FAIL ") + msg)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
