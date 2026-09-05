#!/usr/bin/env python3
"""Batch-D verifiers: local validation harness entries for the 8 synthetic tasks built
from docs/synthetic-task-specs (TASK-09/10/11/18/19/20/22/23).

Style clone of scripts/harness.py: per-task instruction/workdir/verify/fidelity/timeout,
plus a small CLI for standalone positive/negative controls:

    python3 scripts/verifier_batch_d.py --task syn-exfil-dns-forensics \
        --workdir /tmp/batchD_x/solved [--solve]

Verifier sources:
- key=value report tasks (TASK-10/11): harness._v_kv_report against the task's
  tests/expected_incident_report.txt (official sorted-diff semantics, LC_ALL=C).
- flag tasks: TASK-09 uses the spec's test.sh semantics (whitespace-stripped exact
  match, decoy is an explicit 0); TASK-19 runs the spec's hidden pytest
  (exact flag + evidence-bundle-unmodified sha256).
- hidden pytest tasks (TASK-18/20/22/23): run the task's tests/ directory with
  APP_DIR pointing at the workdir.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"
DEFAULT_AGENT_TIMEOUT = 600  # official task.toml agent.timeout_sec default

# NOTE: self-contained re-implementation of harness._v_kv_report / harness.v_flag
# (importing harness.py here would recurse once harness.py starts importing this
# module to merge TASKS; the logic is byte-faithful to the harness originals).


def _c_sort_lines(lines: list[str]) -> list[str]:
    return sorted(lines, key=lambda s: [ord(c) for c in s])


def _v_kv_report(workdir: Path, expected_src: Path, n_lines: int = 4) -> tuple[bool, str]:
    """Replicates official forensics test.sh (harness clone):
    exactly N non-empty lines, ^[a-z_]+=.+$, no ' = ', C-sort + diff."""
    import re
    report = workdir / "incident_report.txt"
    if not report.exists():
        return False, "incident_report.txt missing"
    raw = report.read_text(encoding="utf-8", errors="replace")
    got_lines = [ln[:-1] if ln.endswith("\r") else ln for ln in raw.splitlines()]
    got_lines = [ln for ln in got_lines if ln != ""]
    if len(got_lines) != n_lines:
        return False, f"expected {n_lines} non-empty lines, got {len(got_lines)}"
    for ln in got_lines:
        if not ln or not re.match(r"^[a-z_]+=.+$", ln):
            return False, f"format violation: {ln!r}"
        if " = " in ln:
            return False, f"format violation (space around =): {ln!r}"
    if not expected_src.exists():
        return False, f"expected-file missing: {expected_src}"
    exp_raw = expected_src.read_text(encoding="utf-8", errors="replace")
    exp_lines = [ln[:-1] if ln.endswith("\r") else ln for ln in exp_raw.splitlines()]
    exp_lines = [ln for ln in exp_lines if ln != ""]
    if _c_sort_lines(got_lines) != _c_sort_lines(exp_lines):
        diff = {"expected": _c_sort_lines(exp_lines), "got": _c_sort_lines(got_lines)}
        import json as _json
        return False, f"content mismatch: {_json.dumps(diff, ensure_ascii=False)}"
    return True, "ok"


def v_flag(workdir: Path, flag: str) -> tuple[bool, str]:
    fp = workdir / "flag.txt"
    if not fp.exists():
        return False, "flag.txt missing"
    content = "".join(fp.read_text(encoding="utf-8", errors="replace").split())
    if content == flag:
        return True, "ok"
    return False, f"flag mismatch: got {content[:60]!r}"


# --------------------------- verifiers --------------------------- #


def v_flag_with_decoy(workdir: Path) -> tuple[bool, str]:
    """TASK-09 spec tests/test.sh semantics: whitespace-stripped flag.txt must equal the
    real flag; the IR decoy flag is an explicit fail (not just a mismatch)."""
    fp = workdir / "flag.txt"
    real, decoy = "flag{pers1st_cr0n_v9}", "flag{d3c0y_n0t_th1s}"
    if not fp.exists():
        return False, "flag.txt missing"
    content = "".join(fp.read_text(encoding="utf-8", errors="replace").split())
    if content == real:
        return True, "ok"
    if content == decoy:
        return False, "decoy flag submitted (explicit 0 per spec)"
    return False, f"flag.txt must contain exactly {real!r}"


def _pytest_verify(tests_dir: Path, timeout: int = 300):
    """Run a task's hidden pytest suite with APP_DIR=<workdir> (read-only evidence check)."""
    def verify(workdir: Path) -> tuple[bool, str]:
        env = os.environ.copy()
        env["APP_DIR"] = str(workdir)
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", str(tests_dir), "-q", "--tb=short",
                 "-p", "no:cacheprovider"],
                capture_output=True, text=True, env=env, cwd=workdir, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return False, f"hidden tests timed out after {timeout}s"
        tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
        if proc.returncode == 0 and "passed" in tail:
            return True, f"ok ({tail})"
        return False, f"hidden tests failed: {tail}"
    return verify


# --------------------------- workdir builders --------------------------- #


def build_env_subdir(task: str, sub: str):
    """Copy synthetic_tasks/<task>/environment/<sub> into <workdir>/<sub>
    (workdir plays the role of /app; mirrors the existing harness builders)."""
    src = SYN / task / "environment" / sub

    def build(dst: Path) -> None:
        shutil.copytree(src, dst / sub)

    return build


# --------------------------- task registry --------------------------- #

TASKS = {
    "syn-persistence-hunt-host": {
        "instruction": (SYN / "persistence-hunt-host/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("persistence-hunt-host", "host"),
        "verify": v_flag_with_decoy,
        "fidelity": "official-clone-style",  # spec tests/test.sh semantics (real/decoy tripwire)
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    "syn-exfil-dns-forensics": {
        "instruction": (SYN / "exfil-dns-forensics/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("exfil-dns-forensics", "incident"),
        "verify": lambda wd: _v_kv_report(
            wd, SYN / "exfil-dns-forensics/tests/expected_incident_report.txt", n_lines=5),
        "fidelity": "official-clone-style",
        "timeout": 900,  # spec task.toml agent.timeout_sec
    },
    "syn-log-tamper-forensics": {
        "instruction": (SYN / "log-tamper-forensics/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("log-tamper-forensics", "incident"),
        "verify": lambda wd: _v_kv_report(
            wd, SYN / "log-tamper-forensics/tests/expected_incident_report.txt", n_lines=5),
        "fidelity": "official-clone-style",
        "timeout": 900,
    },
    "syn-webshell-hunt-forensics": {
        "instruction": (SYN / "webshell-hunt-forensics/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("webshell-hunt-forensics", "incident"),
        "verify": _pytest_verify(SYN / "webshell-hunt-forensics/tests"),
        "fidelity": "hidden-pytest-offline",
        "timeout": 900,
    },
    "syn-credential-stash-flag": {
        "instruction": (SYN / "credential-stash-flag/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("credential-stash-flag", "target_home"),
        "verify": _pytest_verify(SYN / "credential-stash-flag/tests"),
        "fidelity": "hidden-pytest-offline",
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    "syn-masquerade-hunt-forensics": {
        "instruction": (SYN / "masquerade-hunt-forensics/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("masquerade-hunt-forensics", "incident"),
        "verify": _pytest_verify(SYN / "masquerade-hunt-forensics/tests"),
        "fidelity": "hidden-pytest-offline",
        "timeout": 900,
    },
    "syn-impair-defenses-exfil-forensics": {
        "instruction": (SYN / "impair-defenses-exfil-forensics/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("impair-defenses-exfil-forensics", "incident"),
        "verify": _pytest_verify(SYN / "impair-defenses-exfil-forensics/tests"),
        "fidelity": "hidden-pytest-offline",
        "timeout": 900,
    },
    "syn-lateral-movement-forensics": {
        "instruction": (SYN / "lateral-movement-forensics/instruction.md").read_text().strip(),
        "workdir": build_env_subdir("lateral-movement-forensics", "incident"),
        "verify": _pytest_verify(SYN / "lateral-movement-forensics/tests"),
        "fidelity": "hidden-pytest-offline",
        "timeout": 900,
    },
}


# --------------------------- runner --------------------------- #


def _task_dirname(task: str) -> str:
    assert task.startswith("syn-"), task
    return task[len("syn-"):]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", required=True, choices=sorted(TASKS))
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--solve", action="store_true",
                        help="run solution/solve.sh with APP_DIR=<workdir> before verifying")
    parser.add_argument("--build-workdir", action="store_true",
                        help="(re)create the workdir from the task environment first")
    args = parser.parse_args()

    cfg = TASKS[args.task]
    wd = args.workdir
    if args.build_workdir:
        if wd.exists():
            shutil.rmtree(wd)
        cfg["workdir"](wd)
    if args.solve:
        env = os.environ.copy()
        env["APP_DIR"] = str(wd)
        subprocess.run(["bash", str(SYN / _task_dirname(args.task) / "solution/solve.sh")],
                       env=env, check=True)
    try:
        ok, msg = cfg["verify"](wd)
    except Exception as exc:
        ok, msg = False, f"verifier error: {exc!r}"
    print(("PASS" if ok else "FAIL"), f"{args.task}: {msg}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
