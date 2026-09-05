#!/usr/bin/env python3
"""Offline validation matrix for the synthetic task set (batches A-D).

For every task:
  1. NEGATIVE control: build pristine workdir -> verify() must FAIL.
  2. POSITIVE control: build fresh workdir -> run solution/solve.sh with
     APP_DIR=<workdir> -> verify() must PASS.

Exit code 0 iff every task passes BOTH controls.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, "/home/z/my-project/scripts")
import harness  # noqa: E402  (merges batch modules into harness.TASKS)

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"
WORK = Path("/tmp/validate_synth")

# tasks whose fix we simulate locally (official solve.sh needs postgres)
SIMULATED_FIX = {
    "fix-sqli-login": "apply official solve.sh patch via python replace",
}


def solve_task(key: str, workdir: Path) -> tuple[bool, str]:
    dirname = key[len("syn-"):] if key.startswith("syn-") else key
    solve_sh = SYN / dirname / "solution" / "solve.sh"
    env = os.environ.copy()
    env["APP_DIR"] = str(workdir)
    if not solve_sh.exists():
        # repo tasks: no solve.sh shipped; simulate the official fix inline
        if key == "fix-sqli-login":
            auth = workdir / "routers" / "auth.py"
            src = auth.read_text()
            vuln = (
                "        query = (\n"
                "            f\"SELECT id FROM users \"\n"
                "            f\"WHERE username = '{req.username}' AND password = '{req.password}'\"\n"
                "        )\n"
                "        row = await conn.fetchrow(query)"
            )
            fixed = (
                "        row = await conn.fetchrow(\n"
                "            \"SELECT id FROM users WHERE username = $1 AND password = $2\",\n"
                "            req.username,\n"
                "            req.password,\n"
                "        )"
            )
            if vuln not in src:
                return False, "official solve: vulnerable pattern not found"
            auth.write_text(src.replace(vuln, fixed))
            return True, "simulated official patch applied"
        return False, f"solve.sh missing: {solve_sh}"
    proc = subprocess.run(
        ["bash", str(solve_sh)], env=env, capture_output=True, text=True, timeout=420)
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-8:]
        return False, "solve.sh failed: " + " | ".join(tail)
    return True, "solve.sh ok"


def main() -> int:
    keys = sys.argv[1:] or sorted(harness.TASKS)
    only_synth = [k for k in keys if k.startswith("syn-") or k in SIMULATED_FIX]
    results: list[tuple[str, str, str]] = []  # key, control, status/msg
    failures = 0
    WORK.mkdir(parents=True, exist_ok=True)

    for key in only_synth:
        cfg = harness.TASKS[key]
        base = WORK / key
        if base.exists():
            shutil.rmtree(base)
        base.mkdir(parents=True)

        # ---- negative control ----
        neg = base / "pristine"
        try:
            cfg["workdir"](neg)
            ok, msg = cfg["verify"](neg)
            neg_res = "OK" if not ok else "LEAK"  # must FAIL on pristine
        except Exception as exc:
            neg_res, msg = "ERROR", repr(exc)
        if neg_res != "OK":
            failures += 1
        results.append((key, "neg", f"{neg_res}: {msg[:110]}"))

        # ---- positive control ----
        pos = base / "solved"
        try:
            cfg["workdir"](pos)
            t0 = time.monotonic()
            s_ok, s_msg = solve_task(key, pos)
            if not s_ok:
                pos_res = "SOLVE-FAIL"
                msg = s_msg
            else:
                ok, msg = cfg["verify"](pos)
                pos_res = "OK" if ok else "FAIL"
                msg = f"{msg} [{time.monotonic()-t0:.0f}s]"
        except Exception as exc:
            pos_res, msg = "ERROR", repr(exc)
        if pos_res != "OK":
            failures += 1
        results.append((key, "pos", f"{pos_res}: {msg[:110]}"))

        print(f"{key:42s} neg={results[-2][2][:60]}")
        print(f"{'':42s} pos={results[-1][2][:60]}", flush=True)

    print("\n==== SUMMARY ====")
    for key, control, msg in results:
        mark = "ok " if (control == "neg" and msg.startswith("OK")) or \
                        (control == "pos" and msg.startswith("OK")) else "!! "
        print(f"{mark}{control:3s} {key:42s} {msg}")
    print(f"\nfailures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
