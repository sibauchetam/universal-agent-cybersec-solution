#!/usr/bin/env python3
"""Local validation harness: runs submission agent against task workdirs via Groq.

Usage: python3 harness.py --tasks hello-file,bye-file --token-idx 0
Results -> /home/z/my-project/results/<task>.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

BASE = Path("/home/z/my-project")
REPO = BASE / "UniversalAgenticCompetitionPublic"
SUBMISSION = BASE / "submission"
RESULTS = BASE / "results"
EVAL_ROOT = Path("/tmp/secagent_eval")

GROQ_BASE = os.environ.get("OPENAI_BASE_URL", "https://api.groq.com/openai/v1")
MODEL = os.environ.get("LOCAL_AGENT_MODEL", "qwen/qwen3.6-27b")
TOKENS = [
    t for t in (
        os.environ.get("GROQ_API_KEY_1"),
        os.environ.get("GROQ_API_KEY_2"),
    ) if t
]
PROXY = os.environ.get("GROQ_PROXY", "")


# --------------------------- verifiers --------------------------- #


def v_file_exact(workdir: Path, path: str, expected: str) -> tuple[bool, str]:
    fp = workdir / path
    if not fp.exists():
        return False, f"{path} missing"
    got = fp.read_text(encoding="utf-8")
    if got != expected:
        return False, f"content mismatch: {got!r} != {expected!r}"
    return True, "ok"


def v_hello(workdir: Path) -> tuple[bool, str]:
    return v_file_exact(workdir, "hello.txt", "Hello")


def v_bye(workdir: Path) -> tuple[bool, str]:
    return v_file_exact(workdir, "bye.txt", "Bye")


def v_security_report(workdir: Path) -> tuple[bool, str]:
    """Replicates local_task/find-sqli-login/tests/test_security_report.py"""
    report = workdir / "security_report.json"
    if not report.exists():
        return False, "security_report.json missing"
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"invalid JSON: {exc}"
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list) or not data["findings"]:
        return False, "missing non-empty findings[]"

    def flatten(value) -> str:
        if isinstance(value, dict):
            return " ".join(flatten(v) for v in value.values())
        if isinstance(value, list):
            return " ".join(flatten(v) for v in value)
        return str(value)

    sqli_signals = ["sql injection", "sqli", "sql_injection", "cwe-89", "injection", "raw sql",
                    "string interpolation", "f-string", "parameterized", "prepared statement"]
    login_signals = ["login", "/login", "auth", "authentication", "routers/auth.py", "auth.py", "loginrequest"]
    detail_signals = ["bypass", "authentication bypass", "admin'--", "or '1'='1", "password",
                      "credential", "req.username", "req.password", "fetchrow"]

    for finding in data["findings"]:
        text = flatten(finding).lower()
        if (any(s in text for s in sqli_signals) and any(s in text for s in login_signals)
                and any(s in text for s in detail_signals)):
            return True, "ok"
    return False, "no finding matching SQLi-in-login with detail"


def v_incident_report(workdir: Path) -> tuple[bool, str]:
    """Replicates local_task/incident-log-forensics/tests/test.sh (sort+diff)."""
    expected_src = REPO / "local_task/incident-log-forensics/solution/expected_incident_report.txt"
    return _v_kv_report(workdir, expected_src)


def _v_kv_report(workdir: Path, expected_src: Path) -> tuple[bool, str]:
    report = workdir / "incident_report.txt"
    if not report.exists():
        return False, "incident_report.txt missing"
    got_lines = [ln.strip("\r") for ln in report.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(got_lines) != 4:
        return False, f"expected 4 non-empty lines, got {len(got_lines)}"
    for ln in got_lines:
        if not re.match(r"^[a-z_]+=\S+$", ln) or " = " in ln:
            return False, f"format violation: {ln!r}"
    exp = sorted(ln.strip("\r") for ln in expected_src.read_text().splitlines() if ln.strip())
    if sorted(got_lines) != exp:
        diff = {"expected": exp, "got": sorted(got_lines)}
        return False, f"content mismatch: {json.dumps(diff)}"
    return True, "ok"


def v_static_sqli_fix(workdir: Path) -> tuple[bool, str]:
    """No live service locally: verify the vulnerable f-string SQL is gone and
    a parameterized form is present in the patched router."""
    vuln_markers = [
        "LIKE '%{q}%'", "f\"SELECT * FROM items WHERE name LIKE",
        "WHERE username = '{req.username}'",
    ]
    hits = []
    for py in workdir.rglob("*.py"):
        src = py.read_text(encoding="utf-8", errors="replace")
        for marker in vuln_markers:
            if marker in src:
                hits.append(f"{py.name}: {marker}")
    if hits:
        return False, f"vulnerable SQL patterns remain: {hits}"
    return True, "ok (static check; live-service regression not runnable locally)"


def v_flag(workdir: Path, flag: str) -> tuple[bool, str]:
    if (workdir / "flag.txt").exists() and (workdir / "flag.txt").read_text(encoding="utf-8", errors="replace").strip() == flag:
        return True, "ok"
    return False, f"flag.txt must contain exactly {flag!r}"


# --------------------------- task registry --------------------------- #

FORENSICS_ENV = REPO / "local_task/incident-log-forensics/environment"


def build_forensics_workdir(dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for f in FORENSICS_ENV.iterdir():
        if f.name in {"Dockerfile"}:
            continue
        if f.is_file():
            shutil.copy(f, dst / f.name)


def build_app_workdir(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst)


def v_pickle_fix(workdir: Path) -> tuple[bool, str]:
    """Run hidden deserialization tests (offline TestClient) against the agent's fixed app."""
    tests_dir = SYN / "fix-insecure-pickle/tests"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(workdir)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_dir / "test_deserialization.py"),
         "-q", "--tb=short", "-p", "no:cacheprovider"],
        capture_output=True, text=True, env=env, cwd=workdir, timeout=180,
    )
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    if proc.returncode == 0 and "passed" in tail:
        return True, f"ok ({tail})"
    return False, f"hidden tests failed: {tail}"


SYN = BASE / "synthetic_tasks"


def build_pickle_workdir(dst: Path) -> None:
    shutil.copytree(SYN / "fix-insecure-pickle/environment/app", dst)


def build_syn_forensics_workdir(dst: Path) -> None:
    shutil.copytree(SYN / "bruteforce-ssh-forensics/environment/incident", dst / "incident")


def build_ctf_workdir(dst: Path) -> None:
    shutil.copytree(SYN / "staged-files-flag/environment/host", dst / "host")


TASKS = {
    "hello-file": {
        "instruction": (REPO / "local_task/hello-file/instruction.md").read_text().strip(),
        "workdir": lambda dst: dst.mkdir(parents=True, exist_ok=True),
        "verify": v_hello,
    },
    "bye-file": {
        "instruction": (REPO / "local_task/bye-file/instruction.md").read_text().strip(),
        "workdir": lambda dst: dst.mkdir(parents=True, exist_ok=True),
        "verify": v_bye,
    },
    "find-sqli-login": {
        "instruction": (REPO / "local_task/find-sqli-login/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(REPO / "local_task/find-sqli-login/environment/app", dst),
        "verify": v_security_report,
    },
    "incident-log-forensics": {
        "instruction": (REPO / "local_task/incident-log-forensics/instruction.md").read_text().strip(),
        "workdir": build_forensics_workdir,
        "verify": v_incident_report,
    },
    "fix-sqli-search": {
        "instruction": (REPO / "local_task/fix-sqli-search/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(REPO / "local_task/fix-sqli-search/environment/app", dst),
        "verify": v_static_sqli_fix,
    },
    # ---------------- synthetic (simulated private set) ----------------
    "syn-fix-insecure-pickle": {
        "instruction": (SYN / "fix-insecure-pickle/instruction.md").read_text().strip(),
        "workdir": build_pickle_workdir,
        "verify": v_pickle_fix,
    },
    "syn-bruteforce-ssh-forensics": {
        "instruction": (SYN / "bruteforce-ssh-forensics/instruction.md").read_text().strip(),
        "workdir": build_syn_forensics_workdir,
        "verify": lambda wd: _v_kv_report(wd, SYN / "bruteforce-ssh-forensics/tests/expected_incident_report.txt"),
    },
    "syn-staged-files-flag": {
        "instruction": (SYN / "staged-files-flag/instruction.md").read_text().strip(),
        "workdir": build_ctf_workdir,
        "verify": lambda wd: v_flag(wd, "flag{st4g3d_1005_xx9}"),
    },
}


# --------------------------- runner --------------------------- #


def run_task(name: str, token: str, max_requests: int, time_budget: int, save_logs: bool = True) -> dict:
    cfg = TASKS[name]
    task_dir = EVAL_ROOT / name
    workdir = task_dir / "app"
    if task_dir.exists():
        shutil.rmtree(task_dir)
    cfg["workdir"](workdir)
    workdir.chmod(0o755)

    env = os.environ.copy()
    env.update({
        "OPENAI_API_KEY": token,
        "OPENAI_BASE_URL": GROQ_BASE,
        "LOCAL_AGENT_MODEL": MODEL,
        "SEC_AGENT_PROXY_URL": PROXY,
        "SEC_AGENT_RPM": "30",
        "SEC_AGENT_RPD_CAP": "1000",
        "SEC_AGENT_MAX_REQUESTS": str(max_requests),
        "SEC_AGENT_MAX_TOKENS": "600",
        "SEC_AGENT_TIME_BUDGET": str(time_budget),
        "SEC_AGENT_WORKDIR": str(workdir),
        "SEC_AGENT_PATH_REMAP": str(workdir),
        "LOCAL_AGENT_WORKDIR": str(workdir),
        "PYTHONDONTWRITEBYTECODE": "1",
    })

    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(SUBMISSION / "sec_agent.py"), cfg["instruction"]],
        capture_output=True, text=True, env=env, timeout=time_budget + 90,
    )
    wall = round(time.monotonic() - started, 1)

    ok, msg = cfg["verify"](workdir)
    reqs = None
    m = re.findall(r'"event": "llm_requests", "n": (\d+)', proc.stdout)
    if m:
        reqs = int(m[-1])
    result = {
        "task": name,
        "solved": ok,
        "verifier": msg,
        "wall_sec": wall,
        "llm_requests": reqs,
        "exit_code": proc.returncode,
        "final_output": proc.stdout.strip().splitlines()[-1][:400] if proc.stdout.strip() else "",
    }
    if save_logs:
        (task_dir / "agent_stdout.log").write_text(proc.stdout[-60000:])
        (task_dir / "agent_stderr.log").write_text(proc.stderr[-30000:])
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / f"{name}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", required=True)
    parser.add_argument("--token-idx", type=int, default=0)
    parser.add_argument("--max-requests", type=int, default=25)
    parser.add_argument("--time-budget", type=int, default=420)
    args = parser.parse_args()

    token = TOKENS[args.token_idx % len(TOKENS)]
    EVAL_ROOT.mkdir(parents=True, exist_ok=True)

    for name in [t.strip() for t in args.tasks.split(",") if t.strip()]:
        if name not in TASKS:
            print(f"UNKNOWN TASK {name}; available: {list(TASKS)}")
            continue
        print(f"\n=== RUN {name} ===", flush=True)
        try:
            result = run_task(name, token, args.max_requests, args.time_budget)
        except subprocess.TimeoutExpired:
            result = {"task": name, "solved": False, "verifier": "harness timeout", "wall_sec": -1}
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
