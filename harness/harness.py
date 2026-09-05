#!/usr/bin/env python3
"""Local validation harness: runs submission agent against task workdirs.

Faithful to official Harbor semantics (P0 hardening):
- verify-after-kill: the verifier runs EVEN IF the agent hits its timeout
  (official task.toml agent.timeout_sec=600; Harbor kills the agent, the
  verifier still inspects whatever the agent left behind).
- per-task timeouts matching official task.toml (default 600s).
- fast-fail: the queue aborts as soon as a task fails on provider quota
  (daily cap / TPD), instead of burning every remaining task on 429 pauses.
- structured events: the agent writes SEC_AGENT_EVENTS_FILE (JSONL); the
  harness parses requests / tokens / failure signals from it (stdout regex
  is only a fallback).
- token accounting: tin/tout from final_usage -> the competition tie-break
  is solved-count -> time -> tokens, so tokens are a first-class metric.
- immutable run directories: results/<run_id>/<task>.json + run_manifest.json
  + summary.json (old behavior overwrote results/<task>.json per run).
- faithful verifier clones: hello/bye use official `$(cat)` semantics
  (trailing newlines stripped); forensics uses `^[a-z_]+=.+$` (spaces
  allowed in values) and LC_ALL=C byte-order sort.

Usage:
  python3 harness.py --tasks hello-file,bye-file [--token-idx 0]
                     [--max-requests 25] [--time-budget 600] [--provider groq|openrouter]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/home/z/my-project")
REPO = BASE / "UniversalAgenticCompetitionPublic"
SUBMISSION = BASE / "submission"
RESULTS = BASE / "results"
EVAL_ROOT = Path("/tmp/secagent_eval")
SYN = BASE / "synthetic_tasks"

PROVIDER_BASES = {
    "groq": os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
    "openrouter": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
}
# Provider-scoped defaults: a Groq key must never authenticate an OpenRouter
# run and vice versa (mismatched key -> opaque 401); model names also differ
# per provider serving.
DEFAULT_MODELS = {
    "groq": "qwen/qwen3.6-27b",
    "openrouter": "qwen/qwen3.6-35b-a3b",
}
PROVIDER_KEY_VARS = {
    "groq": ("GROQ_API_KEY_1", "GROQ_API_KEY_2"),
    "openrouter": ("OPENROUTER_API_KEY",),
}
MODEL = os.environ.get("LOCAL_AGENT_MODEL", "")  # resolved per-provider in main()
PROXY = ""  # resolved per-provider in main(): GROQ_PROXY / OPENROUTER_PROXY


def _resolve_tokens(provider: str) -> list[str]:
    """API tokens for THIS provider only (no cross-provider key leakage)."""
    return [v for v in (os.environ.get(k) for k in PROVIDER_KEY_VARS[provider]) if v]

DEFAULT_AGENT_TIMEOUT = 600  # official task.toml agent.timeout_sec


# --------------------------- verifiers --------------------------- #


def v_file_exact(workdir: Path, path: str, expected: str) -> tuple[bool, str]:
    """Official semantics (hello/bye test.sh): [ "$(cat /app/X)" = "E" ].
    $(cat) strips ALL trailing newlines; leading whitespace and trailing
    spaces are preserved by bash command substitution."""
    fp = workdir / path
    if not fp.exists():
        return False, f"{path} missing"
    got = fp.read_text(encoding="utf-8", errors="replace")
    if got.rstrip("\n") != expected:
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


def _c_sort_lines(lines: list[str]) -> list[str]:
    """LC_ALL=C sort equivalent: byte-wise ordering of the UTF-8 text."""
    return sorted(lines, key=lambda s: s.encode("utf-8", "surrogateescape"))


def _v_kv_report(workdir: Path, expected_src: Path, n_lines: int = 4) -> tuple[bool, str]:
    """Replicates official forensics test.sh:
    - exactly N non-empty lines (grep -cve '^$')
    - each line matches ^[a-z_]+=.+$  (spaces ALLOWED in value; backslash-S was a drift)
    - no ' = ' substring
    - normalize (strip trailing \r) then LC_ALL=C sort, then diff."""
    report = workdir / "incident_report.txt"
    if not report.exists():
        return False, "incident_report.txt missing"
    raw = report.read_text(encoding="utf-8", errors="replace")
    got_lines = [ln[:-1] if ln.endswith("\r") else ln for ln in raw.splitlines()]
    got_lines = [ln for ln in got_lines if ln != ""]  # grep -cve '^$' counts non-empty only
    if len(got_lines) != n_lines:
        return False, f"expected {n_lines} non-empty lines, got {len(got_lines)}"
    for ln in got_lines:
        if not re.match(r"^[a-z_]+=.+$", ln):
            return False, f"format violation: {ln!r}"
        if " = " in ln:
            return False, f"format violation (space around =): {ln!r}"
    if not expected_src.exists():
        return False, f"expected-file missing: {expected_src}"
    exp_raw = expected_src.read_text(encoding="utf-8", errors="replace")
    exp_lines = [ln[:-1] if ln.endswith("\r") else ln for ln in exp_raw.splitlines()]
    exp_lines = [ln for ln in exp_lines if ln != ""]
    got_sorted = _c_sort_lines(got_lines)
    exp_sorted = _c_sort_lines(exp_lines)
    if got_sorted != exp_sorted:
        diff = {"expected": exp_sorted, "got": got_sorted}
        return False, f"content mismatch: {json.dumps(diff, ensure_ascii=False)}"
    return True, "ok"


def v_incident_report(workdir: Path) -> tuple[bool, str]:
    expected_src = REPO / "local_task/incident-log-forensics/solution/expected_incident_report.txt"
    return _v_kv_report(workdir, expected_src, n_lines=4)


def v_static_sqli_fix(workdir: Path) -> tuple[bool, str]:
    """STATIC fidelity: official verifier boots PostgreSQL + uvicorn and runs
    a hidden pytest suite; no local postgres, so we only check the vulnerable
    patterns are gone. A local pass here is necessary but NOT sufficient."""
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
    return True, "ok (STATIC check; live-service regression not runnable locally)"


def v_flag(workdir: Path, flag: str) -> tuple[bool, str]:
    if (workdir / "flag.txt").exists() and (workdir / "flag.txt").read_text(encoding="utf-8", errors="replace").strip() == flag:
        return True, "ok"
    return False, f"flag.txt must contain exactly {flag!r}"


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


def v_live_service(workdir: Path, tests_dir: Path, wait_sec: int = 30) -> tuple[bool, str]:
    """Generic LIVE-SERVICE verifier clone (official fix-task semantics):
    kill stale uvicorns owned by the agent, start `uvicorn main:app` from the
    workdir under VERIFIER control, wait for /healthz, run the hidden pytest
    suite, clean up. Use for fix-specs backed by sqlite/in-memory stores
    (e.g. future TASK-15/16/21 implementations)."""
    subprocess.run(["pkill", "-f", "uvicorn main:app"], capture_output=True)
    time.sleep(1)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(workdir)
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000",
         "--log-level", "warning"],
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
        if proc.returncode == 0:
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
        "fidelity": "official-clone",
        "timeout": 120,
    },
    "bye-file": {
        "instruction": (REPO / "local_task/bye-file/instruction.md").read_text().strip(),
        "workdir": lambda dst: dst.mkdir(parents=True, exist_ok=True),
        "verify": v_bye,
        "fidelity": "official-clone",
        "timeout": 120,
    },
    "find-sqli-login": {
        "instruction": (REPO / "local_task/find-sqli-login/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(REPO / "local_task/find-sqli-login/environment/app", dst),
        "verify": v_security_report,
        "fidelity": "official-clone",
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    "incident-log-forensics": {
        "instruction": (REPO / "local_task/incident-log-forensics/instruction.md").read_text().strip(),
        "workdir": build_forensics_workdir,
        "verify": v_incident_report,
        "fidelity": "official-clone",
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    "fix-sqli-search": {
        "instruction": (REPO / "local_task/fix-sqli-search/instruction.md").read_text().strip(),
        "workdir": lambda dst: build_app_workdir(REPO / "local_task/fix-sqli-search/environment/app", dst),
        "verify": v_static_sqli_fix,
        "fidelity": "static-only",  # official runs live service + postgres; locally impossible
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    # ---------------- synthetic (simulated private set) ----------------
    "syn-fix-insecure-pickle": {
        "instruction": (SYN / "fix-insecure-pickle/instruction.md").read_text().strip(),
        "workdir": build_pickle_workdir,
        "verify": v_pickle_fix,
        "fidelity": "hidden-pytest-offline",
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    "syn-bruteforce-ssh-forensics": {
        "instruction": (SYN / "bruteforce-ssh-forensics/instruction.md").read_text().strip(),
        "workdir": build_syn_forensics_workdir,
        "verify": lambda wd: _v_kv_report(wd, SYN / "bruteforce-ssh-forensics/tests/expected_incident_report.txt"),
        "fidelity": "official-clone-style",
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
    "syn-staged-files-flag": {
        "instruction": (SYN / "staged-files-flag/instruction.md").read_text().strip(),
        "workdir": build_ctf_workdir,
        "verify": lambda wd: v_flag(wd, "flag{st4g3d_1005_xx9}"),
        "fidelity": "official-clone-style",
        "timeout": DEFAULT_AGENT_TIMEOUT,
    },
}


# --------------------------- runner --------------------------- #


def _agent_sha256() -> str:
    return hashlib.sha256((SUBMISSION / "sec_agent.py").read_bytes()).hexdigest()[:16]


def _parse_events(events_path: Path) -> tuple[int | None, dict | None, set[str]]:
    """Parse the agent's structured JSONL: request count, final usage, signals."""
    last_requests: int | None = None
    usage: dict | None = None
    signals: set[str] = set()
    if not events_path.exists():
        return last_requests, usage, signals
    try:
        for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except Exception:
                continue
            e = ev.get("event")
            if e == "llm_requests":
                last_requests = ev.get("n")
            elif e == "final_usage":
                usage = ev
                if ev.get("requests") is not None:
                    last_requests = ev["requests"]
            elif e in ("daily_cap_hit", "rpd_cap"):
                signals.add("daily_cap")
            elif e == "budget_exhausted":
                signals.add("budget")
            elif e == "output_truncated":
                signals.add("truncated")
            elif e == "fatal":
                signals.add("crash")
            elif e == "fastpath":
                signals.add("fastpath")
            elif e == "itpm_retry":
                signals.add("itpm_413")
    except Exception:
        pass
    return last_requests, usage, signals


def _fail_class(solved: bool, verifier_msg: str, signals: set[str], exit_code: int,
                timed_out: bool) -> str:
    if solved:
        return "ok"
    if "daily_cap" in signals:
        return "quota"
    if timed_out:
        return "timeout"
    if "crash" in signals or (exit_code not in (0, None)):
        return "crash"
    low = verifier_msg.lower()
    if "missing" in low:
        return "deliverable-missing"
    if "format" in low:
        return "deliverable-format"
    return "deliverable-content"


def run_task(name: str, token: str, max_requests: int, time_budget: int,
             run_dir: Path, base_url: str) -> dict:
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
        "OPENAI_BASE_URL": base_url,
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
        "SEC_AGENT_EVENTS_FILE": str(task_dir / "agent_events.jsonl"),
        "PYTHONDONTWRITEBYTECODE": "1",
    })

    started = time.monotonic()
    timed_out = False
    proc = None
    try:
        proc = subprocess.run(
            [sys.executable, str(SUBMISSION / "sec_agent.py"), cfg["instruction"]],
            capture_output=True, text=True, env=env, timeout=time_budget + 90,
        )
        stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        # verify-after-kill: official Harbor kills the agent at timeout and
        # the verifier still inspects leftovers; do the same locally.
        timed_out = True
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        exit_code = None
    wall = round(time.monotonic() - started, 1)

    # Verifier ALWAYS runs (even after kill) - official semantics.
    try:
        ok, msg = cfg["verify"](workdir)
    except Exception as exc:
        ok, msg = False, f"verifier error: {exc!r}"

    events_path = task_dir / "agent_events.jsonl"
    reqs, usage, signals = _parse_events(events_path)
    if reqs is None:  # fallback: legacy stdout regex
        m = re.findall(r'"event": "llm_requests", "n": (\d+)', stdout or "")
        if m:
            reqs = int(m[-1])

    result = {
        "task": name,
        "solved": ok,
        "fail_class": _fail_class(ok, msg, signals, exit_code, timed_out),
        "verifier": msg,
        "fidelity": cfg["fidelity"],
        "wall_sec": wall,
        "agent_timed_out": timed_out,
        "llm_requests": reqs,
        "tokens_in": (usage or {}).get("tin"),
        "tokens_out": (usage or {}).get("tout"),
        "signals": sorted(signals),
        "exit_code": exit_code,
        "final_output": (stdout or "").strip().splitlines()[-1][:400] if (stdout or "").strip() else "",
    }
    (task_dir / "agent_stdout.log").write_text((stdout or "")[-60000:])
    (task_dir / "agent_stderr.log").write_text((stderr or "")[-30000:])
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / f"{name}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", required=True)
    parser.add_argument("--token-idx", type=int, default=0)
    parser.add_argument("--max-requests", type=int, default=25)
    parser.add_argument("--time-budget", type=int, default=0,
                        help="override per-task timeouts; 0 = use official 600s")
    parser.add_argument("--provider", choices=sorted(PROVIDER_BASES), default="openrouter")
    args = parser.parse_args()

    tokens = _resolve_tokens(args.provider)
    if not tokens:
        print(f"NO API TOKEN for provider '{args.provider}' "
              f"(set {', '.join(PROVIDER_KEY_VARS[args.provider])})")
        sys.exit(2)
    token = tokens[args.token_idx % len(tokens)]
    base_url = PROVIDER_BASES[args.provider]
    global MODEL, PROXY
    MODEL = os.environ.get("LOCAL_AGENT_MODEL") or DEFAULT_MODELS[args.provider]
    PROXY = (os.environ.get("GROQ_PROXY", "") if args.provider == "groq"
             else os.environ.get("OPENROUTER_PROXY", ""))
    EVAL_ROOT.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RESULTS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (RESULTS / "latest-run.txt").write_text(run_id + "\n")

    task_names = [t.strip() for t in args.tasks.split(",") if t.strip()]
    manifest = {
        "run_id": run_id,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "provider": args.provider,
        "base_url": base_url,
        "model": MODEL,
        "agent_sha256_16": _agent_sha256(),
        "max_requests": args.max_requests,
        "time_budget_override": args.time_budget or None,
        "tasks": task_names,
    }
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"RUN {run_id} provider={args.provider} model={MODEL} agent={manifest['agent_sha256_16']}")

    results: list[dict] = []
    for name in task_names:
        if name not in TASKS:
            print(f"UNKNOWN TASK {name}; available: {list(TASKS)}")
            continue
        budget = args.time_budget or TASKS[name]["timeout"]
        print(f"\n=== RUN {name} (budget {budget}s, fidelity {TASKS[name]['fidelity']}) ===", flush=True)
        try:
            result = run_task(name, token, args.max_requests, budget, run_dir, base_url)
        except subprocess.TimeoutExpired:
            result = {"task": name, "solved": False, "fail_class": "timeout",
                      "verifier": "harness timeout", "wall_sec": -1}
        results.append(result)
        print(json.dumps(result, indent=2, ensure_ascii=False), flush=True)

        # Fast-fail: do not burn the queue when the provider quota is dead.
        if result.get("fail_class") == "quota":
            print(f"\n!! QUOTA EXHAUSTED on {name} - aborting remaining queue "
                  f"({len(task_names) - len(results)} tasks skipped)")
            break

    solved = sum(1 for r in results if r.get("solved"))
    summary = {
        "run_id": run_id,
        "solved": solved,
        "total": len(results),
        "requests": sum(r.get("llm_requests") or 0 for r in results),
        "tokens_in": sum(r.get("tokens_in") or 0 for r in results),
        "tokens_out": sum(r.get("tokens_out") or 0 for r in results),
        "wall_sec_total": round(sum(r.get("wall_sec") or 0 for r in results), 1),
        "fail_classes": {fc: sum(1 for r in results if r.get("fail_class") == fc)
                         for fc in {r.get("fail_class") for r in results}},
        "results": results,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\n=== SUMMARY run={run_id}: solved {solved}/{len(results)}, "
          f"requests {summary['requests']}, tokens {summary['tokens_in']}/{summary['tokens_out']} ===")


if __name__ == "__main__":
    main()
