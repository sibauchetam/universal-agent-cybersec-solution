#!/usr/bin/env python3
"""Universal cybersecurity agent for Universal Agent Competition.

Design (research-backed, see repo docs/research.md):
- SDK-first: pydantic-ai 1.x tool loop, raw openai-SDK fallback loop.
- Mechanical task classification + trivial fast-path (0 requests).
- replace_in_file as primary patching tool (unified diffs are unreliable for small models).
- Typed pytest feedback (error_type/expected/actual/location) instead of raw tracebacks.
- External-oracle self-verification of the deliverable + repair loop before finishing.
- Strict token/time budgets; serial requests only.

Env interface (set by Harbor wrapper):
  LOCAL_AGENT_MODEL, OPENAI_BASE_URL, OPENAI_API_KEY
Optional:
  SEC_AGENT_MAX_REQUESTS (default 45), SEC_AGENT_TIME_BUDGET (default 540s),
  SEC_AGENT_PROXY_URL (httpx proxy for testing), SEC_AGENT_WORKDIR,
  SEC_AGENT_TOOL_OUTPUT_CHARS (7000), SEC_AGENT_CMD_TIMEOUT (90s)
"""
from __future__ import annotations

import asyncio
import difflib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

LOGGER = logging.getLogger("sec-agent")
SECRET_MARKERS = ("api_key", "apikey", "token", "secret", "password")

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


START = time.monotonic()
REQUEST_COUNT = 0
# Test-only: redirect absolute /app paths to a local workdir when /app is unavailable.
APP_REMAP = _env("SEC_AGENT_PATH_REMAP")
MODEL_NAME = _env("LOCAL_AGENT_MODEL") or _env("OPENAI_MODEL") or "default"
BASE_URL = _env("OPENAI_BASE_URL") or "http://127.0.0.1:8000/v1"
API_KEY = _env("OPENAI_API_KEY") or "not-needed"
PROXY = _env("SEC_AGENT_PROXY_URL") or _env("AGENT_PROXY_URL")
MAX_REQUESTS = int(_env("SEC_AGENT_MAX_REQUESTS", "45") or 45)
TIME_BUDGET = float(_env("SEC_AGENT_TIME_BUDGET", "540") or 540)
CMD_TIMEOUT = int(_env("SEC_AGENT_CMD_TIMEOUT", "90") or 90)
TOOL_CHARS = int(_env("SEC_AGENT_TOOL_OUTPUT_CHARS", "7000") or 7000)
TEMPERATURE = float(_env("SEC_AGENT_TEMPERATURE", "0.2") or 0.2)
MAX_TOKENS = int(_env("SEC_AGENT_MAX_TOKENS", "8192") or 8192)
REASONING_EFFORT = _env("SEC_AGENT_REASONING_EFFORT")  # e.g. "none" to suppress qwen thinking


def _resolve_workdir() -> Path:
    """Prefer /app (all competition tasks operate there)."""
    forced = _env("SEC_AGENT_WORKDIR")
    if forced:
        return Path(forced).resolve()
    if os.path.isdir("/app"):
        return Path("/app")
    raw = _env("LOCAL_AGENT_WORKDIR")
    if raw:
        return Path(raw).resolve()
    return Path.cwd().resolve()


def time_left() -> float:
    return TIME_BUDGET - (time.monotonic() - START)


def _trunc(text: str, limit: int | None = None) -> str:
    limit = limit or TOOL_CHARS
    if len(text) <= limit:
        return text
    cut = text[:limit]
    # keep last line intact
    nl = cut.rfind("\n")
    if nl > limit // 2:
        cut = cut[:nl]
    return f"{cut}\n... [truncated {len(text) - limit} chars; use grep/read_file to target content]"


def _log(event: str, **fields: Any) -> None:
    payload = {"event": event}
    for key, value in fields.items():
        if any(m in key.lower() for m in SECRET_MARKERS):
            value = "<redacted>"
        if isinstance(value, str) and len(value) > 2000:
            value = value[:2000] + "...<snip>"
        payload[key] = value
    try:
        LOGGER.info(json.dumps(payload, ensure_ascii=False, default=str))
    except Exception:
        LOGGER.info(json.dumps({"event": event}))


def _setup_logging() -> None:
    if LOGGER.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[sec-agent] %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False


# --------------------------------------------------------------------------- #
# Tool implementations (shared by both loops)
# --------------------------------------------------------------------------- #


@dataclass
class AgentState:
    workdir: Path
    tool_calls: int = 0
    notes: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.notes is None:
            self.notes = {}


def remap_path(p: Path) -> Path:
    if APP_REMAP and str(p).startswith("/app"):
        rel = str(p)[len("/app"):].lstrip("/")
        return Path(APP_REMAP) / rel
    return p


def _resolve_path(path: str, state: AgentState) -> Path:
    p = Path(path)
    if not p.is_absolute():
        p = state.workdir / p
    return remap_path(p.resolve())


async def _subprocess(command: str, cwd: Path | None, timeout: int) -> tuple[int, str]:
    """Run shell command; never raises; bounded output."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=str(cwd) if cwd else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:  # pragma: no cover
        return 127, f"spawn failed: {exc!r}"
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return 124, f"[timeout after {timeout}s] partial output suppressed"
    out = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")
    text = ""
    if out:
        text += f"[stdout]\n{out}"
    if err:
        text += f"[stderr]\n{err}"
    if not text:
        text = "<empty>"
    return proc.returncode or 0, text


async def tool_bash(state: AgentState, command: str) -> str:
    state.tool_calls += 1
    code, text = await _subprocess(command, state.workdir, CMD_TIMEOUT)
    return _trunc(f"[exit {code}] $ {command}\n{text}")


async def tool_read_file(state: AgentState, path: str, start_line: int = 1, max_lines: int = 400) -> str:
    state.tool_calls += 1
    fp = _resolve_path(path, state)
    if not fp.is_file():
        # helpful near-miss suggestions
        parent = fp.parent
        names = [p.name for p in parent.iterdir()] if parent.is_dir() else []
        close = difflib.get_close_matches(fp.name, names, n=3)
        return f"ERROR: not a file: {fp}. Nearby entries: {close or names[:20]}"
    try:
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return f"ERROR reading {fp}: {exc!r}"
    total = len(lines)
    start_line = max(1, int(start_line))
    max_lines = max(10, min(int(max_lines), 800))
    chunk = lines[start_line - 1 : start_line - 1 + max_lines]
    numbered = "\n".join(f"{i + start_line:>5}| {ln}" for i, ln in enumerate(chunk))
    more = ""
    if start_line - 1 + max_lines < total:
        more = f"\n... [{total - (start_line - 1 + max_lines)} more lines; call with start_line={start_line + max_lines}]"
    return _trunc(f"[{fp} | {total} lines]\n{numbered}{more}")


async def tool_write_file(state: AgentState, path: str, content: str) -> str:
    state.tool_calls += 1
    fp = _resolve_path(path, state)
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(content, encoding="utf-8")
        return f"OK: wrote {len(content)} chars to {fp}"
    except Exception as exc:
        return f"ERROR writing {fp}: {exc!r}"


async def tool_append_file(state: AgentState, path: str, content: str) -> str:
    state.tool_calls += 1
    fp = _resolve_path(path, state)
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        with fp.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return f"OK: appended {len(content)} chars to {fp}"
    except Exception as exc:
        return f"ERROR appending {fp}: {exc!r}"


async def tool_replace_in_file(state: AgentState, path: str, old_text: str, new_text: str) -> str:
    """Exact single-match replacement; returns the closest context when it fails
    (small models copy context imperfectly - show them the real text)."""
    state.tool_calls += 1
    fp = _resolve_path(path, state)
    if not fp.is_file():
        return f"ERROR: not a file: {fp}"
    src = fp.read_text(encoding="utf-8", errors="replace")
    count = src.count(old_text)
    if count == 1:
        fp.write_text(src.replace(old_text, new_text, 1), encoding="utf-8")
        return f"OK: replaced 1 occurrence in {fp}"
    if count > 1:
        return f"ERROR: {count} occurrences of old_text in {fp}; add more surrounding context to make it unique."
    # not found: offer closest window to help the model fix its copy
    lines = src.splitlines()
    probe = old_text.strip().splitlines()[0][:80] if old_text.strip() else ""
    best, ratio = "", 0.0
    if probe:
        for idx in range(max(1, len(lines) - 8)):
            window = "\n".join(lines[idx : idx + max(2, len(old_text.splitlines()))])
            r = difflib.SequenceMatcher(None, probe, window[:400]).ratio()
            if r > ratio:
                best, ratio = window, r
    hint = f"Closest matching region (similarity {ratio:.0%}):\n{best[:900]}" if best else ""
    return f"ERROR: old_text not found in {fp}. Copy the EXACT text from read_file output. {hint}"


async def tool_apply_patch(state: AgentState, path: str, diff_content: str) -> str:
    state.tool_calls += 1
    fp = _resolve_path(path, state)
    if not fp.is_file():
        return f"ERROR: not a file: {fp}"
    code, text = await _subprocess("", None, 1)  # placeholder to keep async shape uniform
    proc = await asyncio.create_subprocess_exec(
        "patch", "-N", "-r", "-", str(fp),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(diff_content.encode()), timeout=30)
    except asyncio.TimeoutError:
        return "ERROR: patch timed out"
    out = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        return f"ERROR: patch failed (exit {proc.returncode}).\n{out}\n{err}\nPrefer replace_in_file instead."
    return f"OK: applied diff to {fp}\n{out}"


async def tool_list_dir(state: AgentState, path: str = ".") -> str:
    state.tool_calls += 1
    root = _resolve_path(path, state)
    if not root.exists():
        return f"ERROR: not found: {root}"
    cmd = (
        f"find {shlex.quote(str(root))} -maxdepth 3 "
        f"-not -path '*/.git*' -not -path '*/node_modules*' -not -path '*/__pycache__*' "
        f"-not -path '*/.venv*' | head -200"
    )
    code, text = await _subprocess(cmd, None, 30)
    return _trunc(f"[tree {root}]\n{text}")


async def tool_grep(state: AgentState, pattern: str, path: str = ".", glob: str = "", case_insensitive: bool = False) -> str:
    state.tool_calls += 1
    root = _resolve_path(path, state)
    if shutil.which("rg"):
        cmd = "rg -n --no-heading -S " if not case_insensitive else "rg -n --no-heading -i "
        cmd += shlex.quote(pattern) + " " + shlex.quote(str(root))
        cmd += " -g '!node_modules' -g '!.git' -g '!__pycache__' -g '!.venv'"
        if glob:
            cmd += " -g " + shlex.quote(glob)
        cmd += " | head -120"
    else:
        cmd = f"grep -rn{'i' if case_insensitive else ''} -e {shlex.quote(pattern)} {shlex.quote(str(root))}"
        cmd += " --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=__pycache__ --exclude-dir=.venv"
        if glob:
            cmd += f" --include={shlex.quote(glob)}"
        cmd += " | head -120"
    code, text = await _subprocess(cmd, None, 30)
    return _trunc(f"[grep '{pattern}' in {root} | exit {code}]\n{text}")


def parse_pytest_feedback(raw: str) -> str:
    """Typed structured feedback instead of raw traceback (research: +42pp on small models)."""
    failures: list[str] = []
    errors: list[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("FAILED ") or s.startswith("ERROR "):
            failures.append(s)
        if "AssertionError" in s or "Error" in s and ":" in s and len(s) < 300:
            if s not in errors:
                errors.append(s)
    summary = ""
    m = re.search(r"=+ (.+) =+", raw.splitlines()[-1] if raw.splitlines() else "")
    if m:
        summary = m.group(1)
    n_failed = len(failures)
    head = f"[pytest result] {summary or ('FAILURES: ' + str(n_failed) if n_failed else 'see output')}"
    typed = {
        "status": "failed" if (n_failed or "failed" in summary) else ("passed" if "passed" in summary else "unknown"),
        "n_failed_named": n_failed,
        "failed_tests": failures[:10],
        "error_types_found": errors[:6],
    }
    tail = raw[-2500:]
    return f"{head}\n[typed feedback] {json.dumps(typed, ensure_ascii=False)}\n[raw tail]\n{tail}"


async def tool_run_pytest(state: AgentState, paths: str = "tests/") -> str:
    state.tool_calls += 1
    args = paths or "tests/"
    cmd = f"python3 -m pytest {args} -q --tb=short -p no:cacheprovider 2>&1 | tail -80"
    code, text = await _subprocess(cmd, state.workdir, min(CMD_TIMEOUT, 180))
    return _trunc(parse_pytest_feedback(text), 6000)


# Tool registry: name -> (json_schema, coroutine(state, **kwargs))
TOOL_SPECS: dict[str, dict[str, Any]] = {
    "bash": {
        "description": "Run a shell command in the workspace. Use for curl, strings, base64, git, docker, etc.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string", "description": "shell command"}},
            "required": ["command"],
        },
    },
    "read_file": {
        "description": "Read a text file with line numbers. Supports start_line/max_lines for big files.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "description": "1-based first line (default 1)"},
                "max_lines": {"type": "integer", "description": "default 400"},
            },
            "required": ["path"],
        },
    },
    "write_file": {
        "description": "Create/overwrite a file with exact content (deliverable reports, flag files).",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
    },
    "append_file": {
        "description": "Append content to an existing file.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    "replace_in_file": {
        "description": "PREFERRED way to edit code: replace one exact old_text fragment with new_text. Copy old_text verbatim from read_file output.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "old_text": {"type": "string"},
                "new_text": {"type": "string"},
            },
            "required": ["path", "old_text", "new_text"],
        },
    },
    "apply_patch": {
        "description": "Apply a unified diff to a file (fallback for big multi-line edits).",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "diff_content": {"type": "string"}},
            "required": ["path", "diff_content"],
        },
    },
    "list_dir": {
        "description": "List files up to depth 3 with find (no sizes).",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "default '.'"}},
            "required": [],
        },
    },
    "grep": {
        "description": "Search file contents (ripgrep/grep). Great first move: hunt sinks like execute(, eval(, subprocess, pickle.loads, jwt.decode.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "path": {"type": "string", "description": "default '.'"},
                "glob": {"type": "string", "description": "e.g. '*.py'"},
                "case_insensitive": {"type": "boolean"},
            },
            "required": ["pattern"],
        },
    },
    "run_pytest": {
        "description": "Run pytest in the workspace; returns typed feedback (status, failed tests, error types).",
        "parameters": {
            "type": "object",
            "properties": {"paths": {"type": "string", "description": "default 'tests/'"}},
            "required": [],
        },
    },
}

TOOL_FUNCS: dict[str, Callable[..., Awaitable[str]]] = {
    "bash": tool_bash,
    "read_file": tool_read_file,
    "write_file": tool_write_file,
    "append_file": tool_append_file,
    "replace_in_file": tool_replace_in_file,
    "apply_patch": tool_apply_patch,
    "list_dir": tool_list_dir,
    "grep": tool_grep,
    "run_pytest": tool_run_pytest,
}


# --------------------------------------------------------------------------- #
# Task classification (mechanical first, LLM fallback)
# --------------------------------------------------------------------------- #

TRIVIAL_PATTERNS = [
    re.compile(r"[Cc]reate (?:a|an) file at [`\"']?(/app/[\w./\-]+|[\w./\-]+)[`\"']?\s+whose entire content is exactly (?:the single word )?[`\"']?([\w]+)[`\"']?"),
    re.compile(r"[Cc]reate (?:a|an) file [`\"']?([\w./\-]+)[`\"']?\s+(?:at\s+)?whose? content is exactly (?:the single word )?[`\"']?([\w]+)[`\"']?"),
]


def detect_trivial(instruction: str) -> tuple[str, str] | None:
    """Returns (path, exact_content) for trivial file-creation tasks."""
    for rx in TRIVIAL_PATTERNS:
        m = rx.search(instruction)
        if m:
            path, content = m.group(1), m.group(2)
            if not path.startswith("/"):
                path = "/app/" + path.lstrip("./")
            return path, content
    return None


def classify_mechanical(instruction: str) -> str:
    low = instruction.lower()
    if "incident_report" in low or "key=value" in low or "forensic" in low:
        return "forensics"
    if "security_report" in low and ("json" in low or "findings" in low):
        return "audit"
    if "flag{" in low or "ctf" in low or "capture the flag" in low:
        return "ctf"
    if re.search(r"\bfix\b|\brepair\b|remediat|patch\b", low) and re.search(r"test|regression|pytest", low):
        return "fix"
    if re.search(r"\bfix\b|\brepair\b|vulnerab|insecure", low):
        return "fix"
    if "audit" in low or "report" in low:
        return "audit"
    return "generic"


def guess_deliverable(instruction: str, kind: str, workdir: Path) -> str:
    # Prefer explicit deliverable filenames over incidental /app paths (artifact dirs).
    m = re.search(r"/app/[A-Za-z0-9_./-]*(?:security_report\.json|incident_report\.txt|flag\.txt|[A-Za-z0-9_-]+\.(?:json|txt|md))", instruction)
    if not m:
        m = re.search(r"`(/app/[^`\s]+)`", instruction)
    if not m:
        m = re.search(r"/app/[A-Za-z0-9_./-]+", instruction)
    if m:
        return m.group(1) if m.groups() and m.group(1) else m.group(0)
    defaults = {
        "audit": str(workdir / "security_report.json"),
        "forensics": str(workdir / "incident_report.txt"),
        "ctf": str(workdir / "flag.txt"),
    }
    return defaults.get(kind, "")


# --------------------------------------------------------------------------- #
# Prompts
# --------------------------------------------------------------------------- #

SYSTEM_COMMON = """You are an elite, non-interactive cybersecurity agent completing a task autonomously inside a Linux workspace. The verifier checks a concrete deliverable file with BINARY scoring (pass/fail), so precision about the required format matters more than eloquence.

Operating rules:
- You have a limited request budget. Every turn should do useful work: run a tool, then think briefly, then act again.
- Read the task instruction carefully: the deliverable path, exact format, and required keys are all specified there. Never invent extra keys or formats.
- File edits: use replace_in_file with old_text copied EXACTLY from read_file output (line numbers prefix each line - strip the `N|` prefix). Use write_file only for NEW files like reports.
- Prefer running things (pytest, curl, python3) over guessing. Verify claims with evidence.
- Finish by writing the deliverable, then reply with a short summary (<=120 words). Do not print the file content in your final reply."""


WORKFLOWS: dict[str, str] = {
    "audit": """WORKFLOW for security audit (bug-bounty style JSON report):
1. list_dir to map the codebase; grep for dangerous sinks: "execute(", "fetchrow(", "f\"", "eval(", "exec(", "subprocess", "os.system", "pickle", "yaml.load", "md5", "sha1", "jwt.decode", "redirect(", "requests.get(".
2. read_file every candidate location plus its imports/models to confirm reachability and attacker-controlled dataflow (source -> sink). Read auth/db/routers files fully if small.
3. For each CONFIRMED issue record: exact file + function/endpoint, a verbatim code snippet as evidence, realistic impact, concrete fix (e.g. parameterized query).
4. Write the deliverable JSON exactly as the instruction specifies. Include the most critical finding with full detail; add other confirmed findings. Severity must be one of critical|high|medium|low|informational.
5. Double-check the report is valid JSON and mentions the exact endpoint/function names from the code.""",
    "fix": """WORKFLOW for vulnerability fixing (keep functionality green):
1. run_pytest FIRST to capture the baseline (before any edit).
2. grep sinks and read the vulnerable code paths. Identify the minimal correct fix.
3. Apply fixes with replace_in_file. Standard fixes: parameterize SQL queries (db.fetch(query, param)), sanitize/avoid shell (shlex.join, subprocess without shell=True), validate/authorize object ownership, replace weak crypto, restrict deserialization.
4. run_pytest again - all tests MUST pass. If a test fails, read the typed feedback (failed_tests, error_types_found) and fix precisely; loop until green.
5. Do not rename public functions/models or change response schemas. Do not add dependencies.""",
    "forensics": """WORKFLOW for log forensics:
1. list_dir the artifacts directory; read_file EVERY artifact fully (they are small). Do not sample - decisive fields hide in any file.
2. Build a timeline. Correlate identities across sources: proxy XFF IPs <-> app audit subjects <-> auth log users. Watch for: truncated/recovered files, split log shards, decoy IPs and red herrings.
3. Compute each required field exactly as the instruction maps it (e.g. payload_logical_bytes if present else bytes; verbatim ISO timestamp including fractional seconds).
4. Write the deliverable in the EXACT format: one key=value per line, no spaces around '=', no blank lines, no comments, no extra keys. Numbers without quotes/commas.
5. Re-read your deliverable and diff it mentally against the instruction checklist before finishing.""",
    "ctf": """WORKFLOW for CTF-style tasks:
1. Recon: list_dir, then bash with `find . -type f | head -50`, `file` on interesting files.
2. Hunt flags: grep for "flag{", "FLAG", "ctf{", also check env vars, git log/history, archive contents (unzip -l, tar -tzf), encoded blobs (base64 -d, strings, xxd), layered encodings.
3. Beware DECOY flags: a file literally named flag.txt may contain a fake flag; the real one may be split across chunks, hidden in metadata, or assembled from pieces. Verify the flag matches the exact format the instruction requests.
4. Write the deliverable exactly as instructed and re-verify its content.""",
    "generic": """WORKFLOW (generic):
1. list_dir + read key files to understand what is asked.
2. Identify the concrete deliverable (file path + format) from the instruction.
3. Do the work with tools; verify with external oracles where possible (pytest, running services, JSON parsing).
4. Write the deliverable and double-check its format against the instruction.""",
}

CRITIC_PROMPT = """CRITIC PASS. Review your deliverable now, as a hostile external verifier would:
1. Re-read the instruction: deliverable path, exact format, required keys, field mappings.
2. Read the deliverable file. Check: correct path? valid JSON / exact line format? all required keys present exactly once? values plausible and consistent with evidence you saw?
3. If anything is off, fix it with tools immediately.
If everything is correct, reply with the single word: OK"""

REPAIR_PROMPT = """Your deliverable failed mechanical verification:
{reason}
Fix the deliverable NOW using tools (read it, correct it, write it). Then reply with a one-line confirmation."""


def build_system_prompt(kind: str) -> str:
    return SYSTEM_COMMON + "\n\n" + WORKFLOWS.get(kind, WORKFLOWS["generic"])


def build_first_message(instruction: str, kind: str, workdir: Path, baseline: str) -> str:
    parts = [f"TASK INSTRUCTION:\n{instruction}"]
    code, text = _run_sync_quiet(f"find {shlex.quote(str(workdir))} -maxdepth 2 -not -path '*/.git*' -not -path '*/__pycache__*' -not -path '*/.venv*' -type f | head -60; echo '---'; du -sh {shlex.quote(str(workdir))} 2>/dev/null")
    parts.append(f"\nWORKSPACE SNAPSHOT ({workdir}):\n{text}")
    if baseline:
        parts.append(f"\nBASELINE TEST RESULT (before any edits):\n{baseline}")
    return "\n".join(parts)


def _run_sync_quiet(command: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        return proc.returncode or 0, (proc.stdout + proc.stderr)
    except Exception as exc:
        return 1, repr(exc)


# --------------------------------------------------------------------------- #
# Deliverable verification (external-oracle style)
# --------------------------------------------------------------------------- #


def verify_deliverable(kind: str, deliverable: str, workdir: Path) -> tuple[bool, str]:
    if not deliverable:
        return False, "no deliverable path identified"
    fp = Path(deliverable)
    if not fp.is_absolute():
        fp = workdir / fp
    if not fp.exists():
        return False, f"deliverable file missing: {fp}"
    try:
        content = fp.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return False, f"deliverable unreadable: {exc!r}"
    if kind == "audit":
        try:
            data = json.loads(content)
        except Exception as exc:
            return False, f"not valid JSON: {exc}"
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list) or not data.get("findings"):
            return False, "JSON must be an object with non-empty 'findings' array"
        return True, "ok"
    if kind == "forensics":
        lines = [ln for ln in content.replace("\r\n", "\n").split("\n") if ln.strip()]
        if len(lines) != len(set(ln.split("=")[0] for ln in lines if "=" in ln)):
            return False, "duplicate keys detected"
        if not (2 <= len(lines) <= 12):
            return False, f"expected 2..12 key=value lines, got {len(lines)}"
        for ln in lines:
            if not re.match(r"^[a-z_]+=\S+$", ln):
                return False, f"line violates key=value format: {ln[:80]!r}"
            if " = " in ln:
                return False, f"spaces around '=' are forbidden: {ln[:80]!r}"
        return True, "ok"
    if kind == "ctf":
        if re.search(r"flag\{|FLAG\{|ctf\{|CTF\{", content) or len(content.strip()) > 0:
            return True, "ok"
        return False, "flag file empty"
    return True, "ok"


# --------------------------------------------------------------------------- #
# pydantic-ai primary loop
# --------------------------------------------------------------------------- #


def _make_http_client() -> Any:
    """httpx client with response normalization, optional proxy, optional RPM throttle.

    Some OpenAI-compatible servers (e.g. Groq) return fields that break strict
    pydantic validation in SDKs (service_tier='on_demand', x_groq={...}). We
    strip them at the transport layer so both loops tolerate any server.
    """
    import httpx

    rpm = _env("SEC_AGENT_RPM")
    min_interval = (60.0 / float(rpm) + 0.15) if rpm else 0.0
    strip_fields = {"service_tier", "x_groq", "logprobs"}

    class _NormalizeTransport(httpx.AsyncHTTPTransport):
        def __init__(self) -> None:
            super().__init__(proxy=PROXY if PROXY else None)
            self._min = min_interval
            self._last = 0.0
            self._lock = asyncio.Lock()

        async def handle_async_request(self, request: Any) -> Any:
            global REQUEST_COUNT
            if self._min:
                async with self._lock:
                    now = time.monotonic()
                    wait = self._last + self._min - now
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._last = time.monotonic()
            REQUEST_COUNT += 1
            if REQUEST_COUNT % 10 == 0:
                _log("llm_requests", n=REQUEST_COUNT)
            rpd_cap = int(_env("SEC_AGENT_RPD_CAP", "1000") or 1000)
            if REQUEST_COUNT > rpd_cap:
                raise httpx.TransportError(f"RPD cap {rpd_cap} reached")
            # transient connection failures (flaky proxy/network): bounded retry
            for attempt in range(5):
                try:
                    response = await super().handle_async_request(request)
                    break
                except (httpx.ProxyError, httpx.ConnectError, httpx.RemoteProtocolError):
                    if attempt == 4:
                        raise
                    await asyncio.sleep(2.0 * (2 ** attempt))
            content_type = response.headers.get("content-type", "")
            if "application/json" not in content_type:
                return response
            try:
                await response.aread()
                data = json.loads(response.content)
                changed = False
                if isinstance(data, dict):
                    for key in list(data.keys()):
                        if key in strip_fields:
                            data.pop(key)
                            changed = True
                if not changed:
                    return response
                new_body = json.dumps(data).encode()
                headers = httpx.Headers(response.headers)
                # Body is already decompressed by aread(); drop encoding headers so
                # httpx does not try to brotli/gzip-decode the rebuilt response.
                for drop in ("content-encoding", "content-length"):
                    try:
                        del headers[drop]
                    except Exception:
                        pass
                return httpx.Response(
                    status_code=response.status_code,
                    headers=headers,
                    content=new_body,
                    request=request,
                )
            except Exception:
                return response

    return httpx.AsyncClient(
        timeout=httpx.Timeout(120.0, connect=10.0),
        transport=_NormalizeTransport(),
    )


def _make_openai_client() -> Any:
    from openai import AsyncOpenAI

    return AsyncOpenAI(
        base_url=BASE_URL,
        api_key=API_KEY,
        max_retries=3,
        timeout=120.0,
        http_client=_make_http_client(),
    )


def _make_model() -> Any:
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    return OpenAIChatModel(MODEL_NAME, provider=OpenAIProvider(openai_client=_make_openai_client()))


def make_history_compactor(keep_last_returns: int = 3, max_return_chars: int = 1100, max_text_chars: int = 900) -> Any:
    """pydantic-ai history processor: elides older tool outputs / assistant text so
    per-request input tokens stay bounded on long tasks (ACM paper: -20% tokens)."""
    from pydantic_ai.messages import ModelRequest, ModelResponse, ToolReturnPart, TextPart

    def _shorten(content: Any, marker: str) -> str:
        text = content if isinstance(content, str) else str(content)
        return text[:max_return_chars] + marker

    def processor(messages: list) -> list:
        returns: list[tuple[int, int]] = []  # (msg_idx, part_idx)
        for i, msg in enumerate(messages):
            for j, part in enumerate(getattr(msg, "parts", []) or []):
                if isinstance(part, ToolReturnPart):
                    returns.append((i, j))
        elide = set(returns[:-keep_last_returns] if len(returns) > keep_last_returns else [])
        n_responses = sum(1 for m in messages if isinstance(m, ModelResponse))
        seen_responses = 0
        for i, msg in enumerate(messages):
            if isinstance(msg, (ModelRequest, ModelResponse)):
                parts = msg.parts
                new_parts = []
                for j, part in enumerate(parts):
                    try:
                        if isinstance(part, ToolReturnPart) and (i, j) in elide:
                            content = part.content
                            if isinstance(content, str) and len(content) > max_return_chars:
                                part.content = _shorten(
                                    content,
                                    "\n... [earlier tool output elided to preserve context; re-run the tool if needed]",
                                )
                        elif isinstance(part, TextPart) and isinstance(msg, ModelResponse):
                            seen_responses_here = seen_responses
                            if len(messages) - i > 2 and part.content and len(part.content) > max_text_chars:
                                part.content = part.content[:max_text_chars] + "\n... [earlier reasoning elided]"
                    except Exception:
                        pass
                    new_parts.append(part)
                msg.parts = new_parts
        return messages

    return processor


def _model_settings() -> Any:
    from pydantic_ai.models.openai import OpenAIChatModelSettings

    kwargs: dict[str, Any] = {"temperature": TEMPERATURE, "max_tokens": MAX_TOKENS}
    if REASONING_EFFORT:
        kwargs["openai_reasoning_effort"] = REASONING_EFFORT
    return OpenAIChatModelSettings(**kwargs)


async def run_pyai_loop(
    instruction: str,
    kind: str,
    state: AgentState,
    request_budget: int,
    baseline: str,
) -> str:
    from pydantic_ai import Agent, UsageLimits
    from pydantic_ai.models.openai import OpenAIChatModelSettings

    agent: Any = Agent(
        _make_model(),
        deps_type=AgentState,
        output_type=str,
        retries=2,
        system_prompt=build_system_prompt(kind),
        model_settings=_model_settings(),
        history_processors=[make_history_compactor()],
    )

    # Explicit signatures: pydantic-ai derives tool schemas from type hints,
    # so **kwargs wrappers are NOT viable. Closures over `state` are fine here
    # because the agent instance is created per-run.

    @agent.tool_plain(retries=2)
    async def bash(command: str) -> str:
        """Run a shell command in the workspace. Use for curl, strings, base64, git, docker, etc."""
        return await tool_bash(state, command)

    @agent.tool_plain(retries=2)
    async def read_file(path: str, start_line: int = 1, max_lines: int = 400) -> str:
        """Read a text file with line numbers. Supports start_line/max_lines for big files."""
        return await tool_read_file(state, path, start_line, max_lines)

    @agent.tool_plain(retries=2)
    async def write_file(path: str, content: str) -> str:
        """Create/overwrite a file with exact content (deliverable reports, flag files)."""
        return await tool_write_file(state, path, content)

    @agent.tool_plain(retries=2)
    async def append_file(path: str, content: str) -> str:
        """Append content to an existing file."""
        return await tool_append_file(state, path, content)

    @agent.tool_plain(retries=2)
    async def replace_in_file(path: str, old_text: str, new_text: str) -> str:
        """PREFERRED way to edit code: replace one exact old_text fragment with new_text. Copy old_text verbatim from read_file output."""
        return await tool_replace_in_file(state, path, old_text, new_text)

    @agent.tool_plain(retries=2)
    async def apply_patch(path: str, diff_content: str) -> str:
        """Apply a unified diff to a file (fallback for big multi-line edits)."""
        return await tool_apply_patch(state, path, diff_content)

    @agent.tool_plain(retries=2)
    async def list_dir(path: str = ".") -> str:
        """List files up to depth 3 with find (no sizes)."""
        return await tool_list_dir(state, path)

    @agent.tool_plain(retries=2)
    async def grep(pattern: str, path: str = ".", glob: str = "", case_insensitive: bool = False) -> str:
        """Search file contents (ripgrep/grep). Great first move: hunt sinks like execute(, eval(, subprocess, pickle.loads, jwt.decode."""
        return await tool_grep(state, pattern, path, glob, case_insensitive)

    @agent.tool_plain(retries=2)
    async def run_pytest(paths: str = "tests/") -> str:
        """Run pytest in the workspace; returns typed feedback (status, failed tests, error types)."""
        return await tool_run_pytest(state, paths)

    first = build_first_message(instruction, kind, state.workdir, baseline)
    limits = UsageLimits(request_limit=request_budget)
    result = await agent.run(first, deps=state, usage_limits=limits)
    return result.output


# --------------------------------------------------------------------------- #
# Fallback loop: raw openai SDK (used if pydantic-ai is unavailable/fails)
# --------------------------------------------------------------------------- #


async def run_openai_fallback(
    instruction: str,
    kind: str,
    state: AgentState,
    request_budget: int,
    baseline: str,
) -> str:
    client = _make_openai_client()
    tools = [
        {"type": "function", "function": {"name": name, "description": spec["description"], "parameters": spec["parameters"]}}
        for name, spec in TOOL_SPECS.items()
    ]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": build_system_prompt(kind)},
        {"role": "user", "content": build_first_message(instruction, kind, state.workdir, baseline)},
    ]
    final = ""
    for _ in range(request_budget):
        if time_left() <= 20:
            break
        response = await client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            tools=tools,
            tool_choice="auto",
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
        )
        msg = response.choices[0].message
        if msg.content:
            final = msg.content
        if not msg.tool_calls:
            break
        messages.append(
            {
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ],
            }
        )
        for tc in msg.tool_calls:
            name = tc.function.name
            try:
                kwargs = json.loads(tc.function.arguments or "{}")
            except Exception as exc:
                kwargs, parse_err = {}, f"invalid JSON args: {exc}"
            try:
                if kwargs:
                    result = await TOOL_FUNCS[name](state, **kwargs)
                else:
                    result = f"ERROR: {parse_err}"
            except Exception as exc:
                result = f"ERROR: tool raised {exc!r}"
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result[:TOOL_CHARS]})
    return final or "fallback loop ended"


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #


def run_baseline_tests() -> str:
    code, text = _run_sync_quiet(
        "python3 -m pytest tests/ -q --tb=no -p no:cacheprovider 2>&1 | tail -6"
    )
    if "error" in text.lower() and "no tests ran" in text.lower():
        return ""
    return text if ("passed" in text or "failed" in text or "error" in text.lower()) else ""


async def classify_with_llm(instruction: str) -> str:
    """One tiny request when mechanical classification is 'generic'."""
    try:
        client = _make_openai_client()
        response = await client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "Classify the task. Reply with EXACTLY one word: audit|fix|forensics|ctf|generic"},
                {"role": "user", "content": instruction[:3000]},
            ],
            temperature=0.0,
            max_tokens=8,
        )
        word = (response.choices[0].message.content or "").strip().lower()
        for cand in ("audit", "fix", "forensics", "ctf", "generic"):
            if cand in word:
                return cand
    except Exception as exc:
        _log("classify_llm_failed", error=repr(exc))
    return "generic"


async def ensure_deliverable(instruction: str, kind: str, state: AgentState, deliverable: str, budget_left: int) -> bool:
    ok, reason = verify_deliverable(kind, deliverable, state.workdir)
    if ok:
        return True
    if budget_left <= 0 or time_left() <= 30:
        return False
    _log("repair_needed", reason=reason)
    repair_instruction = (
        REPAIR_PROMPT.format(reason=reason)
        + f"\nDeliverable path: {deliverable}\n\nTASK INSTRUCTION (for reference):\n{instruction[:4000]}"
    )
    try:
        await run_pyai_loop(repair_instruction, kind, state, min(6, budget_left), "")
    except Exception as exc:
        _log("repair_loop_failed", error=repr(exc))
        try:
            await run_openai_fallback(repair_instruction, kind, state, min(4, budget_left), "")
        except Exception as exc2:
            _log("repair_fallback_failed", error=repr(exc2))
    ok, _ = verify_deliverable(kind, deliverable, state.workdir)
    return ok


def _rate_limit_wait(exc: Exception) -> float | None:
    """Parse Groq/OpenAI 'Please try again in Xs' hints from 429 bodies."""
    text = repr(exc)
    m = re.search(r"try again in ([\d.]+)(min|s| seconds?| minutes?)", text)
    if not m:
        return None
    value = float(m.group(1))
    unit = m.group(2)
    if "min" in unit:
        return value * 60.0
    return value


def _is_daily_cap(exc: Exception) -> bool:
    """TPD/RPD exhaustion: waiting inside the run is pointless - fail fast so the harness can switch API keys."""
    text = repr(exc)
    return ("per day" in text or "TPD" in text or "daily" in text
            or "requests per day" in text or "RPD" in text)


async def main_async(instruction: str) -> str:
    state = AgentState(workdir=_resolve_workdir())
    _log("start", model=MODEL_NAME, workdir=str(state.workdir))

    # 0) trivial fast path: zero LLM requests
    trivial = detect_trivial(instruction)
    if trivial:
        path, content = trivial
        fp = Path(path) if Path(path).is_absolute() else state.workdir / path
        fp = remap_path(fp)
        try:
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
        except Exception as exc:
            _log("fastpath_failed", error=repr(exc), note="falling back to LLM flow")
        else:
            _log("fastpath", path=str(fp))
            return f"Fast-path: wrote {fp} with exact content."

    # 1) classification (mechanical -> LLM fallback)
    kind = classify_mechanical(instruction)
    requests_used = 0
    if kind == "generic":
        kind2 = await classify_with_llm(instruction)
        if kind2 != "generic":
            kind = kind2
            requests_used += 1
    deliverable = guess_deliverable(instruction, kind, state.workdir)
    _log("classified", kind=kind, deliverable=deliverable)

    # 2) baseline tests for fix-type tasks (mechanical, free)
    baseline = run_baseline_tests() if kind == "fix" else ""

    # 3) main loop (per-minute rate limits get patient retry; daily caps fail fast;
    #    other errors -> fallback loop)
    budget_main = MAX_REQUESTS - requests_used
    final = ""
    for attempt in range(3):
        try:
            final = await run_pyai_loop(instruction, kind, state, budget_main, baseline)
            break
        except Exception as exc:
            _log("primary_loop_failed", error=repr(exc), attempt=attempt)
            if "UsageLimitExceeded" in repr(exc) or "request_limit" in repr(exc):
                _log("budget_exhausted", note="normal completion; proceeding to verification/repair")
                break
            if _is_daily_cap(exc):
                _log("daily_cap_hit", note="fail fast; switch API key to continue")
                break
            conn_error = ("Connection error" in repr(exc) or "ProxyError" in repr(exc)
                          or "ConnectError" in repr(exc))
            if conn_error and time_left() > 120:
                _log("conn_error_backoff", note="flaky network/proxy; waiting 60s")
                await asyncio.sleep(60)
                continue
            if "RateLimit" in repr(exc) or "429" in repr(exc):
                wait = _rate_limit_wait(exc) or 65.0
                if time_left() > wait + 60:
                    await asyncio.sleep(min(wait + 5.0, 90.0))
                    continue
            try:
                final = await run_openai_fallback(instruction, kind, state, min(budget_main, 30), baseline)
            except Exception as exc2:
                _log("fallback_loop_failed", error=repr(exc2))
                final = final or f"agent failed: {exc2!r}"
            break

    # 4) mechanical verification + repair
    remaining = MAX_REQUESTS - requests_used
    await ensure_deliverable(instruction, kind, state, deliverable, remaining)

    _log("done", kind=kind, tool_calls=state.tool_calls, wall_s=round(time.monotonic() - START, 1))
    return final or "finished"


def main() -> None:
    _setup_logging()
    instruction = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else _env("SEC_AGENT_INSTRUCTION", "") or ""
    if not instruction.strip():
        print("Usage: sec_agent.py \"<instruction>\"")
        sys.exit(2)
    try:
        final = asyncio.run(asyncio.wait_for(main_async(instruction), timeout=max(TIME_BUDGET, 30)))
    except asyncio.TimeoutError:
        final = "time budget exhausted; deliverable left as-is"
    except Exception as exc:
        _log("fatal", error=repr(exc))
        final = f"fatal: {exc!r}"
    print(final)


if __name__ == "__main__":
    main()
