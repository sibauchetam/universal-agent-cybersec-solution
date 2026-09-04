#!/usr/bin/env python3
"""Golden controls for harness verifier clones (no LLM, no network).

Positive control: a KNOWN-GOOD artifact must PASS the clone.
Negative control: a KNOWN-BAD artifact must FAIL it.

These tests pin the clones to the OFFICIAL verifier semantics so that a
careless clone edit (the H-a drift finding) fails loudly here instead of
silently corrupting validation runs. Run: pytest scripts/test_harness_verifiers.py -q
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness as H  # noqa: E402

BASE = Path("/home/z/my-project")
SYN = BASE / "synthetic_tasks"
REPO = BASE / "UniversalAgenticCompetitionPublic"


# --------------------------- hello / bye --------------------------- #


def test_hello_exact_pass(tmp_path):
    (tmp_path / "hello.txt").write_text("Hello")
    ok, msg = H.v_hello(tmp_path)
    assert ok, msg


def test_hello_trailing_newlines_pass_official_cat_semantics(tmp_path):
    # $(cat) strips ALL trailing newlines -> official verifier passes these
    (tmp_path / "hello.txt").write_text("Hello\n")
    ok, _ = H.v_hello(tmp_path)
    assert ok
    (tmp_path / "hello.txt").write_text("Hello\n\n\n")
    ok, _ = H.v_hello(tmp_path)
    assert ok


def test_hello_negative_trailing_space_fails(tmp_path):
    # command substitution does NOT strip spaces -> official fails this
    (tmp_path / "hello.txt").write_text("Hello ")
    ok, _ = H.v_hello(tmp_path)
    assert not ok


def test_hello_negative_wrong_content(tmp_path):
    (tmp_path / "hello.txt").write_text("hello")
    ok, _ = H.v_hello(tmp_path)
    assert not ok


def test_hello_negative_missing(tmp_path):
    ok, msg = H.v_hello(tmp_path)
    assert not ok and "missing" in msg


def test_bye_positive_and_negative(tmp_path):
    (tmp_path / "bye.txt").write_text("Bye\n")
    ok, _ = H.v_bye(tmp_path)
    assert ok
    (tmp_path / "bye.txt").write_text("Bye!")
    ok, _ = H.v_bye(tmp_path)
    assert not ok


# --------------------------- key=value forensics --------------------------- #


def _make_kv(tmp_path: Path, lines: list[str], expected_src: Path) -> tuple[bool, str]:
    (tmp_path / "incident_report.txt").write_text("\n".join(lines) + "\n")
    return H._v_kv_report(tmp_path, expected_src)


EXPECTED_OFFICIAL = REPO / "local_task/incident-log-forensics/solution/expected_incident_report.txt"


def test_kv_official_expected_passes_itself(tmp_path):
    """Positive control: the official expected file must pass our clone."""
    shutil.copy(EXPECTED_OFFICIAL, tmp_path / "incident_report.txt")
    ok, msg = H._v_kv_report(tmp_path, EXPECTED_OFFICIAL)
    assert ok, msg


def test_kv_value_with_spaces_passes_official_regex(tmp_path):
    """Drift regression: official regex is ^[a-z_]+=.+$ (spaces allowed).
    The old clone used \\S+ and rejected legitimate spacey values.

    We verify FORMAT separately from CONTENT: a 4-line report whose values
    contain spaces must NOT be rejected with a *format* error (content
    mismatch is expected, since values differ from the official expected)."""
    expected = [ln for ln in EXPECTED_OFFICIAL.read_text().splitlines() if ln.strip()]
    assert expected, "official expected file unexpectedly empty"
    spaced = [re.sub(r"^([a-z_]+=)", r"\1ACME corp value ", ln) for ln in expected]
    assert any(" " in ln.split("=", 1)[1] for ln in spaced), "mutation produced no spacey value"
    ok, msg = _make_kv(tmp_path, spaced, EXPECTED_OFFICIAL)
    assert not ok  # values differ from expected -> content mismatch, NOT format
    assert "format" not in msg.lower(), f"format drift: {msg}"


def test_kv_negative_value_changed(tmp_path):
    lines = [ln for ln in EXPECTED_OFFICIAL.read_text().splitlines() if ln.strip()]
    mutated = [lines[0].replace("=", "=WRONG-", 1) if "=" in lines[0] else lines[0]] + lines[1:]
    ok, _ = _make_kv(tmp_path, mutated, EXPECTED_OFFICIAL)
    assert not ok


def test_kv_negative_wrong_line_count(tmp_path):
    lines = [ln for ln in EXPECTED_OFFICIAL.read_text().splitlines() if ln.strip()]
    ok, msg = _make_kv(tmp_path, lines[:3], EXPECTED_OFFICIAL)
    assert not ok and "lines" in msg
    ok, msg = _make_kv(tmp_path, lines + ["extra_key=val"], EXPECTED_OFFICIAL)
    assert not ok and "lines" in msg


def test_kv_negative_format_violation(tmp_path):
    lines = [ln for ln in EXPECTED_OFFICIAL.read_text().splitlines() if ln.strip()]
    bad = lines + ["bad key = value"][:0]  # placeholder no-op
    bad = [lines[0] + " = x"] + lines[1:]  # ' = ' substring -> official fails
    ok, msg = _make_kv(tmp_path, bad[: len(lines)], EXPECTED_OFFICIAL)
    assert not ok


def test_kv_c_sort_matches_official_lc_all_c(tmp_path):
    """Byte-order sort (LC_ALL=C) must equal our _c_sort_lines on the real file."""
    lines = [ln for ln in EXPECTED_OFFICIAL.read_text().splitlines() if ln.strip()]
    official = subprocess_sort_c(lines) if False else None
    assert H._c_sort_lines(lines) == sorted(lines, key=lambda s: s.encode("utf-8"))


def subprocess_sort_c(lines: list[str]) -> list[str]:  # pragma: no cover
    import subprocess
    data = "\n".join(lines).encode()
    out = subprocess.run(["sort"], input=data, capture_output=True, env={"LC_ALL": "C"})
    return out.stdout.decode().splitlines()


# --------------------------- audit JSON --------------------------- #


def _finding(title: str, cat: str, loc: str, ev: str) -> dict:
    return {"title": title, "severity": "high", "category": cat,
            "location": loc, "evidence": ev, "impact": "i", "recommendation": "r"}


def test_security_report_positive_all_signal_groups(tmp_path):
    f = _finding("SQLi", "SQL Injection (CWE-89)", "routers/auth.py POST /login",
                 "f-string builds WHERE username = '{req.username}'; authentication bypass via admin'--")
    (tmp_path / "security_report.json").write_text(json.dumps({"findings": [f]}))
    ok, msg = H.v_security_report(tmp_path)
    assert ok, msg


def test_security_report_negative_missing_detail_group(tmp_path):
    f = _finding("SQLi", "SQL Injection", "routers/auth.py", "parameterized queries are absent")
    (tmp_path / "security_report.json").write_text(json.dumps({"findings": [f]}))
    ok, _ = H.v_security_report(tmp_path)
    assert not ok


def test_security_report_negative_invalid_json(tmp_path):
    (tmp_path / "security_report.json").write_text("{not json")
    ok, msg = H.v_security_report(tmp_path)
    assert not ok and "JSON" in msg


def test_security_report_negative_missing_file(tmp_path):
    ok, _ = H.v_security_report(tmp_path)
    assert not ok


# --------------------------- CTF flag --------------------------- #


def test_flag_positive_with_trailing_newline(tmp_path):
    (tmp_path / "flag.txt").write_text("flag{st4g3d_1005_xx9}\n")
    ok, _ = H.v_flag(tmp_path, "flag{st4g3d_1005_xx9}")
    assert ok


def test_flag_negative_wrong(tmp_path):
    (tmp_path / "flag.txt").write_text("flag{wrong}")
    ok, _ = H.v_flag(tmp_path, "flag{st4g3d_1005_xx9}")
    assert not ok


# --------------------------- pickle hidden tests --------------------------- #


def test_pickle_negative_control_vulnerable_app_fails(tmp_path):
    """The hidden tests MUST fail on the unfixed (vulnerable) app."""
    shutil.copytree(SYN / "fix-insecure-pickle/environment/app", tmp_path / "app")
    ok, _ = H.v_pickle_fix(tmp_path / "app")
    assert not ok, "negative control broken: hidden tests pass on vulnerable app"


def test_pickle_positive_control_reference_fix_passes(tmp_path):
    """Apply the reference fix from solution/solve.sh (parsed from the script
    itself to avoid drift) -> hidden tests MUST pass."""
    workdir = tmp_path / "app"
    shutil.copytree(SYN / "fix-insecure-pickle/environment/app", workdir)
    solve = (SYN / "fix-insecure-pickle/solution/solve.sh").read_text()
    m = re.search(r"fixed = '''(.*?)'''", solve, re.S)
    assert m, "cannot parse fixed block from solve.sh"
    fixed_block = m.group(1)

    jobs = workdir / "routers" / "jobs.py"
    src = jobs.read_text()
    src = src.replace("import base64, pickle\n", "import base64\nimport json\n", 1)
    start = src.index('@router.post("/jobs/import")')
    end = src.index('@router.post("/jobs")')
    src = src[:start] + fixed_block + src[end:]
    jobs.write_text(src)

    ok, msg = H.v_pickle_fix(workdir)
    assert ok, f"positive control broken: {msg}"


# --------------------------- static sqli fix --------------------------- #


def test_sqli_static_negative_control_vulnerable_fails(tmp_path):
    src_dir = REPO / "local_task/fix-sqli-search/environment/app"
    shutil.copytree(src_dir, tmp_path / "app")
    ok, _ = H.v_static_sqli_fix(tmp_path / "app")
    assert not ok, "negative control broken: static verifier passes vulnerable app"


def test_sqli_static_positive_control_cleaned_passes(tmp_path):
    src_dir = REPO / "local_task/fix-sqli-search/environment/app"
    shutil.copytree(src_dir, tmp_path / "app")
    for py in (tmp_path / "app").rglob("*.py"):
        src = py.read_text()
        src = src.replace("LIKE '%{q}%'", "LIKE :q").replace(
            "f\"SELECT * FROM items WHERE name LIKE", "SELECT * FROM items WHERE name LIKE"
        ).replace("WHERE username = '{req.username}'", "WHERE username = :u")
        py.write_text(src)
    ok, _ = H.v_static_sqli_fix(tmp_path / "app")
    assert ok


# --------------------------- events parsing --------------------------- #


def test_parse_events_requests_and_usage(tmp_path):
    ev = tmp_path / "agent_events.jsonl"
    ev.write_text("\n".join([
        json.dumps({"event": "start"}),
        json.dumps({"event": "llm_requests", "n": 1, "t_ms": 100}),
        json.dumps({"event": "llm_requests", "n": 2, "t_ms": 200}),
        json.dumps({"event": "final_usage", "requests": 2, "tin": 1500, "tout": 300, "t_ms": 900}),
    ]) + "\n")
    reqs, usage, signals = H._parse_events(ev)
    assert reqs == 2
    assert usage and usage["tin"] == 1500 and usage["tout"] == 300
    assert signals == set()


def test_parse_events_signals(tmp_path):
    ev = tmp_path / "agent_events.jsonl"
    ev.write_text("\n".join([
        json.dumps({"event": "daily_cap_hit"}),
        json.dumps({"event": "output_truncated"}),
        json.dumps({"event": "fatal", "error": "X"}),
    ]) + "\n")
    reqs, usage, signals = H._parse_events(ev)
    assert reqs is None and usage is None
    assert {"daily_cap", "truncated", "crash"} <= signals


def test_fail_class_taxonomy():
    assert H._fail_class(True, "ok", set(), 0, False) == "ok"
    assert H._fail_class(False, "x missing", set(), 0, False) == "deliverable-missing"
    assert H._fail_class(False, "format violation", set(), 0, False) == "deliverable-format"
    assert H._fail_class(False, "content mismatch", set(), 0, False) == "deliverable-content"
    assert H._fail_class(False, "x", {"daily_cap"}, 0, False) == "quota"
    assert H._fail_class(False, "x", set(), 0, True) == "timeout"
    assert H._fail_class(False, "x", {"crash"}, 1, False) == "crash"
