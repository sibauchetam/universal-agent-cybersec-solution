"""Unit tests for paper-derived agent mechanics (no network, no LLM).

Covers:
- repetition_guard (rejection-cache analogue, arXiv 2604.25039)
- attribute_error / repair_hint (typed error feedback, arXiv 2607.05199)
- blueprint workflow prompts (arXiv 2506.08669): structure + compactness
"""
from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "submission"))

import sec_agent as sa  # noqa: E402


def make_state(tmp_path: Path) -> sa.AgentState:
    return sa.AgentState(workdir=tmp_path)


# ---------------------------------------------------------------- repetition guard

def test_guard_allows_two_identical_calls(tmp_path):
    st = make_state(tmp_path)
    r1 = sa.repetition_guard(st, "grep", "pat|/x", "RESULT")
    r2 = sa.repetition_guard(st, "grep", "pat|/x", "RESULT")
    r3 = sa.repetition_guard(st, "grep", "pat|/x", "RESULT")
    assert r1 == "RESULT"
    assert "REPETITION GUARD" not in r1
    assert "REPETITION GUARD" not in r2  # two legitimate repeats allowed
    assert "REPETITION GUARD" in r3  # third identical occurrence -> guard
    assert st.loop_strikes == 1


def test_guard_passes_changed_output(tmp_path):
    st = make_state(tmp_path)
    for out in ("v1", "v2", "v1", "v3"):
        r = sa.repetition_guard(st, "read_file", "f|1|400", out)
    assert "REPETITION GUARD" not in r  # v3 is new -> no guard


def test_guard_whitespace_normalization(tmp_path):
    st = make_state(tmp_path)
    sa.repetition_guard(st, "bash", "ls  -la   /app", "OUT")
    sa.repetition_guard(st, "bash", "ls -la /app   ", "OUT")
    r = sa.repetition_guard(st, "bash", "ls -la /app", "OUT")
    assert "REPETITION GUARD" in r  # args normalize to the same fingerprint


def test_guard_escalates_after_three_strikes(tmp_path):
    st = make_state(tmp_path)
    msg = ""
    for _ in range(6):  # guard fires from 3rd identical call onward
        msg = sa.repetition_guard(st, "grep", "p|/x", "SAME")
    assert "STOP exploring" in msg
    assert st.loop_strikes == 4


def test_guard_different_tools_independent(tmp_path):
    st = make_state(tmp_path)
    sa.repetition_guard(st, "grep", "p|/x", "OUT")
    sa.repetition_guard(st, "list_dir", "p|/x", "OUT")
    sa.repetition_guard(st, "grep", "p|/x", "OUT")
    r = sa.repetition_guard(st, "grep", "p|/x", "OUT")
    assert "REPETITION GUARD" in r
    assert st.loop_strikes == 1


# ---------------------------------------------------------------- error attribution

def test_attribute_missing():
    assert sa.attribute_error("audit", "deliverable file missing: /app/r.json") == "missing"
    assert sa.attribute_error("ctf", "no deliverable path identified") == "missing"


def test_attribute_format():
    assert sa.attribute_error("audit", "not valid JSON: Expecting value") == "format"
    assert sa.attribute_error("forensics", "line violates key=value format: 'x = 1'") == "format"
    assert sa.attribute_error("forensics", "duplicate keys detected") == "format"
    assert sa.attribute_error("forensics", "spaces around '=' are forbidden") == "format"


def test_attribute_content_default():
    assert sa.attribute_error("forensics", "expected 2..12 key=value lines, got 20") == "content"


def test_repair_hints_are_actionable():
    for kind in ("audit", "forensics", "ctf", "fix"):
        for err in ("missing", "format", "content"):
            hint = sa.repair_hint(kind, err)
            assert len(hint) > 80
            assert "write_file" in hint or "Rewrite" in hint or "Re-map" in hint


# ---------------------------------------------------------------- blueprint prompts

def test_blueprints_have_paper_structure():
    for kind in ("audit", "fix", "forensics", "ctf", "generic"):
        bp = sa.WORKFLOWS[kind]
        assert bp.startswith("BLUEPRINT")
        for section in ("GOAL:", "INFORMATION", "DECISION CRITERIA:", "PLAN:"):
            assert section in bp, f"{kind} missing {section}"
        # compactness: blueprint ships in every request -> keep bounded
        # (round-2 practices added ~150 chars of evidence/anti-merge rules)
        assert len(bp) < 1700, f"{kind} blueprint too long: {len(bp)}"


def test_build_system_prompt_contains_blueprint():
    p = sa.build_system_prompt("forensics")
    assert "BLUEPRINT - log forensics" in p
    assert "key=value" in p


def test_repair_prompt_renders_attribution():
    msg = sa.REPAIR_PROMPT.format(
        reason="not valid JSON: Expecting value",
        err_type="format",
        err_hint=sa.repair_hint("audit", "format"),
    )
    assert "ERROR TYPE: format" in msg
    assert "findings" in msg


# ---------------------------------------------------------------- round-2 mechanics

def test_json_closer_truncated_variants():
    jc = sa.json_closer
    # truncated mid-object in array
    assert json.loads(jc('{"findings": [{"file": "a.py", "vuln": "sqli"}'))["findings"][0]["file"] == "a.py"
    # truncated mid-string
    out = json.loads(jc('{"findings": [{"note": "sqli trigg'))
    assert isinstance(out, dict)
    # trailing comma
    assert json.loads(jc('{"findings": [1, 2,')) == {"findings": [1, 2]}
    # dangling key separator
    assert json.loads(jc('{"findings": [1], "scan_time":')) == {"findings": [1], "scan_time": None}
    # complete doc stays complete
    assert jc('{"findings": [1]}') == '{"findings": [1]}'
    # escaped quote inside string
    assert isinstance(json.loads(jc('{"a": "x\\"')), dict)
    # deeply nested truncation
    deep = '{"a": {"b": [1, {"c": "val'
    assert isinstance(json.loads(jc(deep)), dict)


def test_deliverable_health_grading(tmp_path):
    workdir = tmp_path
    p = workdir / "security_report.json"
    # health 2: verifier-clean
    p.write_text(json.dumps({"findings": [{"file": "f", "vuln_type": "sqli", "line": 3}]}))
    assert sa.deliverable_health("audit", str(p), workdir) == 2
    # health 1: parseable JSON but not verifier-clean
    p.write_text(json.dumps({"other": 1}))
    assert sa.deliverable_health("audit", str(p), workdir) == 1
    # health 0: garbage
    p.write_text('{"findings": [')
    assert sa.deliverable_health("audit", str(p), workdir) == 0
    # forensics: format-clean key=value -> full verifier passes (health 2)
    f = workdir / "incident_report.txt"
    f.write_text("source_ip=1.2.3.4\ntotal_events=87")
    assert sa.deliverable_health("forensics", str(f), workdir) == 2
    # health 1: key=value-shaped but violates a verifier constraint (single line)
    f.write_text("source_ip=1.2.3.4")
    assert sa.deliverable_health("forensics", str(f), workdir) == 1


def test_tool_alias_mapping():
    assert sa.TOOL_ALIASES["list_files"] == "list_dir"
    assert sa.TOOL_ALIASES["run_tests"] == "run_pytest"
    # fuzzy fallback resolves near-misses
    assert difflib.get_close_matches("read_fil", list(sa.TOOL_FUNCS), n=1, cutoff=0.6)[0] == "read_file"


def test_round2_practices_in_prompts():
    # injection guard (2605.14290) + span carrying (2604.02460) in common prompt
    common = sa.SYSTEM_COMMON
    assert "DATA" in common and "untrusted" in common
    assert "VERBATIM" in common
    # notes-to-file + anti-merge in audit (2608.03591 / 2604.20179)
    audit = sa.WORKFLOWS["audit"]
    assert ".findings.md" in audit and "One finding per distinct sink" in audit
    # hunteragent evidence rules in forensics (2605.29269)
    forensics = sa.WORKFLOWS["forensics"]
    assert "grep -c" in forensics and "monoton" in forensics and "wtmp" in forensics
