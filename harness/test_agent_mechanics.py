"""Unit tests for paper-derived agent mechanics (no network, no LLM).

Covers:
- repetition_guard (rejection-cache analogue, arXiv 2604.25039)
- attribute_error / repair_hint (typed error feedback, arXiv 2607.05199)
- blueprint workflow prompts (arXiv 2506.08669): structure + compactness
"""
from __future__ import annotations

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
        assert len(bp) < 1600, f"{kind} blueprint too long: {len(bp)}"


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
