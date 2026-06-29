"""Tests for the OpenClaw assurance report."""

from __future__ import annotations

import json

from openclaw.checks import FAIL, INCONCLUSIVE, PASS, Finding
from openclaw.report import VERDICT_FAIL, VERDICT_PASS, build_report


def _f(status, cid="AC-X") -> Finding:
    return Finding(cid, "title", status, "info", "detail")


def test_verdict_pass_when_no_failures():
    report = build_report([_f(PASS), _f(INCONCLUSIVE, "AC-Y")])
    assert report.verdict == VERDICT_PASS
    assert report.exit_code() == 0


def test_verdict_fail_when_any_failure():
    report = build_report([_f(PASS), _f(FAIL, "AC-Y")])
    assert report.verdict == VERDICT_FAIL
    assert report.exit_code() == 1


def test_counts():
    report = build_report([_f(PASS), _f(PASS, "AC-Y"), _f(FAIL, "AC-Z"), _f(INCONCLUSIVE, "AC-W")])
    assert report.counts() == {PASS: 2, FAIL: 1, INCONCLUSIVE: 1}


def test_to_json_is_valid_and_has_verdict():
    report = build_report([_f(PASS)])
    data = json.loads(report.to_json())
    assert data["verdict"] == VERDICT_PASS
    assert data["component"] == "openclaw"
    assert data["counts"][PASS] == 1
    assert data["findings"][0]["control_id"] == "AC-X"


def test_to_markdown_escapes_pipes_and_newlines():
    f = Finding("AC-X", "t", FAIL, "high", "line one | with pipe\nand newline")
    md = build_report([f]).to_markdown()
    assert "FAIL" in md
    # the detail cell must not contain a raw pipe or newline that breaks the table
    row = [ln for ln in md.splitlines() if "AC-X" in ln][0]
    assert "\\|" in row
    assert "\n" not in row


def test_to_text_includes_evidence():
    f = Finding("AC-X", "t", PASS, "info", "ok", evidence=["audit.jsonl"])
    text = build_report([f]).to_text()
    assert "evidence: audit.jsonl" in text
    assert "AC-X" in text


def test_to_memory_record_partitions_controls_by_status():
    report = build_report(
        [
            Finding("AC-PASS", "ok", PASS, "info", "fine"),
            Finding("AC-FAIL", "bad", FAIL, "high", "broke"),
            Finding("AC-INC", "unknown", INCONCLUSIVE, "info", "no evidence"),
        ]
    )
    rec = report.to_memory_record()
    assert rec["verdict"] == VERDICT_FAIL
    assert rec["passed_controls"] == ["AC-PASS"]
    assert rec["inconclusive_controls"] == ["AC-INC"]
    assert [c["control_id"] for c in rec["failed_controls"]] == ["AC-FAIL"]
    # failed controls carry enough detail for the consumer to act on
    assert rec["failed_controls"][0]["title"] == "bad"
    assert rec["failed_controls"][0]["severity"] == "high"
    assert rec["counts"] == {PASS: 1, FAIL: 1, INCONCLUSIVE: 1}


def test_to_memory_record_is_json_serializable():
    rec = build_report([_f(PASS)]).to_memory_record()
    assert json.loads(json.dumps(rec))["verdict"] == VERDICT_PASS
