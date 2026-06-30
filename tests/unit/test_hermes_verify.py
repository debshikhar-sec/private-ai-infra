"""Tests for the Hermes verification step — the closed assurance loop.

These exercise the seam where Hermes (orchestrator) invokes OpenClaw (verifier) and
folds the verdict into memory, so the next planning cycle plans from verified state.
Pure-stdlib and offline: evidence is read from temp files, no gateway involved.
"""

from __future__ import annotations

import json

from hermes import planner, verify
from hermes.store import MemoryStore

_CLEAN_AUDIT = (
    '{"ts":"t","request_id":"r1","principal":"analyst","method":"POST",'
    '"path":"/v1/chat/completions","model":"strategy","decision":"allow",'
    '"reason":"ok","status":200}\n'
    '{"ts":"t","request_id":"r2","principal":"hermes","method":"POST",'
    '"path":"/v1/chat/completions","model":"strategy","decision":"deny",'
    '"reason":"autonomy_exceeded: L3>L1","status":403}\n'
)
_TAMPERED_AUDIT = (
    '{"ts":"t","request_id":"x1","principal":"hermes","method":"POST",'
    '"path":"/v1/chat/completions","model":"strategy","decision":"allow",'
    '"reason":"autonomy_exceeded leaked","status":200}\n'
)


def _audit(tmp_path, body) -> str:
    p = tmp_path / "decisions.jsonl"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_gather_and_record_pass_writes_proceed_gate(tmp_path):
    mem = tmp_path / "mem"
    record = verify.gather_and_record(memory_dir=mem, audit=_audit(tmp_path, _CLEAN_AUDIT))
    assert record["verdict"] == "PASS"
    state = MemoryStore(mem).load_state()
    assert state["assurance"]["verdict"] == "PASS"
    assert state["current_gate"] == "assurance PASS"


def test_gather_and_record_fail_gates_next_plan(tmp_path):
    mem = tmp_path / "mem"
    record = verify.gather_and_record(memory_dir=mem, audit=_audit(tmp_path, _TAMPERED_AUDIT))
    assert record["verdict"] == "FAIL"
    # The closed loop: the failing control now appears in Hermes' next planning prompt.
    state = MemoryStore(mem).load_state()
    digest = planner.summarize_state(state)
    assert "Last assurance verification (OpenClaw): FAIL" in digest
    assert "AC-AUTONOMY-CEILING" in digest


def test_main_exit_zero_on_pass(tmp_path, capsys):
    mem = tmp_path / "mem"
    code = verify.main(["--memory-dir", str(mem), "--audit", _audit(tmp_path, _CLEAN_AUDIT)])
    assert code == 0
    assert "assurance PASS" in capsys.readouterr().out


def test_main_exit_one_on_fail(tmp_path, capsys):
    mem = tmp_path / "mem"
    code = verify.main(["--memory-dir", str(mem), "--audit", _audit(tmp_path, _TAMPERED_AUDIT)])
    assert code == 1
    err = capsys.readouterr().err
    assert "gated on remediating" in err


def test_gather_and_record_cross_checks_policy_and_isolation(tmp_path):
    # A full pass with policy + an isolation report should still record cleanly.
    policy = tmp_path / "policy.toml"
    policy.write_text(
        '[[principals]]\nname = "analyst"\nallowed_models = ["strategy"]\n'
        '[[principals]]\nname = "hermes"\nallowed_models = ["strategy"]\n',
        encoding="utf-8",
    )
    iso = tmp_path / "iso.txt"
    iso.write_text(
        "ISOLATION_RESULT=PASS\nSECRET_SCAN_RESULT=PASS_NO_FATAL_HITS\nOPENCODE_EXIT=0\n",
        encoding="utf-8",
    )
    record = verify.gather_and_record(
        memory_dir=tmp_path / "mem",
        audit=_audit(tmp_path, _CLEAN_AUDIT),
        policy=str(policy),
        opencode_report=str(iso),
    )
    assert record["verdict"] == "PASS"
    assert "AC-AUTHZ-MODEL" in record["passed_controls"]
    assert "AC-OPENCODE-ISOLATION" in record["passed_controls"]


def _eval_report(tmp_path, verdict, *, passed, failed, probes=()):
    results = [
        {"id": pid, "owasp": "LLM06", "attack": atk, "status": "fail"}
        for pid, atk in probes
    ]
    p = tmp_path / "evals.json"
    p.write_text(
        '{"component":"security-evals","generated_at":"t","verdict":"%s",'
        '"counts":{"pass":%d,"fail":%d,"skip":0},"results":%s}'
        % (verdict, passed, failed, json.dumps(results)),
        encoding="utf-8",
    )
    return str(p)


def test_passing_eval_report_records_as_passed_control(tmp_path):
    record = verify.gather_and_record(
        memory_dir=tmp_path / "mem",
        audit=_audit(tmp_path, _CLEAN_AUDIT),
        eval_report=_eval_report(tmp_path, "PASS", passed=12, failed=0),
    )
    assert record["verdict"] == "PASS"
    assert "AC-SECURITY-EVALS" in record["passed_controls"]


def test_failing_eval_report_gates_next_plan(tmp_path):
    # The whole point: a control that let an attack through in the eval suite must
    # become a failing assurance control and gate Hermes' next planning cycle.
    mem = tmp_path / "mem"
    record = verify.gather_and_record(
        memory_dir=mem,
        audit=_audit(tmp_path, _CLEAN_AUDIT),
        eval_report=_eval_report(
            tmp_path, "FAIL", passed=11, failed=1,
            probes=[("AUTONOMY-004", "header L1 + body L6")],
        ),
    )
    assert record["verdict"] == "FAIL"
    assert any(c["control_id"] == "AC-SECURITY-EVALS" for c in record["failed_controls"])
    digest = planner.summarize_state(MemoryStore(mem).load_state())
    assert "AC-SECURITY-EVALS" in digest


def _apply_report(tmp_path, payload):
    p = tmp_path / "apply.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return str(p)


def test_passing_apply_report_records_as_passed_control(tmp_path):
    record = verify.gather_and_record(
        memory_dir=tmp_path / "mem",
        audit=_audit(tmp_path, _CLEAN_AUDIT),
        apply_report=_apply_report(
            tmp_path,
            {"status": "applied", "approver": "alice", "committed": True,
             "declared_files": ["a.py"], "changed_files": ["a.py"]},
        ),
    )
    assert record["verdict"] == "PASS"
    assert "AC-APPLY-INTEGRITY" in record["passed_controls"]


def test_ungated_apply_report_gates_next_plan(tmp_path):
    # An apply that mutated the tree with no recorded approver is an authority bypass:
    # it must become a failing assurance control and gate Hermes' next plan.
    mem = tmp_path / "mem"
    record = verify.gather_and_record(
        memory_dir=mem,
        audit=_audit(tmp_path, _CLEAN_AUDIT),
        apply_report=_apply_report(
            tmp_path,
            {"status": "applied", "approver": None, "committed": True,
             "declared_files": ["a.py"], "changed_files": ["a.py"]},
        ),
    )
    assert record["verdict"] == "FAIL"
    assert any(c["control_id"] == "AC-APPLY-INTEGRITY" for c in record["failed_controls"])
    digest = planner.summarize_state(MemoryStore(mem).load_state())
    assert "AC-APPLY-INTEGRITY" in digest
