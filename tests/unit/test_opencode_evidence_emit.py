"""Evidence-sink design step 3: OpenCode executor emits a signed ``apply_result`` record.

These tests pin the executor-emit contract in-process, against a real
:class:`openclaw.sink.EvidenceSink` with an ephemeral in-test HMAC key (no key material in
the repo, no disk/env loading). They prove: after a successful apply the executor pushes one
signed, chained ``apply_result`` record; ``run_id``/``approval_id`` bind at the envelope
(not the payload); the sink validates authorship before appending; and every structural
failure raises :class:`EvidenceError` (fail-closed, never swallowed). A minimal worker-wiring
test confirms the additive injection: no sink → unchanged behavior; injected sink → emit
after the (still-written) ``apply_report.json``.
"""

import json

import pytest
from openclaw import sink as sinkmod
from opencode_sandbox import apply as act
from opencode_sandbox import evidence_emit
from opencode_sandbox.apply import APPLIED, ApplyReport

# Ephemeral, in-test key material only — never loaded from disk/env, never committed.
_KEY = b"opencode-emit-key-0123456789abcd"  # 32 bytes
_KEY2 = b"a-different-opencode-key-abcdef01"
_SINK_ID = "sink-exec-1"
_KEY_ID = "opencode-hmac-1"


def _report(**over):
    fields = dict(
        status=APPLIED,
        autonomy_level=3,
        declared_files=["a.py"],
        changed_files=["a.py"],
        approver="owner",
        committed=False,
        detail="applied and verified in sandbox",
    )
    fields.update(over)
    return ApplyReport(**fields)


def _sink(key=_KEY, key_id=_KEY_ID, sink_id=_SINK_ID):
    reg = sinkmod.EmitterKeyRegistry()
    reg.register(sinkmod.EMITTER_OPENCODE, key_id, key)
    return sinkmod.EvidenceSink(sink_id, reg)


def _emit(s, *, key=_KEY, **over):
    kwargs = dict(
        sink_id=_SINK_ID,
        run_id="run-abc",
        approval_id="appr-1",
        emitter_key_id=_KEY_ID,
        report=_report(),
    )
    kwargs.update(over)
    return evidence_emit.emit_apply_result(s, key, **kwargs)


# --- build_apply_result_payload ---
def test_build_payload_matches_to_record_and_excludes_run_binding():
    rep = _report()
    payload = evidence_emit.build_apply_result_payload(rep)
    assert payload == rep.to_record()
    # run_id/approval_id bind at the envelope layer, never the payload.
    assert "run_id" not in payload
    assert "approval_id" not in payload
    # pure: calling again yields the same value; the report is unchanged.
    assert evidence_emit.build_apply_result_payload(rep) == payload


# --- happy path ---
def test_emit_appends_one_apply_result_record():
    s = _sink()
    rec = _emit(s)
    assert len(s) == 1
    assert rec.envelope.record_type == "apply_result"
    assert rec.seq == 0


def test_emitted_record_uses_emitter_opencode():
    s = _sink()
    rec = _emit(s)
    assert rec.envelope.emitter == sinkmod.EMITTER_OPENCODE


def test_emitted_envelope_contains_injected_run_id():
    s = _sink()
    rec = _emit(s, run_id="run-xyz")
    assert rec.envelope.run_id == "run-xyz"


def test_emitted_envelope_contains_approval_id_when_provided():
    s = _sink()
    rec = _emit(s, approval_id="appr-77")
    assert rec.envelope.approval_id == "appr-77"


def test_emitted_envelope_approval_id_is_none_when_omitted():
    s = _sink()
    rec = _emit(s, approval_id=None)
    assert rec.envelope.approval_id is None


def test_emitted_payload_includes_apply_report_fields():
    s = _sink()
    rec = _emit(s)
    for field in (
        "status",
        "declared_files",
        "changed_files",
        "violations",
        "committed",
        "generated_at",
        "detail",
    ):
        assert field in rec.payload
    assert rec.payload["status"] == "applied"
    assert rec.payload["declared_files"] == ["a.py"]


def test_payload_hash_matches_stored_payload():
    s = _sink()
    rec = _emit(s)
    assert sinkmod.payload_digest(rec.payload) == rec.envelope.payload_hash


def test_signature_verifies_and_chain_passes():
    s = _sink()
    _emit(s)
    s.verify_chain()  # does not raise: sig + chain valid


def test_multiple_emits_chain_correctly():
    s = _sink()
    r0 = _emit(s, run_id="run-0")
    r1 = _emit(s, run_id="run-1")
    assert (r0.seq, r1.seq) == (0, 1)
    assert r1.prev_hash == r0.record_hash
    s.verify_chain()


def test_ts_defaults_to_report_generated_at():
    s = _sink()
    rep = _report()
    rec = _emit(s, report=rep)
    assert rec.envelope.ts == rep.generated_at


def test_emit_does_not_touch_the_filesystem(monkeypatch):
    def _no_open(*args, **kwargs):  # pragma: no cover - only fires on a violation
        raise AssertionError("emit must not open/write any file (no disk/env key loading)")

    monkeypatch.setattr("builtins.open", _no_open)
    s = _sink()
    _emit(s)
    s.verify_chain()


# --- structural rejections (fail closed, loud) ---
def test_missing_sink_raises():
    with pytest.raises(sinkmod.EvidenceError):
        evidence_emit.emit_apply_result(
            None,
            _KEY,
            sink_id=_SINK_ID,
            run_id="run-abc",
            approval_id=None,
            emitter_key_id=_KEY_ID,
            report=_report(),
        )


def test_missing_or_bad_key_raises():
    s = _sink()
    for bad in (None, b"", "not-bytes"):
        with pytest.raises(sinkmod.EvidenceError):
            _emit(s, key=bad)


def test_empty_sink_id_raises():
    s = _sink()
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s, sink_id="")


def test_empty_run_id_raises():
    s = _sink()
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s, run_id="")


def test_empty_emitter_key_id_raises():
    s = _sink()
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s, emitter_key_id="")


def test_missing_registry_key_causes_evidence_error():
    reg = sinkmod.EmitterKeyRegistry()  # no key registered for opencode
    s = sinkmod.EvidenceSink(_SINK_ID, reg)
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s)  # sink cannot resolve (opencode, key_id) -> unknown_emitter
    assert len(s) == 0  # nothing appended on failure


def test_sink_id_mismatch_causes_evidence_error():
    s = _sink()  # sink's real id is _SINK_ID
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s, sink_id="a-different-sink")  # envelope sink_id != sink id -> sink_mismatch
    assert len(s) == 0


def test_wrong_signing_key_causes_evidence_error():
    s = _sink()  # registry holds _KEY
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s, key=_KEY2)  # signed with a key the sink does not hold -> sig_invalid
    assert len(s) == 0


# --- no gateway / no verifier-consume coupling ---
def test_evidence_emit_has_no_gateway_or_verifier_consume_imports():
    import types

    module_globals = {
        v.__name__ for v in vars(evidence_emit).values() if isinstance(v, types.ModuleType)
    }
    assert not any(name.startswith("private_ai_gateway") for name in module_globals)
    assert not any(
        tok in name
        for name in module_globals
        for tok in ("worker", "checks", "report")
    )
    # The record types come from the sink core, not any gateway/verifier module.
    assert evidence_emit.SigningEnvelope.__module__.startswith("openclaw")


# --- minimal worker wiring (additive injection) ---
class _FakePeer:
    """A stub AgentPeer just sufficient for CodeActWorker._start's happy path."""

    def __init__(self):
        self.reports = []

    def whoami(self):
        return {"principal": "opencode"}

    def inbox(self, *, status="submitted"):
        return []

    def find_peer(self, *args, **kwargs):
        return None  # no verifier: _start emits (emit precedes verifier lookup), then reports

    def report(self, task_id, status, *, result="", verdict=""):
        self.reports.append((task_id, status, verdict))
        return {"reported": True}


def _proposal_and_target(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("old\n", encoding="utf-8")
    prop = tmp_path / "prop.json"
    prop.write_text(
        json.dumps(
            {
                "edits": [{"path": "a.py", "kind": "modify", "new_content": "new\n"}],
                "rationale": "test",
                "autonomy_level": "L3",
            }
        ),
        encoding="utf-8",
    )
    return prop, target


def test_worker_without_sink_preserves_old_behavior(tmp_path):
    from opencode_sandbox.worker import CodeActWorker

    prop, target = _proposal_and_target(tmp_path)
    worker = CodeActWorker(
        _FakePeer(),
        approval=act.Approval("owner", "ok"),
        proposal_path=prop,
        target=target,
        runtime_dir=tmp_path / "rt",
    )
    worker._start({"id": "t1", "granted_level": 3})  # must not raise
    # apply_report.json is still written (back-compat), with no sink to emit into.
    assert list((tmp_path / "rt").rglob("apply_report.json"))


def test_worker_with_sink_emits_after_apply(tmp_path):
    from opencode_sandbox.worker import CodeActWorker

    prop, target = _proposal_and_target(tmp_path)
    s = _sink()
    worker = CodeActWorker(
        _FakePeer(),
        approval=act.Approval("owner", "ok"),
        proposal_path=prop,
        target=target,
        runtime_dir=tmp_path / "rt",
        evidence_sink=s,
        evidence_key=_KEY,
        emitter_key_id=_KEY_ID,
        sink_id=_SINK_ID,
        run_id="run-worker",
        approval_id="appr-w",
    )
    worker._start({"id": "t1", "granted_level": 3})
    assert len(s) == 1
    rec = s.records[0]
    assert rec.envelope.record_type == "apply_result"
    assert rec.envelope.emitter == sinkmod.EMITTER_OPENCODE
    assert rec.envelope.run_id == "run-worker"
    assert rec.envelope.approval_id == "appr-w"
    s.verify_chain()
    # apply_report.json is preserved alongside the sink record (back-compat).
    assert list((tmp_path / "rt").rglob("apply_report.json"))


# --- Step 6A: the executor emit carries a v2, evidence-identified envelope ---
def test_emit_envelope_is_schema_v2_with_stable_evidence_id():
    # The apply_result record is v2 and carries a well-formed, signed evidence_id, and its
    # EvidenceRef is derivable from the appended record. The payload is unchanged (item 15).
    import re

    s = _sink()
    rec = _emit(s)
    assert rec.envelope.schema_version == 2
    assert re.match(r"^ev-[0-9a-f]{32}$", rec.envelope.evidence_id)
    # Payload contract unchanged: exactly the report record, no evidence-ref field added.
    assert rec.payload == _report().to_record()
    ref = rec.evidence_ref()
    assert ref.evidence_id == rec.envelope.evidence_id
    assert ref.record_type == "apply_result"
    assert ref.sink_id == _SINK_ID


def test_two_emits_have_distinct_evidence_ids():
    s = _sink()
    r1 = _emit(s, run_id="run-1", approval_id="appr-1")
    r2 = _emit(s, run_id="run-2", approval_id="appr-2")
    assert r1.envelope.evidence_id != r2.envelope.evidence_id


# --- Step 6B: apply_result binds an optional execute_ref, and only that ---
def _execute_ref():
    """A plausible gateway execute_validated EvidenceRef (shape only; not resolved here)."""
    return sinkmod.EvidenceRef(
        evidence_id=sinkmod.new_evidence_id(),
        evidence_digest="sha256:" + "a" * 64,
        record_type="execute_validated",
        sink_id=_SINK_ID,
    )


def test_emit_without_execute_ref_is_payload_identical():
    # Default/no-linkage compatibility: with no execute_ref the payload is exactly the report.
    s = _sink()
    rec = _emit(s)
    assert rec.payload == _report().to_record()
    assert "execute_ref" not in rec.payload


def test_emit_with_execute_ref_adds_only_that_field():
    s = _sink()
    ref = _execute_ref()
    rec = _emit(s, execute_ref=ref)
    base = _report().to_record()
    # The signed payload retains every existing key and adds exactly one: execute_ref.
    assert set(rec.payload.keys()) == set(base.keys()) | {"execute_ref"}
    assert rec.payload["execute_ref"] == ref.to_mapping()
    for k, v in base.items():
        assert rec.payload[k] == v
    assert sinkmod.payload_digest(rec.payload) == rec.envelope.payload_hash  # ref is signed


def test_emit_with_malformed_execute_ref_fails_closed():
    # A non-EvidenceRef execute_ref must not produce a (falsely) linked apply_result.
    s = _sink()
    with pytest.raises(sinkmod.EvidenceError):
        _emit(s, execute_ref={"evidence_id": "ev-" + "0" * 32})
    assert len(s) == 0
