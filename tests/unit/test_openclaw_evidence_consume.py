"""Evidence-sink design step 4: OpenClaw verifier *consumes* signed ``apply_result`` records.

These tests pin the consume contract in-process, against a real
:class:`openclaw.sink.EvidenceSink` with ephemeral in-test HMAC keys (no key material in the
repo, no disk/env loading). They prove the verifier can independently validate sink evidence —
verify the chain, find the matching signed ``apply_result``, and derive the apply verdict from
it — and, critically, that an unsigned ``apply_report.json`` alone is **insufficient** for a
PASS once signed evidence is required (the self-attestation regression, threat T1).

Valid records are built with the real executor emit helper
(:func:`opencode_sandbox.evidence_emit.emit_apply_result`); importing it in a test does not
touch the executor package. Tamper/replay cases reach into the sink's internal ``_records``
deliberately (white-box) to forge states that ``append`` would otherwise refuse, so that
``verify_chain`` — and therefore the consume path — is what catches them.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from openclaw import checks, evidence
from openclaw import sink as sinkmod
from openclaw.checks import FAIL, INCONCLUSIVE, PASS, Evidence
from openclaw.report import build_report
from opencode_sandbox import evidence_emit
from opencode_sandbox.apply import APPLIED, FAILED, ApplyReport

# Ephemeral, in-test key material only — never loaded from disk/env, never committed.
_KEY = b"openclaw-consume-key-0123456789ab"  # 32 bytes
_KEY2 = b"a-different-consume-key-abcdef012"
_SINK_ID = "sink-consume-1"
_KEY_ID = "opencode-hmac-1"
_RUN = "run-xyz"
_APPR = "appr-9"

_REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- helpers
def _registry(*, emitter=None, key=_KEY, key_id=_KEY_ID) -> sinkmod.EmitterKeyRegistry:
    reg = sinkmod.EmitterKeyRegistry()
    reg.register(emitter or sinkmod.EMITTER_OPENCODE, key_id, key)
    return reg


def _sink(reg: sinkmod.EmitterKeyRegistry | None = None, sink_id: str = _SINK_ID):
    return sinkmod.EvidenceSink(sink_id, reg or _registry())


def _report(**over) -> ApplyReport:
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


def _emit(sink, *, key=_KEY, run_id=_RUN, approval_id=_APPR, report=None, key_id=_KEY_ID,
          nonce=None):
    return evidence_emit.emit_apply_result(
        sink,
        key,
        sink_id=sink.sink_id,
        run_id=run_id,
        approval_id=approval_id,
        emitter_key_id=key_id,
        report=report or _report(),
        nonce=nonce,
    )


def _apply_view(**over) -> evidence.ApplyReportView:
    fields = dict(
        status="applied",
        approver="owner",
        committed=False,
        declared_files=["a.py"],
        changed_files=["a.py"],
    )
    fields.update(over)
    return evidence.ApplyReportView(**fields)


def _control(**ev_over) -> object:
    ev = Evidence(audit=evidence.AuditLog(), **ev_over)
    return checks.check_apply_evidence_chain(ev)


# ------------------------------------------------------------ old-mode compatibility
def test_no_sink_preserves_old_behavior():
    # No sink, not required: the new control is INCONCLUSIVE and never changes a verdict.
    f = _control(apply_report=_apply_view(), evidence_sink=None)
    assert f.status == INCONCLUSIVE


def test_unsigned_apply_report_old_mode_still_passes_when_sink_not_required():
    # File-mode: a clean applied report PASSes AC-APPLY-INTEGRITY. The gated signed-evidence
    # control is absent entirely (no sink, not required), so the run is the historical set and
    # the verdict is still PASS.
    ev = Evidence(audit=evidence.AuditLog(), apply_report=_apply_view())
    findings = checks.run_all(ev)
    report = build_report(findings)
    assert report.verdict == "PASS"
    assert len(findings) == len(checks.ALL_CHECKS)  # gated control not appended
    assert not [f for f in findings if f.control_id == "AC-APPLY-EVIDENCE-CHAIN"]
    integ = [f for f in findings if f.control_id == "AC-APPLY-INTEGRITY"][0]
    assert integ.status == PASS


# ------------------------------------------------------------------- happy consume
def test_run_all_appends_signed_control_only_when_sink_engaged():
    sink = _sink()
    _emit(sink)
    with_sink = checks.run_all(Evidence(audit=evidence.AuditLog(), evidence_sink=sink, run_id=_RUN))
    without = checks.run_all(Evidence(audit=evidence.AuditLog()))
    assert len(without) == len(checks.ALL_CHECKS)
    assert {f.control_id for f in without} & {"AC-APPLY-EVIDENCE-CHAIN", "AC-EVIDENCE-GRAPH"} == set()
    # Engaging a sink appends exactly the two gated signed-evidence controls (design step 4
    # apply-chain + design step 6B graph linkage).
    assert len(with_sink) == len(checks.ALL_CHECKS) + 2
    gated = {f.control_id for f in with_sink} - {f.control_id for f in without}
    assert gated == {"AC-APPLY-EVIDENCE-CHAIN", "AC-EVIDENCE-GRAPH"}


def test_clean_sink_apply_result_passes_when_required():
    sink = _sink()
    _emit(sink)
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == PASS
    assert "signed" in f.detail.lower()


def test_finds_matching_record_by_run_id():
    sink = _sink()
    _emit(sink, run_id="run-A", report=_report(declared_files=["a.py"], changed_files=["a.py"]))
    _emit(sink, run_id="run-B", report=_report(declared_files=["b.py"], changed_files=["b.py"]))
    va = evidence.load_apply_result_from_sink(sink, run_id="run-A")
    vb = evidence.load_apply_result_from_sink(sink, run_id="run-B")
    assert va.usable and vb.usable
    assert va.run_id == "run-A" and vb.run_id == "run-B"
    assert va.declared_files == ["a.py"] and vb.declared_files == ["b.py"]
    assert va.seq != vb.seq


def test_filters_by_emitter_opencode():
    # A *gateway*-emitter record with the same run_id/type must be ignored — only an
    # opencode-authored apply_result counts. With none present, the view is "missing".
    reg = _registry(emitter=sinkmod.EMITTER_GATEWAY)
    sink = _sink(reg)
    payload = {
        "status": "applied", "approver": "owner", "committed": False,
        "declared_files": ["a.py"], "changed_files": ["a.py"],
    }
    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION, evidence_id=sinkmod.new_evidence_id(),
        sink_id=_SINK_ID, run_id=_RUN,
        approval_id=_APPR, emitter=sinkmod.EMITTER_GATEWAY, emitter_key_id=_KEY_ID,
        record_type="apply_result", payload_hash=sinkmod.payload_digest(payload),
        ts="t", nonce="n-gw",
    )
    sink.append(env, payload, sinkmod.sign_envelope(env, _KEY))
    view = evidence.load_apply_result_from_sink(sink, run_id=_RUN)
    assert view.configured and view.missing


def test_filters_by_record_type_apply_result():
    # An opencode record whose type is not "apply_result" is ignored.
    sink = _sink()
    payload = {"verdict": "PASS"}
    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION, evidence_id=sinkmod.new_evidence_id(),
        sink_id=_SINK_ID, run_id=_RUN,
        approval_id=_APPR, emitter=sinkmod.EMITTER_OPENCODE, emitter_key_id=_KEY_ID,
        record_type="assurance_verdict", payload_hash=sinkmod.payload_digest(payload),
        ts="t", nonce="n-av",
    )
    sink.append(env, payload, sinkmod.sign_envelope(env, _KEY))
    view = evidence.load_apply_result_from_sink(sink, run_id=_RUN)
    assert view.configured and view.missing


def test_approval_id_match_passes_when_present():
    sink = _sink()
    _emit(sink, approval_id="appr-1")
    f = _control(
        evidence_sink=sink, run_id=_RUN, approval_id="appr-1",
        require_signed_apply_evidence=True,
    )
    assert f.status == PASS


def test_approval_id_mismatch_fails():
    sink = _sink()
    _emit(sink, approval_id="appr-1")
    # Asking for a different approval_id filters the record out -> required-but-missing -> FAIL.
    f = _control(
        evidence_sink=sink, run_id=_RUN, approval_id="appr-2",
        require_signed_apply_evidence=True,
    )
    assert f.status == FAIL


# ------------------------------------------------- the self-attestation regression
def test_unsigned_apply_report_alone_fails_when_signed_evidence_required():
    # THE HEADLINE: a forged/self-attested apply_report.json with no signed sink evidence is
    # insufficient for PASS once signed evidence is required.
    forged = _apply_view(approver="owner", status="applied")  # looks clean, but unsigned
    f = _control(
        apply_report=forged, evidence_sink=None, require_signed_apply_evidence=True
    )
    assert f.status == FAIL
    assert "unsigned" in f.detail.lower() or "no evidence sink" in f.detail.lower()


def test_file_missing_but_valid_signed_record_passes_when_required():
    sink = _sink()
    _emit(sink)
    f = _control(
        apply_report=None, evidence_sink=sink, run_id=_RUN,
        require_signed_apply_evidence=True,
    )
    assert f.status == PASS


def test_missing_required_apply_result_fails():
    sink = _sink()  # empty
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == FAIL


def test_conflict_between_apply_report_and_signed_payload_fails():
    # File says a different approver than the signed record -> tamper signal -> FAIL, even
    # though the signed record on its own would PASS.
    sink = _sink()
    _emit(sink, report=_report(approver="owner"))
    conflicting_file = _apply_view(approver="mallory")
    f = _control(apply_report=conflicting_file, evidence_sink=sink, run_id=_RUN)
    assert f.status == FAIL
    assert "disagree" in f.detail.lower() or "conflict" in f.detail.lower()


# ------------------------------------------------------------- integrity failures
def test_tampered_sink_payload_fails():
    sink = _sink()
    _emit(sink)
    # Mutate the *stored* payload in place: verify_chain recomputes the payload hash and
    # detects the mismatch -> the consume path fails closed.
    sink._records[0].payload["status"] = "refused"
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == FAIL
    view = evidence.load_apply_result_from_sink(sink, run_id=_RUN)
    assert view.chain_error


def test_invalid_signature_or_unknown_key_fails_without_crashing():
    # (a) invalid signature: swap the verification key so the stored MAC no longer verifies.
    sink = _sink()
    _emit(sink)
    sink._registry._keys[(sinkmod.EMITTER_OPENCODE, _KEY_ID)] = _KEY2
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == FAIL

    # (b) unknown key: drop the key entirely -> registry.get raises -> chain_error, no crash.
    sink2 = _sink()
    _emit(sink2)
    del sink2._registry._keys[(sinkmod.EMITTER_OPENCODE, _KEY_ID)]
    view = evidence.load_apply_result_from_sink(sink2, run_id=_RUN)
    assert view.chain_error
    f2 = _control(evidence_sink=sink2, run_id=_RUN, require_signed_apply_evidence=True)
    assert f2.status == FAIL


def test_broken_chain_fails():
    sink = _sink()
    _emit(sink, nonce="n0", report=_report(declared_files=["a.py"], changed_files=["a.py"]))
    _emit(sink, nonce="n1", report=_report(declared_files=["b.py"], changed_files=["b.py"]))
    # Reorder the stored records: seq no longer equals index -> chain re-derivation fails.
    sink._records.reverse()
    view = evidence.load_apply_result_from_sink(sink, run_id=_RUN)
    assert view.chain_error
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == FAIL


def test_multiple_matching_records_select_highest_seq_deterministically():
    # Two records for the same run: an earlier clean-APPLIED and a later FAILED. The consume
    # path must select the highest seq (the FAILED one), so the verdict is FAIL — proving it
    # does not opportunistically pick the earlier passing record.
    sink = _sink()
    _emit(sink, nonce="n0", report=_report(status=APPLIED))
    _emit(sink, nonce="n1", report=_report(status=FAILED))
    view = evidence.load_apply_result_from_sink(sink, run_id=_RUN)
    assert view.seq == 1
    assert (view.status or "").lower() == "failed"
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == FAIL


def test_duplicate_nonce_replay_fails_via_verify_chain():
    # Forge a second, correctly-hashed record that reuses the first record's (emitter, nonce).
    # append() would refuse this; injecting it directly lets verify_chain's from-scratch replay
    # defence catch it -> chain_error -> FAIL.
    sink = _sink()
    rec0 = _emit(sink, nonce="dup-nonce")
    tmp = dataclasses.replace(rec0, seq=1, prev_hash=rec0.record_hash)
    rec1 = dataclasses.replace(tmp, record_hash=sinkmod.record_digest(tmp.hashable_fields()))
    sink._records.append(rec1)
    view = evidence.load_apply_result_from_sink(sink, run_id=_RUN)
    assert view.chain_error
    f = _control(evidence_sink=sink, run_id=_RUN, require_signed_apply_evidence=True)
    assert f.status == FAIL


# -------------------------------------------------------------- source-scan guards
def test_no_key_loading_from_disk_or_env():
    # The edited modules must not load key material from disk or environment.
    forbidden = ("os.environ", "getenv", "PRIVATE_AI_EVIDENCE_KEY", "environ[")
    for mod in (evidence, checks):
        src = Path(mod.__file__).read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{mod.__name__} references {token!r}"
    worker_src = (_REPO_ROOT / "agents" / "openclaw" / "worker.py").read_text(encoding="utf-8")
    for token in forbidden:
        assert token not in worker_src, f"worker.py references {token!r}"
