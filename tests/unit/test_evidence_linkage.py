"""Evidence-sink design step 6B: signed linkage across the authorization→execution→apply graph.

These tests pin the *signed evidence graph*

    approval_decided  <--approval_ref--  execute_validated  <--execute_ref--  apply_result

end to end, against a real :class:`openclaw.sink.EvidenceSink`. The gateway records are built
through the *real* gateway emit helpers (:mod:`private_ai_gateway.orchestration`) so the
approval-ref resolution path is exercised, not stubbed; the apply_result is built through the
*real* executor emit (:mod:`opencode_sandbox.evidence_emit`). Verification runs through the
*real* OpenClaw graph loader/control (:mod:`openclaw.evidence` / :mod:`openclaw.checks`).

Every reference is a Step 6A :class:`~openclaw.sink.EvidenceRef` (evidence_id + evidence_digest
+ record_type + sink_id) — never a sequence number or ``record_hash``. No API client supplies a
reference: the gateway mints ``execute_validated``'s ref and threads it internally to the apply.

Standard-library + in-repo only; ephemeral in-test HMAC keys (no disk/env/committed material).
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from uuid import uuid4

import pytest
from openclaw import checks, evidence
from openclaw import sink as sinkmod
from openclaw.checks import FAIL, INCONCLUSIVE, PASS, Evidence
from opencode_sandbox import evidence_emit
from opencode_sandbox.apply import APPLIED, ApplyReport

from private_ai_gateway import approvals, orchestration

# Ephemeral, in-test key material only.
_GW_KEY = b"gateway-linkage-key-0123456789abc"  # 33 bytes; any non-empty bytes suffice
_OC_KEY = b"opencode-linkage-key-0123456789ab"
_SINK_ID = "sink-link-1"
_GW_KID = "gateway-hmac-1"
_OC_KID = "opencode-hmac-1"
_RUN = "run-link"
_APPR = "appr-link"
_HASH = "sha256:" + "c" * 64  # a canonical plan hash


# --------------------------------------------------------------------------- builders
def _registry() -> sinkmod.EmitterKeyRegistry:
    reg = sinkmod.EmitterKeyRegistry()
    reg.register(sinkmod.EMITTER_GATEWAY, _GW_KID, _GW_KEY)
    reg.register(sinkmod.EMITTER_OPENCODE, _OC_KID, _OC_KEY)
    return reg


def _sink(sink_id: str = _SINK_ID) -> sinkmod.EvidenceSink:
    return sinkmod.EvidenceSink(sink_id, _registry())


def _gw(sink, *, require: bool = False) -> SimpleNamespace:
    """A minimal stand-in for the gateway app module the emit helpers read config off."""
    return SimpleNamespace(
        EVIDENCE_SINK=sink,
        EVIDENCE_KEY=_GW_KEY,
        EVIDENCE_KEY_ID=_GW_KID,
        REQUIRE_AUTHORIZATION_EVIDENCE=require,
    )


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


def _emit_approval(sink, *, decision="approve", run_id=_RUN, approval_id=_APPR,
                   plan_hash=_HASH, approver="owner"):
    ok = orchestration._emit_approval_decided(
        _gw(sink), run_id=run_id, approval_id=approval_id,
        decision=decision, approver=approver, canonical_plan_hash=plan_hash,
    )
    assert ok is True
    return sink.records[-1]


def _emit_execute(sink, *, run_id=_RUN, approval_id=_APPR, plan_hash=_HASH, require=False):
    return orchestration._emit_execute_validated(
        _gw(sink, require=require),
        run_id=run_id, approval_id=approval_id, canonical_plan_hash=plan_hash,
    )


def _emit_apply(sink, *, run_id=_RUN, approval_id=_APPR, execute_ref=None, report=None):
    return evidence_emit.emit_apply_result(
        sink, _OC_KEY, sink_id=sink.sink_id, run_id=run_id, approval_id=approval_id,
        emitter_key_id=_OC_KID, report=report or _report(), execute_ref=execute_ref,
    )


def _raw_append(sink, *, emitter, key, key_id, record_type, run_id, approval_id, payload):
    """Append an arbitrary signed record — for constructing malformed/forged graphs directly."""
    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(),
        sink_id=sink.sink_id, run_id=run_id, approval_id=approval_id,
        emitter=emitter, emitter_key_id=key_id, record_type=record_type,
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-01-01T00:00:00+00:00", nonce=uuid4().hex,
    )
    sig = sinkmod.sign_envelope(env, key)
    return sink.append(env, payload, sig)


def _full_graph(sink):
    """Emit the complete happy-path graph; return the execute_validated EvidenceRef."""
    _emit_approval(sink)
    emit = _emit_execute(sink)
    assert emit.proceed is True and emit.evidence_ref is not None
    _emit_apply(sink, execute_ref=emit.evidence_ref)
    return emit.evidence_ref


def _graph_finding(sink, **ev_over):
    ev = Evidence(audit=evidence.AuditLog(), evidence_sink=sink, run_id=_RUN,
                  approval_id=_APPR, **ev_over)
    return checks.check_evidence_graph_linkage(ev)


# ============================================================ 1. happy-path graph
def test_happy_path_graph_verifies_pass():
    sink = _sink()
    _full_graph(sink)
    view = evidence.load_evidence_graph_from_sink(sink, run_id=_RUN, approval_id=_APPR)
    assert view.linked is True and view.usable is True
    assert view.decision == "approve"
    assert view.canonical_plan_hash == _HASH
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == PASS
    assert "approval_decided" in f.detail


# ============================================================ 2. ref stability
def test_pre_append_and_appended_execute_ref_are_identical():
    sink = _sink()
    _emit_approval(sink)
    emit = _emit_execute(sink)
    # The ref the gateway obtained equals the appended execute_validated record's own ref…
    exec_rec = next(r for r in sink.records
                    if r.envelope.record_type == "execute_validated")
    assert emit.evidence_ref == exec_rec.evidence_ref()
    # …and it is exactly what apply_result carries.
    apply_rec = _emit_apply(sink, execute_ref=emit.evidence_ref)
    assert apply_rec.payload["execute_ref"] == emit.evidence_ref.to_mapping()


# ============================================================ 3-5. payload contracts
def test_approval_decided_payload_keys_unchanged():
    sink = _sink()
    rec = _emit_approval(sink)
    assert set(rec.payload.keys()) == {"decision", "approver", "canonical_plan_hash"}


def test_execute_validated_payload_keys_are_exactly_three():
    sink = _sink()
    _emit_approval(sink)
    _emit_execute(sink)
    rec = next(r for r in sink.records if r.envelope.record_type == "execute_validated")
    assert set(rec.payload.keys()) == {"canonical_plan_hash", "validated", "approval_ref"}
    assert set(rec.payload["approval_ref"].keys()) == {
        "evidence_id", "evidence_digest", "record_type", "sink_id"
    }


def test_apply_result_payload_adds_only_execute_ref():
    sink = _sink()
    ref = _full_graph(sink)
    apply_rec = next(r for r in sink.records if r.envelope.record_type == "apply_result")
    base = _report().to_record()
    assert set(apply_rec.payload.keys()) == set(base.keys()) | {"execute_ref"}
    assert apply_rec.payload["execute_ref"] == ref.to_mapping()


# ============================================================ 6. missing approval_ref
def test_missing_approval_ref_breaks_graph():
    # An execute_validated with no approval_ref (built directly) cannot complete the graph.
    sink = _sink()
    appr = _emit_approval(sink)
    exec_rec = _raw_append(
        sink, emitter=sinkmod.EMITTER_GATEWAY, key=_GW_KEY, key_id=_GW_KID,
        record_type="execute_validated", run_id=_RUN, approval_id=_APPR,
        payload={"canonical_plan_hash": _HASH, "validated": True},  # no approval_ref
    )
    assert appr  # (approval exists but is never linked)
    _emit_apply(sink, execute_ref=exec_rec.evidence_ref())
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL and "approval_ref" in f.detail.lower()


# ============================================================ 7. missing execute_ref
def test_missing_execute_ref_required_fails_optional_inconclusive():
    sink = _sink()
    _emit_approval(sink)
    _emit_execute(sink)
    _emit_apply(sink, execute_ref=None)  # legacy/unsigned-linkage apply
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL
    assert _graph_finding(sink, require_signed_linkage=False).status == INCONCLUSIVE


# ============================================================ 8. malformed ref mapping
def test_malformed_execute_ref_mapping_breaks_graph():
    sink = _sink()
    _emit_approval(sink)
    _emit_execute(sink)
    _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="apply_result", run_id=_RUN, approval_id=_APPR,
        payload={**_report().to_record(), "execute_ref": "not-a-mapping"},
    )
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL


# ============================================================ 9. dangling evidence id
def test_dangling_execute_ref_breaks_graph():
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    dangling = dataclasses.replace(ref, evidence_id="ev-" + "0" * 32)
    _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="apply_result", run_id=_RUN, approval_id=_APPR,
        payload={**_report().to_record(), "execute_ref": dangling.to_mapping()},
    )
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


# ============================================================ 10. digest mismatch
def test_execute_ref_digest_mismatch_breaks_graph():
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    tampered = dataclasses.replace(ref, evidence_digest="sha256:" + "d" * 64)
    _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="apply_result", run_id=_RUN, approval_id=_APPR,
        payload={**_report().to_record(), "execute_ref": tampered.to_mapping()},
    )
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


# ============================================================ 11. wrong record type
def test_execute_ref_wrong_record_type_breaks_graph():
    # execute_ref declares record_type approval_decided → not an execute_validated edge.
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    mistyped = dataclasses.replace(ref, record_type="approval_decided")
    _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="apply_result", run_id=_RUN, approval_id=_APPR,
        payload={**_report().to_record(), "execute_ref": mistyped.to_mapping()},
    )
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


# ============================================================ 12. wrong emitter
def test_execute_ref_wrong_emitter_breaks_graph():
    # An execute_validated-typed record emitted by opencode (not the gateway) is not authority.
    sink = _sink()
    appr = _emit_approval(sink)
    forged = _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="execute_validated", run_id=_RUN, approval_id=_APPR,
        payload={"canonical_plan_hash": _HASH, "validated": True,
                 "approval_ref": appr.evidence_ref().to_mapping()},
    )
    _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="apply_result", run_id=_RUN, approval_id=_APPR,
        payload={**_report().to_record(), "execute_ref": forged.evidence_ref().to_mapping()},
    )
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL and "gateway" in f.detail.lower()


# ============================================================ 13-14. cross run / approval
def test_cross_run_execute_ref_breaks_graph():
    sink = _sink()
    # A complete, valid graph for a *different* run.
    _emit_approval(sink, run_id="run-OTHER", approval_id=_APPR)
    other = _emit_execute(sink, run_id="run-OTHER", approval_id=_APPR)
    # apply_result for _RUN references run-OTHER's execute_validated.
    _emit_approval(sink)  # so _RUN has its own approval too
    _emit_apply(sink, run_id=_RUN, approval_id=_APPR, execute_ref=other.evidence_ref)
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


def test_cross_approval_execute_ref_breaks_graph():
    sink = _sink()
    _emit_approval(sink, run_id=_RUN, approval_id="appr-OTHER")
    other = _emit_execute(sink, run_id=_RUN, approval_id="appr-OTHER")
    _emit_approval(sink, run_id=_RUN, approval_id=_APPR)
    _emit_apply(sink, run_id=_RUN, approval_id=_APPR, execute_ref=other.evidence_ref)
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


# ============================================================ 15. referenced decision reject
def test_referenced_reject_decision_breaks_graph():
    sink = _sink()
    reject = _emit_approval(sink, decision="reject")
    exec_rec = _raw_append(
        sink, emitter=sinkmod.EMITTER_GATEWAY, key=_GW_KEY, key_id=_GW_KID,
        record_type="execute_validated", run_id=_RUN, approval_id=_APPR,
        payload={"canonical_plan_hash": _HASH, "validated": True,
                 "approval_ref": reject.evidence_ref().to_mapping()},
    )
    _emit_apply(sink, execute_ref=exec_rec.evidence_ref())
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL and "approve" in f.detail.lower()


# ============================================================ 16. plan-hash mismatch
def test_canonical_plan_hash_mismatch_breaks_graph():
    sink = _sink()
    appr = _emit_approval(sink, plan_hash=_HASH)
    exec_rec = _raw_append(
        sink, emitter=sinkmod.EMITTER_GATEWAY, key=_GW_KEY, key_id=_GW_KID,
        record_type="execute_validated", run_id=_RUN, approval_id=_APPR,
        payload={"canonical_plan_hash": "sha256:" + "e" * 64, "validated": True,
                 "approval_ref": appr.evidence_ref().to_mapping()},
    )
    _emit_apply(sink, execute_ref=exec_rec.evidence_ref())
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


# ============================================================ 17. duplicate execute_validated
def test_duplicate_execute_validated_for_approval_breaks_graph():
    sink = _sink()
    _emit_approval(sink)
    first = _emit_execute(sink)          # execute_validated #1
    _emit_execute(sink)                  # execute_validated #2 (same run/approval)
    _emit_apply(sink, execute_ref=first.evidence_ref)
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL and "ambiguous" in f.detail.lower()


# ============================================================ 18. ambiguous approval_decided
def test_ambiguous_approval_decided_breaks_graph():
    sink = _sink()
    _emit_approval(sink)                 # approval_decided #1
    emit = _emit_execute(sink)           # references #1 (still unique at this point)
    _emit_approval(sink)                 # approval_decided #2 (duplicate)
    _emit_apply(sink, execute_ref=emit.evidence_ref)
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL and "ambiguous" in f.detail.lower()


# ============================================================ 19. tampered referenced record
def test_tampered_referenced_record_fails_chain():
    sink = _sink()
    _full_graph(sink)
    # Corrupt the execute_validated record's signature in place → verify_chain rejects the log.
    for i, rec in enumerate(sink._records):
        if rec.envelope.record_type == "execute_validated":
            sink._records[i] = dataclasses.replace(
                rec, emitter_sig="hmac-sha256:" + "0" * 64
            )
            break
    view = evidence.load_evidence_graph_from_sink(sink, run_id=_RUN, approval_id=_APPR)
    assert view.chain_error is True
    assert _graph_finding(sink, require_signed_linkage=True).status == FAIL


# ============================================================ 20. unsigned file cannot rescue
def test_unsigned_apply_report_cannot_rescue_broken_graph():
    sink = _sink()
    _emit_approval(sink)
    _emit_execute(sink)
    _emit_apply(sink, execute_ref=None)  # linkage absent
    clean_file = evidence.ApplyReportView(
        status="applied", approver="owner", committed=False,
        declared_files=["a.py"], changed_files=["a.py"],
    )
    # A pristine self-attested file does not lift the graph verdict off FAIL when required.
    f = _graph_finding(sink, require_signed_linkage=True, apply_report=clean_file)
    assert f.status == FAIL


# ============================================================ 21. default no-sink compatibility
def test_no_sink_graph_control_is_inconclusive_and_not_gated_in():
    # No sink, linkage not required: the graph control is INCONCLUSIVE and run_all omits it.
    ev = Evidence(audit=evidence.AuditLog())
    assert checks.check_evidence_graph_linkage(ev).status == INCONCLUSIVE
    findings = checks.run_all(ev)
    assert not [f for f in findings if f.control_id == "AC-EVIDENCE-GRAPH"]
    assert len(findings) == len(checks.ALL_CHECKS)


def test_required_linkage_without_sink_is_gated_in_and_fails():
    ev = Evidence(audit=evidence.AuditLog(), require_signed_linkage=True)
    findings = checks.run_all(ev)
    graph = [f for f in findings if f.control_id == "AC-EVIDENCE-GRAPH"]
    assert len(graph) == 1 and graph[0].status == FAIL


# ============================================================ 22. required failure is safe
def test_required_failure_does_not_leak_key_material():
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    dangling = dataclasses.replace(ref, evidence_id="ev-" + "0" * 32)
    _raw_append(
        sink, emitter=sinkmod.EMITTER_OPENCODE, key=_OC_KEY, key_id=_OC_KID,
        record_type="apply_result", run_id=_RUN, approval_id=_APPR,
        payload={**_report().to_record(), "execute_ref": dangling.to_mapping()},
    )
    f = _graph_finding(sink, require_signed_linkage=True)
    assert f.status == FAIL
    # The client-facing detail names the failing edge but leaks no key/signature material.
    assert _GW_KEY.decode() not in f.detail
    assert _OC_KEY.decode() not in f.detail
    assert "hmac-sha256:" not in f.detail


# ============================================================ 23. evidence_refs untouched
def test_approval_record_evidence_refs_is_unchanged_and_unused():
    # The linkage graph is built from sink records only — never the mutable approval state.
    rec = approvals.ApprovalRecord(
        approval_id="a1", run_id=_RUN, principal_id="owner",
        canonical_plan_hash=_HASH, effective_autonomy=3,
    )
    assert rec.evidence_refs == ()
    # The verifier's graph loader does not consult ApprovalRecord at all.
    src = evidence.load_evidence_graph_from_sink.__code__.co_names
    assert "ApprovalRecord" not in src and "evidence_refs" not in src


# ============================================================ 24. no Step 7 durability
def test_resolution_is_a_scan_with_no_durable_index():
    # The resolver works over a plain in-memory sequence — no database/index was introduced.
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    exec_rec = next(r for r in sink.records
                    if r.envelope.record_type == "execute_validated")
    resolved = sinkmod.resolve_evidence_ref(list(sink.records), ref, sink_id=_SINK_ID)
    assert resolved.envelope.evidence_id == exec_rec.envelope.evidence_id
    # Never resolves by position: the resolver takes no seq/record_hash inputs.
    assert "seq" not in sinkmod.resolve_evidence_ref.__code__.co_varnames
    assert not hasattr(sink, "_index")


# --------------------------------------------------------------------------- shared setup
def _full_graph_without_apply(sink):
    """Emit approval_decided + execute_validated; return execute_validated's EvidenceRef."""
    _emit_approval(sink)
    emit = _emit_execute(sink)
    assert emit.proceed and emit.evidence_ref is not None
    return emit.evidence_ref


# ============================================================ resolver unit behavior
def test_resolve_ref_requires_unique_evidence_id():
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    # Duplicate the referenced id onto another record → ambiguous, must fail closed.
    for i, rec in enumerate(sink._records):
        if rec.envelope.record_type == "approval_decided":
            dup_env = dataclasses.replace(rec.envelope, evidence_id=ref.evidence_id)
            sink._records[i] = dataclasses.replace(rec, envelope=dup_env)
            break
    with pytest.raises(sinkmod.EvidenceError):
        sinkmod.resolve_evidence_ref(sink.records, ref, sink_id=_SINK_ID)


def test_resolve_ref_rejects_sink_id_mismatch():
    sink = _sink()
    ref = _full_graph_without_apply(sink)
    with pytest.raises(sinkmod.EvidenceError):
        sinkmod.resolve_evidence_ref(sink.records, ref, sink_id="a-different-sink")


def test_find_unique_record_is_not_latest_wins():
    sink = _sink()
    _emit_approval(sink)
    _emit_approval(sink)  # two approval_decided for the same run/approval
    with pytest.raises(sinkmod.EvidenceError):
        sinkmod.find_unique_record(
            sink.records, emitter=sinkmod.EMITTER_GATEWAY,
            record_type="approval_decided", run_id=_RUN, approval_id=_APPR,
        )
