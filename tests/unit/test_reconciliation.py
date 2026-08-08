"""Step 7B.2 — startup cross-store reconciliation.

One pass joins the authority store and the evidence chain after each has independently
passed its own integrity validation, classifies every approval into one of six classes,
and then takes only the minimal safe action.

What these tests hold the reconciler to:

  * **Every class, via a real restart** where the shape can be produced by driving the
    governed loop and crashing it (classes 1–4), and by constructing the durable shape
    directly where a crash cannot produce it (classes 5–6).
  * **Evidence never becomes authority.** No class creates an approval or a run, and an
    orphan record is retained append-only while granting nothing.
  * **Ambiguity fails closed** — never "pick latest", never "pick first", never silently
    discarded.
  * **Unable to inspect is not clean** — a store that cannot be read aborts startup instead
    of classifying everything clean.
  * **Reconciliation cannot execute.** Structurally asserted: the module imports no
    executor, and no mutation entry point is called during a pass.

Deterministic throughout: crashes are injected at the store/session boundary, restarts are
real close/reopen cycles over a temp state dir. No sleeps.
"""

from __future__ import annotations

import pytest
from openclaw.sink import EMITTER_GATEWAY, EMITTER_OPENCODE, sign_envelope

from private_ai_gateway import app as gw
from private_ai_gateway import reconciliation
from private_ai_gateway.approvals import ApprovalStatus, RunStatus
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.reconciliation import (
    OUTCOME_ATTENTION,
    OUTCOME_CLEAN,
    OUTCOME_INVALIDATED,
    ReconciliationError,
    reconcile,
)
from private_ai_gateway.state import StateConfig, StateError, open_backend

_GW_HEX = "aa" * 32
_OC_HEX = "bb" * 32
_GW_KEY = bytes.fromhex(_GW_HEX)
_OC_KEY = bytes.fromhex(_OC_HEX)
HERMES = {"Authorization": f"Bearer {TOKENS['hermes']}"}
_OWNER_TOKEN = "test-owner-break-glass-token"
_OBJ = "Apply the reviewed fix and verify it"


def _env(tmp_path, **extra):
    env = {
        "PRIVATE_AI_EVIDENCE_KEY_GATEWAY": _GW_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCODE": _OC_HEX,
        "PRIVATE_AI_STATE_BACKEND": "sqlite",
        "PRIVATE_AI_STATE_DIR": str(tmp_path),
        "PRIVATE_AI_EVIDENCE_MODE": "durable",
    }
    env.update(extra)
    return env


def _open(tmp_path, **extra):
    env = _env(tmp_path, **extra)
    return open_backend(StateConfig.from_env(env), environ=env)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    from openclaw import assurance

    install_demo_plane(gw)
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_GATEWAY", _GW_HEX)
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_OPENCODE", _OC_HEX)
    opened = _open(tmp_path)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "APPROVAL_STORE", opened.authority_store)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _GW_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", True, raising=False)
    yield gw.app.test_client(), opened
    try:
        opened.close()
    except Exception:  # noqa: BLE001
        pass


def _plan(client):
    body = client.post(
        "/v1/orchestrate", headers=HERMES, json={"objective": _OBJ, "phase": "plan"}
    ).get_json()
    return body["run_id"], body["canonical_plan_hash"]


def _approve(client, run_id, plan_hash):
    return client.post(
        "/v1/approvals", headers={"Authorization": f"Bearer {_OWNER_TOKEN}"},
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": "reviewed"},
    ).get_json()["approval_id"]


def _execute(client, run_id, approval_id):
    return client.post(
        "/v1/orchestrate", headers=HERMES,
        json={"objective": _OBJ, "phase": "execute",
              "run_id": run_id, "approval_id": approval_id},
    ).get_json()


def _execute_crashing(client, run_id, approval_id):
    resp = client.post(
        "/v1/orchestrate", headers=HERMES,
        json={"objective": _OBJ, "phase": "execute",
              "run_id": run_id, "approval_id": approval_id},
    )
    assert resp.status_code == 500
    return resp


def _append(sink, *, record_type, run_id, approval_id, payload=None, emitter=EMITTER_GATEWAY,
            key=None, nonce="n-x"):
    """Append one signed record through the sink's real validation path."""
    from openclaw import assurance
    from openclaw import sink as sinkmod

    payload = {"crafted": True} if payload is None else payload
    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(),
        sink_id=sink.sink_id,
        run_id=run_id,
        emitter=emitter,
        emitter_key_id=assurance.EMITTER_KEY_IDS[emitter],
        record_type=record_type,
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-08-08T00:00:00+00:00",
        nonce=nonce,
        approval_id=approval_id,
    )
    return sink.append(env, payload, sign_envelope(env, key or _GW_KEY))


def _types(sink):
    return [r.envelope.record_type for r in sink.records]


# --- Class 1: approved, nothing started ----------------------------------------------

def test_class_1_approved_with_no_reservation_is_clean(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    before = _types(opened.evidence_sink)
    opened.close()

    reopened = _open(tmp_path)
    try:
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        appr = reopened.authority_store.get_approval(approval_id)
        assert appr.approval_status is ApprovalStatus.APPROVED   # still usable
        assert appr.used_at is None
        assert reopened.authority_store.get_run(run_id).status is not RunStatus.INVALIDATED
        assert _types(reopened.evidence_sink) == before           # nothing fabricated
        finding = next(f for f in report.findings if f.approval_id == approval_id)
        assert (finding.class_id, finding.outcome) == (1, OUTCOME_CLEAN)
    finally:
        reopened.close()


# --- Class 2: reserved, authority never consumed --------------------------------------

def test_class_2_reservation_without_consumption_is_invalidated(tmp_path, monkeypatch, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(opened.authority_store, "mark_used",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)
    opened.close()

    reopened = _open(tmp_path)          # open_backend reconciles
    try:
        appr = reopened.authority_store.get_approval(approval_id)
        assert appr.approval_status is ApprovalStatus.INVALIDATED
        assert appr.used_at is None                                   # never consumed
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
        assert "apply_result" not in _types(reopened.evidence_sink)   # never mutated
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        assert report.invalidated == ()                               # already resolved
    finally:
        reopened.close()


def test_class_2_is_idempotent_across_repeated_restarts(tmp_path, monkeypatch, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(opened.authority_store, "mark_used",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)
    opened.close()

    first = _open(tmp_path)
    baseline = _types(first.evidence_sink)
    first.close()
    for _ in range(2):
        again = _open(tmp_path)
        try:
            assert again.authority_store.get_approval(approval_id).approval_status is (
                ApprovalStatus.INVALIDATED
            )
            assert _types(again.evidence_sink) == baseline        # no records added/removed
            assert reconcile(again.authority_store, again.evidence_sink).invalidated == ()
            again.evidence_sink.verify_chain()
        finally:
            again.close()


# --- Class 3: authority consumed, outcome unknown -------------------------------------

def test_class_3_used_without_valid_apply_is_dirty_and_invalidated(tmp_path, monkeypatch, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    import hermes.session as hs

    monkeypatch.setattr(hs.GovernedSession, "execute",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)
    before = _types(opened.evidence_sink)
    opened.close()

    reopened = _open(tmp_path)
    try:
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
        assert reopened.authority_store.get_approval(approval_id).approval_status is (
            ApprovalStatus.USED                       # authority stays spent, not "unspent"
        )
        # The apply is NEVER rerun: no new records at all.
        assert _types(reopened.evidence_sink) == before
        assert "apply_result" not in _types(reopened.evidence_sink)
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        # Re-running finds it already terminal; the original pass produced the class-3 call.
        assert report.invalidated == ()
    finally:
        reopened.close()


def test_class_3_finding_says_the_outcome_is_unknown(tmp_path, monkeypatch, wired):
    """The finding must not claim the mutation succeeded or failed."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    import hermes.session as hs

    monkeypatch.setattr(hs.GovernedSession, "execute",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)

    # Classify the pre-restart shape directly, before startup resolves it.
    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert finding.class_id == 3
    assert finding.outcome == OUTCOME_INVALIDATED
    assert finding.run_id == run_id
    assert "may or may not have happened" in finding.reason
    assert "never automatically retried" in finding.reason


# --- Class 4: complete, signature-linked execution ------------------------------------

def test_class_4_complete_execution_is_clean(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert _execute(client, run_id, approval_id)["applied"] is True
    before = _types(opened.evidence_sink)
    opened.close()

    reopened = _open(tmp_path)
    try:
        assert reopened.authority_store.get_approval(approval_id).approval_status is (
            ApprovalStatus.USED
        )
        assert reopened.authority_store.get_run(run_id).status is not RunStatus.INVALIDATED
        assert _types(reopened.evidence_sink) == before       # no mutation repeated
        reopened.evidence_sink.verify_chain()                 # full signed graph verifies
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        finding = next(f for f in report.findings if f.approval_id == approval_id)
        assert (finding.class_id, finding.outcome) == (4, OUTCOME_CLEAN)
        assert report.is_clean
    finally:
        reopened.close()


def test_class_4_requires_real_signed_linkage_not_mere_presence(tmp_path, wired):
    """An apply_result that exists but is not validly linked is class 3, not class 4."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    from unittest.mock import patch

    import hermes.session as hs

    with patch.object(hs.GovernedSession, "execute",
                      side_effect=RuntimeError("crash during mutation")):
        _execute_crashing(client, run_id, approval_id)

    # An apply_result exists for the approval, but carries no execute_ref linking it to the
    # reservation. Presence alone must not be mistaken for a completed execution.
    _append(opened.evidence_sink, record_type="apply_result", run_id=run_id,
            approval_id=approval_id, payload={"applied": True}, emitter=EMITTER_OPENCODE,
            key=_OC_KEY, nonce="n-unlinked")

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert finding.class_id == 3
    assert "execute_ref" in finding.reason or "linkage" in finding.reason


# --- Class 5: evidence with no compatible authority projection ------------------------

def test_class_5_orphan_evidence_never_creates_authority(tmp_path, wired):
    client, opened = wired
    _append(opened.evidence_sink, record_type="execute_validated",
            run_id="run-orphan", approval_id="appr-orphan", nonce="n-orphan")

    before_approvals = len(opened.authority_store.snapshot_approvals())
    report = reconcile(opened.authority_store, opened.evidence_sink)

    finding = next(f for f in report.findings if f.approval_id == "appr-orphan")
    assert (finding.class_id, finding.outcome) == (5, OUTCOME_ATTENTION)
    # No authority row was synthesized from evidence, and none was deleted.
    assert len(opened.authority_store.snapshot_approvals()) == before_approvals
    assert opened.authority_store.get_approval("appr-orphan") is None
    assert opened.authority_store.get_run("run-orphan") is None
    # The orphan record is retained append-only.
    assert any(r.envelope.approval_id == "appr-orphan" for r in opened.evidence_sink.records)


def test_class_5_mismatched_run_binding_fails_closed(tmp_path, wired):
    """Evidence claiming a different run than its authority approval is never reconciled."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    _append(opened.evidence_sink, record_type="execute_validated",
            run_id="run-does-not-match", approval_id=approval_id, nonce="n-mismatch")

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert (finding.class_id, finding.outcome) == (5, OUTCOME_ATTENTION)
    assert "run_id" in finding.reason
    # Fail closed means: not silently treated as a clean class-1 approval.
    assert finding.outcome != OUTCOME_CLEAN


def test_class_5_apply_evidence_without_consumed_authority_fails_closed(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    _append(opened.evidence_sink, record_type="execute_validated", run_id=run_id,
            approval_id=approval_id, nonce="n-res")
    _append(opened.evidence_sink, record_type="apply_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCODE, key=_OC_KEY, nonce="n-app")

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert (finding.class_id, finding.outcome) == (5, OUTCOME_ATTENTION)
    assert "cannot retroactively grant" in finding.reason
    # The approval was never consumed by reconciliation — evidence grants nothing.
    assert opened.authority_store.get_approval(approval_id).used_at is None


# --- Class 6: authority consumed with no reservation ----------------------------------

def test_class_6_used_without_reservation_is_invalidated(tmp_path, wired):
    """Pre-7B.1 legacy, evidence loss, or tampering — fail closed, synthesize nothing."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    opened.authority_store.mark_used(approval_id)      # consumed, but nothing reserved
    before = _types(opened.evidence_sink)

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert (finding.class_id, finding.outcome) == (6, OUTCOME_INVALIDATED)
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
    assert _types(opened.evidence_sink) == before        # no evidence synthesized


def test_class_6_survives_restart_and_is_idempotent(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    opened.authority_store.mark_used(approval_id)
    opened.close()

    reopened = _open(tmp_path)
    try:
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
        assert reconcile(reopened.authority_store, reopened.evidence_sink).invalidated == ()
    finally:
        reopened.close()


# --- terminal runs: late evidence cannot resurrect ------------------------------------

def test_late_apply_evidence_cannot_resurrect_an_invalidated_run(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    opened.authority_store.invalidate_run(run_id)
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED

    # A valid, signed late record appends (append-only holds) ...
    _append(opened.evidence_sink, record_type="apply_result", run_id=run_id,
            approval_id=approval_id, payload={"applied": True}, emitter=EMITTER_OPENCODE,
            key=_OC_KEY, nonce="n-late")
    opened.evidence_sink.verify_chain()
    opened.close()

    # ... and reconciliation still refuses to reopen the run or recreate authority.
    reopened = _open(tmp_path)
    try:
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
        appr = reopened.authority_store.get_approval(approval_id)
        assert appr.approval_status is ApprovalStatus.INVALIDATED
        assert appr.used_at is None
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        finding = next(f for f in report.findings if f.approval_id == approval_id)
        assert finding.outcome == OUTCOME_ATTENTION
        assert "stays invalidated" in finding.reason
    finally:
        reopened.close()


# --- ambiguity fails closed ------------------------------------------------------------

def test_duplicate_reservations_fail_closed_and_are_never_normalized(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    for i in (1, 2):
        _append(opened.evidence_sink, record_type="execute_validated", run_id=run_id,
                approval_id=approval_id, nonce=f"n-dup-{i}")

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert (finding.class_id, finding.outcome) == (5, OUTCOME_ATTENTION)
    assert "ambiguous" in finding.reason
    # Not resolved by picking one, and both records are still present.
    reservations = [r for r in opened.evidence_sink.records
                    if r.envelope.record_type == "execute_validated"
                    and r.envelope.approval_id == approval_id]
    assert len(reservations) == 2


def test_multiple_apply_results_are_not_treated_as_complete(tmp_path, monkeypatch, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert _execute(client, run_id, approval_id)["applied"] is True
    # A second, conflicting apply_result appears for the same approval.
    _append(opened.evidence_sink, record_type="apply_result", run_id=run_id,
            approval_id=approval_id, payload={"applied": False}, emitter=EMITTER_OPENCODE,
            key=_OC_KEY, nonce="n-second-apply")

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in report.findings if f.approval_id == approval_id)
    assert finding.class_id == 3          # NOT class 4
    assert "ambiguous" in finding.reason


# --- unable to inspect is not clean ----------------------------------------------------

class _UnreadableSink:
    sink_id = "gateway-evidence"

    @property
    def records(self):
        raise OSError("evidence chain unreadable (simulated I/O failure)")


class _UnreadableAuthority:
    def snapshot_approvals(self):
        raise OSError("authority store unreadable (simulated I/O failure)")

    def get_run(self, run_id):
        return None

    def invalidate_run(self, run_id):
        raise AssertionError("must not act after a failed inspection")


def test_unreadable_evidence_is_not_classified_clean(wired):
    _, opened = wired
    with pytest.raises(ReconciliationError) as exc:
        reconcile(opened.authority_store, _UnreadableSink())
    assert "could not be read" in str(exc.value)


def test_unreadable_authority_is_not_classified_clean(wired):
    _, opened = wired
    with pytest.raises(ReconciliationError) as exc:
        reconcile(_UnreadableAuthority(), opened.evidence_sink)
    assert "could not be enumerated" in str(exc.value)


def test_unreadable_state_aborts_startup_as_stateerror(tmp_path, monkeypatch, wired):
    """A failed reconciliation must fail startup closed, not start a degraded runtime."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    _approve(client, run_id, plan_hash)
    opened.close()

    def boom(*a, **k):
        raise ReconciliationError("simulated inspection failure")

    monkeypatch.setattr(reconciliation, "reconcile", boom)
    with pytest.raises(StateError) as exc:
        _open(tmp_path)
    assert "failed closed" in str(exc.value)

    # Fail-closed startup must not leak ownership: a clean open still succeeds afterwards.
    monkeypatch.undo()
    ok = _open(tmp_path)
    ok.close()


# --- reconciliation cannot execute anything -------------------------------------------

def test_reconciliation_module_has_no_executor_access():
    """Structural: the module must not import an execution path."""
    import inspect

    src = inspect.getsource(reconciliation)
    for forbidden in (
        "session.execute", "GovernedSession", "CodeActWorker", "opencode_sandbox",
        "run_phase", "hermes", "complete(", "delegate(",
    ):
        assert forbidden not in src, f"reconciliation must not reference {forbidden!r}"


def test_reconciliation_calls_no_mutation_entry_point(tmp_path, monkeypatch, wired):
    """Behavioral: a pass over a dirty database touches no execution entry point."""
    import hermes.session as hs

    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(opened.authority_store, "mark_used",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)
    monkeypatch.undo()
    opened.close()

    called: list[str] = []
    monkeypatch.setattr(hs.GovernedSession, "execute",
                        lambda *a, **k: called.append("execute"))
    monkeypatch.setattr(hs.GovernedSession, "plan", lambda *a, **k: called.append("plan"))

    reopened = _open(tmp_path)          # startup reconciliation runs here
    try:
        assert called == [], f"reconciliation invoked execution: {called}"
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
    finally:
        reopened.close()


def test_reconciliation_creates_and_deletes_nothing(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert _execute(client, run_id, approval_id)["applied"] is True
    approvals_before = {a.approval_id for a in opened.authority_store.snapshot_approvals()}
    evidence_before = [r.envelope.evidence_id for r in opened.evidence_sink.records]
    opened.close()

    reopened = _open(tmp_path)
    try:
        reconcile(reopened.authority_store, reopened.evidence_sink)
        approvals_after = {a.approval_id for a in reopened.authority_store.snapshot_approvals()}
        evidence_after = [r.envelope.evidence_id for r in reopened.evidence_sink.records]
        assert approvals_after == approvals_before   # none created, none deleted
        assert evidence_after == evidence_before     # append-only, nothing rewritten
        assert approval_id in approvals_after
    finally:
        reopened.close()


# --- reporting ------------------------------------------------------------------------

def test_report_exposes_the_fields_operators_need(tmp_path, monkeypatch, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(opened.authority_store, "mark_used",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)

    report = reconcile(opened.authority_store, opened.evidence_sink)
    finding = report.by_class(2)[0]
    assert finding.run_id == run_id and finding.approval_id == approval_id
    assert finding.class_id == 2 and finding.outcome == OUTCOME_INVALIDATED
    assert finding.reason
    # Renders safely for logs: identifiers and prose only, never payloads or key material.
    rendered = str(finding)
    assert run_id in rendered and approval_id in rendered
    for secret in (_GW_HEX, _OC_HEX, _OWNER_TOKEN, TOKENS["hermes"]):
        assert secret not in rendered


def test_memory_backend_reconciles_to_an_empty_clean_report():
    from private_ai_gateway.approvals import ApprovalStore

    report = reconcile(ApprovalStore(), None)     # no evidence plane configured
    assert report.findings == () and report.is_clean
