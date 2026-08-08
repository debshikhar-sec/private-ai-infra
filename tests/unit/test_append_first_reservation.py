"""Step 7B.1 — append-first execution reservation.

The execute path now runs ``validate -> reserve (execute_validated) -> mark_used ->
mutate``, so the durable record that explains an execution exists *before* the authority
that permits it is spent. These tests prove the four things that makes true:

  * **Uniqueness.** At most one ``execute_validated`` reservation can ever exist for one
    ``approval_id`` — sequentially, concurrently, and across a restart. A second one would
    make OpenClaw's ``find_unique_record`` fail the run as ``REF_AMBIGUOUS``, so this is a
    correctness property of the signed graph, not tidiness.
  * **Crash shapes.** C1 (crash before the reservation) leaves the approval cleanly usable;
    C2 (crash after the reservation, before consumption) is resolved fail-closed by
    invalidation at startup, idempotently.
  * **Distinguishability.** C3 and C4 produce durable shapes a later reconciliation can
    tell apart, without classifying them here.
  * **Emit failure.** A reservation that cannot be appended refuses *before* anything is
    consumed, leaving the approval APPROVED and reusable — the cost 7B.0 accepted and 7B.1
    removes.

Deterministic throughout: crashes are injected by monkeypatching the store/sink boundary,
restarts are real close/reopen cycles over a temp state dir, and the concurrency test
synchronizes with barriers and events. No sleeps.
"""

from __future__ import annotations

import threading

import pytest
from openclaw.sink import EMITTER_GATEWAY, find_unique_record

from private_ai_gateway import app as gw
from private_ai_gateway import orchestration
from private_ai_gateway.approvals import ApprovalError, ApprovalStatus, RunStatus
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.reconciliation import reconcile
from private_ai_gateway.state import StateConfig, open_backend

_GW_HEX = "aa" * 32
_OC_HEX = "bb" * 32
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
    """The durable-evidence runtime exactly as app startup configures it."""
    from openclaw import assurance

    install_demo_plane(gw)
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_GATEWAY", _GW_HEX)
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_OPENCODE", _OC_HEX)
    opened = _open(tmp_path)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "APPROVAL_STORE", opened.authority_store)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", bytes.fromhex(_GW_HEX))
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", True, raising=False)
    yield gw.app.test_client(), opened
    try:
        opened.close()
    except Exception:  # noqa: BLE001 — a test may have closed it already
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
    """Drive an execute whose injected fault aborts the path mid-flight.

    Simulating a crash means the remaining steps never run. The gateway turns the injected
    exception into a 500, so the request is *observed* as a failure rather than raising out
    of the test client — what the test then asserts on is the durable state left behind.
    """
    resp = client.post(
        "/v1/orchestrate", headers=HERMES,
        json={"objective": _OBJ, "phase": "execute",
              "run_id": run_id, "approval_id": approval_id},
    )
    assert resp.status_code == 500, "expected the injected fault to abort the execute"
    return resp


def _reservations(sink, approval_id=None):
    out = []
    for r in sink.records:
        env = r.envelope
        if env.record_type != "execute_validated":
            continue
        if approval_id is not None and env.approval_id != approval_id:
            continue
        out.append(r)
    return out


def _types(sink):
    return [r.envelope.record_type for r in sink.records]


# --- ordering ------------------------------------------------------------------------

def test_reservation_is_appended_before_authority_is_consumed(wired, monkeypatch):
    """The defining 7B.1 property, observed at the consumption boundary."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    store = opened.authority_store
    original = store.mark_used
    seen = {}

    def spy(aid, **kw):
        # At the instant authority is spent, the durable reservation must already exist.
        seen["reservations_at_consume"] = len(_reservations(opened.evidence_sink, aid))
        return original(aid, **kw)

    monkeypatch.setattr(store, "mark_used", spy)
    out = _execute(client, run_id, approval_id)
    assert out["applied"] is True and out["verdict"] == "PASS"
    assert seen["reservations_at_consume"] == 1


def test_full_chain_and_shape_after_successful_execute(wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    out = _execute(client, run_id, approval_id)
    assert out["applied"] is True
    assert _types(opened.evidence_sink) == [
        "approval_decided", "execute_validated", "apply_result",
    ]
    opened.evidence_sink.verify_chain()


# --- C1: crash BEFORE the reservation -------------------------------------------------

def test_c1_crash_before_reservation_leaves_approval_usable(tmp_path, monkeypatch, wired):
    """Nothing was reserved, nothing consumed: the approval must survive a restart intact."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    def boom(*a, **k):
        raise RuntimeError("crash: process died before the reservation was appended")

    monkeypatch.setattr(orchestration, "_emit_execute_validated", boom)
    _execute_crashing(client, run_id, approval_id)

    # Durable state at the crash: approval still APPROVED, no reservation.
    assert opened.authority_store.get_approval(approval_id).approval_status is (
        ApprovalStatus.APPROVED
    )
    assert _reservations(opened.evidence_sink, approval_id) == []
    opened.close()

    # Restart: C1 is CLEAN — startup changes nothing and the approval stays usable.
    reopened = _open(tmp_path)
    try:
        appr = reopened.authority_store.get_approval(approval_id)
        assert appr.approval_status is ApprovalStatus.APPROVED
        assert appr.used_at is None
        assert reopened.authority_store.get_run(run_id).status is not RunStatus.INVALIDATED
        assert _reservations(reopened.evidence_sink, approval_id) == []
    finally:
        reopened.close()


# --- C2: crash AFTER the reservation, BEFORE consumption ------------------------------

def test_c2_crash_after_reservation_invalidates_on_restart(tmp_path, monkeypatch, wired):
    """The window 7B.1 exists to make classifiable — resolved by invalidation, not consume."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    def boom(*a, **k):
        raise RuntimeError("crash: process died after reserving, before mark_used")

    monkeypatch.setattr(opened.authority_store, "mark_used", boom)
    _execute_crashing(client, run_id, approval_id)

    # The C2 shape: reservation present, authority NOT yet consumed.
    assert len(_reservations(opened.evidence_sink, approval_id)) == 1
    assert opened.authority_store.get_approval(approval_id).approval_status is (
        ApprovalStatus.APPROVED
    )
    assert "apply_result" not in _types(opened.evidence_sink)
    opened.close()

    # Restart: fail closed. The run and its still-active approval are invalidated; the
    # mutation provably never began, and another attempt needs fresh authority.
    reopened = _open(tmp_path)
    try:
        appr = reopened.authority_store.get_approval(approval_id)
        assert appr.approval_status is ApprovalStatus.INVALIDATED
        assert appr.used_at is None                      # never consumed
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
        assert len(_reservations(reopened.evidence_sink, approval_id)) == 1  # not retried
        assert "apply_result" not in _types(reopened.evidence_sink)          # never mutated
    finally:
        reopened.close()


def test_c2_resolution_is_idempotent_across_repeated_restarts(tmp_path, monkeypatch, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(opened.authority_store, "mark_used",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)
    opened.close()

    first = _open(tmp_path)
    first_types = _types(first.evidence_sink)
    first.close()

    # A second and third restart must be pure no-ops: same states, same chain, no new
    # records, and no further invalidation work reported.
    for _ in range(2):
        again = _open(tmp_path)
        try:
            assert again.authority_store.get_approval(approval_id).approval_status is (
                ApprovalStatus.INVALIDATED
            )
            assert _types(again.evidence_sink) == first_types
            # Re-running the pass directly reports nothing left to resolve. Since 7B.2
            # the class-2 resolver IS the general reconciler, so an already-resolved
            # database reports no further invalidation.
            assert reconcile(again.authority_store, again.evidence_sink).invalidated == ()
            again.evidence_sink.verify_chain()
        finally:
            again.close()


def test_c2_invalidated_approval_cannot_be_executed_after_restart(tmp_path, monkeypatch, wired):
    """The invalidation has teeth: no second reservation can follow a resolved C2."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(opened.authority_store, "mark_used",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    _execute_crashing(client, run_id, approval_id)
    opened.close()

    reopened = _open(tmp_path)
    try:
        monkeypatch.setattr(gw, "APPROVAL_STORE", reopened.authority_store)
        monkeypatch.setattr(gw, "EVIDENCE_SINK", reopened.evidence_sink)
        out = _execute(gw.app.test_client(), run_id, approval_id)
        assert out["applied"] is False
        assert out["refusal_reason"] == "invalidated"
        # Still exactly one reservation: the refused attempt appended nothing.
        assert len(_reservations(reopened.evidence_sink, approval_id)) == 1
    finally:
        reopened.close()


# --- C3 / C4: the durable shapes 7B.1 produces, as classified by 7B.2 ------------------

def test_c3_shape_is_used_plus_reservation_without_apply_result(tmp_path, monkeypatch, wired):
    """Crash after consumption, before the apply completes: possibly-dirty, never retried.

    7B.1's job is producing a shape a reconciler can *tell apart*; since 7B.2 that shape is
    classified dirty and the run is invalidated (see `test_reconciliation.py` for the
    classifier's own coverage).
    """
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    import hermes.session as hs

    def boom(*a, **k):
        raise RuntimeError("crash: process died during the mutation")

    monkeypatch.setattr(hs.GovernedSession, "execute", boom)
    _execute_crashing(client, run_id, approval_id)
    opened.close()

    reopened = _open(tmp_path)
    try:
        appr = reopened.authority_store.get_approval(approval_id)
        assert appr.approval_status is ApprovalStatus.USED          # authority WAS spent
        assert len(_reservations(reopened.evidence_sink, approval_id)) == 1
        assert "apply_result" not in _types(reopened.evidence_sink)  # outcome unknown
        # The shape is distinguishable from C4, and 7B.2 fails it closed at the run level.
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
    finally:
        reopened.close()


def test_c4_shape_is_used_plus_complete_chain(tmp_path, wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert _execute(client, run_id, approval_id)["applied"] is True
    opened.close()

    reopened = _open(tmp_path)
    try:
        assert reopened.authority_store.get_approval(approval_id).approval_status is (
            ApprovalStatus.USED
        )
        assert _types(reopened.evidence_sink) == [
            "approval_decided", "execute_validated", "apply_result",
        ]
        # A complete run is class 4 — left alone by reconciliation.
        assert reopened.authority_store.get_run(run_id).status is not RunStatus.INVALIDATED
        reopened.evidence_sink.verify_chain()
    finally:
        reopened.close()


# --- emit failure now costs nothing ---------------------------------------------------

def test_reservation_emit_failure_leaves_approval_approved_and_reusable(wired, monkeypatch):
    """7B.0 spent the approval when the emit failed; 7B.1 must not."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    calls = {"n": 0}
    real_emit = orchestration._emit_execute_validated

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return orchestration._GatewayEmit(False)      # required + failed -> refuse
        return real_emit(*a, **k)

    monkeypatch.setattr(orchestration, "_emit_execute_validated", flaky)
    refused = _execute(client, run_id, approval_id)
    assert refused["applied"] is False
    assert refused["refusal_reason"] == "authorization_evidence_unavailable"
    assert refused["chain"] == []                          # nothing delegated or mutated

    appr = opened.authority_store.get_approval(approval_id)
    assert appr.approval_status is ApprovalStatus.APPROVED  # NOT spent
    assert appr.used_at is None

    # And the very same approval still works once the evidence plane recovers.
    ok = _execute(client, run_id, approval_id)
    assert ok["applied"] is True and ok["verdict"] == "PASS"
    assert len(_reservations(opened.evidence_sink, approval_id)) == 1


# --- duplicate execution: sequential and concurrent ------------------------------------

def test_sequential_duplicate_execute_adds_no_second_reservation(wired):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert _execute(client, run_id, approval_id)["applied"] is True

    second = _execute(client, run_id, approval_id)
    assert second["applied"] is False
    assert second["refusal_reason"] == "replay"
    assert len(_reservations(opened.evidence_sink, approval_id)) == 1


def test_concurrent_execute_produces_exactly_one_reservation(wired, monkeypatch):
    """The race the critical section exists to prevent, forced open deterministically.

    Both threads are held at a barrier *inside* the execute path, after the digest work and
    immediately before the reservation, so they contend on precisely the validate ->
    reserve -> consume window. Without synchronization both would validate as APPROVED and
    each append a reservation; with it, one wins outright and the other is refused.
    """
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    at_boundary = threading.Barrier(2, timeout=10)
    real_validate = opened.authority_store.validate_for_execute

    def contending_validate(*a, **k):
        # Rendezvous both threads before either can validate, then let them race.
        try:
            at_boundary.wait()
        except threading.BrokenBarrierError:  # pragma: no cover - only on timeout
            pass
        return real_validate(*a, **k)

    monkeypatch.setattr(opened.authority_store, "validate_for_execute", contending_validate)

    results: list[dict] = []
    results_lock = threading.Lock()

    def run_execute():
        out = _execute(gw.app.test_client(), run_id, approval_id)
        with results_lock:
            results.append(out)

    threads = [threading.Thread(target=run_execute) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert all(not t.is_alive() for t in threads), "execute threads did not finish"

    assert len(results) == 2
    applied = [r for r in results if r.get("applied")]
    refused = [r for r in results if not r.get("applied")]

    # Exactly one execution proceeded; the loser is a governed refusal, never a 500.
    assert len(applied) == 1, f"expected one winner, got {[r.get('verdict') for r in results]}"
    assert len(refused) == 1
    assert refused[0]["verdict"] == "REFUSED"
    assert refused[0]["refusal_reason"] == "replay"
    assert refused[0]["chain"] == []

    # Exactly ONE reservation for this approval — the property that keeps the signed graph
    # unambiguous. A duplicate here is what makes OpenClaw fail an otherwise-valid run.
    assert len(_reservations(opened.evidence_sink, approval_id)) == 1

    # Authority consumed exactly once, chain intact, and one apply_result.
    appr = opened.authority_store.get_approval(approval_id)
    assert appr.approval_status is ApprovalStatus.USED
    assert _types(opened.evidence_sink).count("apply_result") == 1
    opened.evidence_sink.verify_chain()

    # The verifier's own locator agrees the authority record is unique.
    rec = find_unique_record(
        opened.evidence_sink.records, emitter=EMITTER_GATEWAY,
        record_type="execute_validated", run_id=run_id, approval_id=approval_id,
    )
    assert rec.envelope.approval_id == approval_id


def test_concurrent_execute_facts_survive_restart(tmp_path, wired, monkeypatch):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    at_boundary = threading.Barrier(2, timeout=10)
    real_validate = opened.authority_store.validate_for_execute

    def contending_validate(*a, **k):
        try:
            at_boundary.wait()
        except threading.BrokenBarrierError:  # pragma: no cover
            pass
        return real_validate(*a, **k)

    monkeypatch.setattr(opened.authority_store, "validate_for_execute", contending_validate)
    threads = [
        threading.Thread(target=lambda: _execute(gw.app.test_client(), run_id, approval_id))
        for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    opened.close()

    reopened = _open(tmp_path)
    try:
        assert len(_reservations(reopened.evidence_sink, approval_id)) == 1
        assert reopened.authority_store.get_approval(approval_id).approval_status is (
            ApprovalStatus.USED
        )
        assert _types(reopened.evidence_sink).count("apply_result") == 1
        reopened.evidence_sink.verify_chain()
        # A completed run is not swept by the C2 pass on reopen.
        assert reopened.authority_store.get_run(run_id).status is not RunStatus.INVALIDATED
    finally:
        reopened.close()


# --- the critical section itself ------------------------------------------------------

def test_reservation_lock_registry_does_not_leak(wired):
    client, opened = wired
    for _ in range(3):
        run_id, plan_hash = _plan(client)
        approval_id = _approve(client, run_id, plan_hash)
        assert _execute(client, run_id, approval_id)["applied"] is True
    # Reference-counted entries are removed once the last holder leaves.
    assert orchestration._RESERVATION_LOCKS == {}
    assert orchestration._RESERVATION_WAITERS == {}


def test_missing_approval_id_refuses_without_taking_a_lock(wired):
    client, opened = wired
    run_id, _ = _plan(client)
    out = _execute(client, run_id, "")
    assert out["applied"] is False
    assert out["refusal_reason"] == "approval_missing"
    assert _reservations(opened.evidence_sink) == []
    assert orchestration._RESERVATION_LOCKS == {}


def test_mark_used_raising_approval_error_is_a_governed_replay(wired, monkeypatch):
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)

    def already_consumed(*a, **k):
        raise ApprovalError("approval is not in an approved state (used)")

    monkeypatch.setattr(opened.authority_store, "mark_used", already_consumed)
    out = _execute(client, run_id, approval_id)
    assert out["applied"] is False
    assert out["refusal_reason"] == "replay"
    assert out["chain"] == []
