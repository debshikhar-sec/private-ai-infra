"""Approval store binding tests — enforces docs/run-id-approval-design.md (storage half).

Covers the status machine, dual run_id+hash binding, expiry, single-use replay,
rejection-as-governed-outcome, restart invalidation (fresh store), the autonomy ceiling,
and the structural exclusion of a model-text approver / body field. No disk persistence.
"""

import builtins
import inspect
from datetime import timedelta

import pytest

from private_ai_gateway import approvals
from private_ai_gateway.approvals import (
    ApprovalError,
    ApprovalStatus,
    ApprovalStore,
    RunStatus,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


def _store_with_run(hash_=HASH_A, *, run_id="run-1", eff=3, ceiling=3):
    store = ApprovalStore()
    store.create_run(
        run_id=run_id,
        principal_id="hermes",
        canonical_plan_hash=hash_,
        effective_autonomy=eff,
        policy_ceiling=ceiling,
    )
    return store


def _approved(store, run_id="run-1", **decide):
    appr = store.create_pending_approval(run_id)
    store.decide_approval(appr.approval_id, decision="approve", approver="owner", **decide)
    return appr


# 1 — create_run stores run_id and canonical_plan_hash
def test_create_run_stores_run_and_hash():
    store = _store_with_run()
    run = store.get_run("run-1")
    assert run is not None
    assert run.run_id == "run-1"
    assert run.canonical_plan_hash == HASH_A
    assert run.status is RunStatus.OPEN


# 2 — approval binds approval_id, run_id, canonical_plan_hash
def test_create_approval_binds_identifiers():
    store = _store_with_run()
    appr = store.create_pending_approval("run-1")
    assert appr.approval_id.startswith("appr-")
    assert appr.run_id == "run-1"
    assert appr.canonical_plan_hash == HASH_A
    assert appr.approval_status is ApprovalStatus.PENDING


# 3 — approved approval validates for matching run_id and hash
def test_approved_validates_on_match():
    store = _store_with_run()
    appr = _approved(store)
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert res.ok
    assert res.record is appr


# 4 — same hash, different run_id refuses
def test_same_hash_different_run_refuses():
    store = _store_with_run()
    # a second run carrying the *same* canonical hash
    store.create_run(
        run_id="run-2", principal_id="hermes", canonical_plan_hash=HASH_A,
        effective_autonomy=3, policy_ceiling=3,
    )
    appr = _approved(store, run_id="run-1")
    res = store.validate_for_execute("run-2", appr.approval_id, HASH_A)
    assert not res.ok
    assert res.reason == approvals.REASON_RUN_MISMATCH


# 5 — same run_id, different hash refuses
def test_same_run_different_hash_refuses():
    store = _store_with_run()
    appr = _approved(store)
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_B)
    assert not res.ok
    assert res.reason == approvals.REASON_HASH_MISMATCH


# 6 — missing / unknown approval refuses
def test_missing_and_unknown_approval_refuse():
    store = _store_with_run()
    res_missing = store.validate_for_execute("run-1", None, HASH_A)
    assert not res_missing.ok and res_missing.reason == approvals.REASON_APPROVAL_MISSING
    res_unknown = store.validate_for_execute("run-1", "appr-does-not-exist", HASH_A)
    assert not res_unknown.ok and res_unknown.reason == approvals.REASON_APPROVAL_MISSING


# 7 — rejected approval refuses and preserves rejection_reason
def test_rejected_is_governed_outcome():
    store = _store_with_run()
    appr = store.create_pending_approval("run-1")
    decided = store.decide_approval(
        appr.approval_id, decision="reject", approver="owner", reason="scope too broad"
    )
    assert decided.approval_status is ApprovalStatus.REJECTED
    assert decided.rejection_reason == "scope too broad"
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_REJECTED


# 8 — expired approval refuses and transitions to expired
def test_expired_refuses_and_transitions():
    store = _store_with_run()
    appr = _approved(store, ttl_seconds=60)
    future = appr.expires_at + timedelta(seconds=1)
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_A, now=future)
    assert not res.ok and res.reason == approvals.REASON_EXPIRED
    assert store.get_approval(appr.approval_id).approval_status is ApprovalStatus.EXPIRED


# 9 — used single-use approval refuses replay
def test_single_use_replay_refused():
    store = _store_with_run()
    appr = _approved(store)
    assert store.validate_for_execute("run-1", appr.approval_id, HASH_A).ok
    store.mark_used(appr.approval_id)
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_REPLAY
    assert store.get_approval(appr.approval_id).approval_status is ApprovalStatus.USED


# 10 — invalidated approval refuses
def test_invalidated_run_refuses():
    store = _store_with_run()
    appr = _approved(store)
    store.invalidate_run("run-1")
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert not res.ok
    assert res.reason in (approvals.REASON_INVALIDATED,)
    assert store.get_approval(appr.approval_id).approval_status is ApprovalStatus.INVALIDATED


# 11 — fresh store models a restart; old ids are unknown/refused
def test_fresh_store_models_restart():
    store = _store_with_run()
    appr = _approved(store)
    assert store.validate_for_execute("run-1", appr.approval_id, HASH_A).ok

    restarted = ApprovalStore()
    res = restarted.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_RUN_NOT_FOUND

    # clear() on the same instance is equivalent
    store.clear()
    res2 = store.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert not res2.ok and res2.reason == approvals.REASON_RUN_NOT_FOUND


# 12 — approval cannot grant effective_autonomy above the ceiling
def test_autonomy_cannot_exceed_ceiling():
    store = ApprovalStore()
    with pytest.raises(ApprovalError):
        store.create_run(
            run_id="run-x", principal_id="hermes", canonical_plan_hash=HASH_A,
            effective_autonomy=6, policy_ceiling=3,
        )


# 13 — a model-text-like approver / body field is not part of the store API
def test_no_model_text_approver_field():
    store = _store_with_run()
    create_sig = inspect.signature(ApprovalStore.create_pending_approval)
    assert "approver" not in create_sig.parameters
    assert "body" not in create_sig.parameters

    # approver is a required, explicit argument at decision time
    decide_sig = inspect.signature(ApprovalStore.decide_approval)
    assert "approver" in decide_sig.parameters

    # you cannot smuggle an approver in at creation time
    with pytest.raises(TypeError):
        store.create_pending_approval("run-1", approver="evil")


# 14 — no disk persistence: a full cycle runs with builtins.open disabled
def test_no_disk_persistence(monkeypatch):
    def _no_open(*args, **kwargs):
        raise AssertionError("approval store must not touch disk")

    monkeypatch.setattr(builtins, "open", _no_open)
    store = ApprovalStore()
    store.create_run(
        run_id="run-nd", principal_id="hermes", canonical_plan_hash=HASH_A,
        effective_autonomy=2, policy_ceiling=3,
    )
    appr = store.create_pending_approval("run-nd")
    store.decide_approval(appr.approval_id, decision="approve", approver="owner")
    res = store.validate_for_execute("run-nd", appr.approval_id, HASH_A)
    assert res.ok
    store.mark_used(appr.approval_id)
    assert store.get_approval(appr.approval_id).approval_status is ApprovalStatus.USED


# Extra — pending (undecided) approval refuses with not_approved
def test_pending_refuses_not_approved():
    store = _store_with_run()
    appr = store.create_pending_approval("run-1")
    res = store.validate_for_execute("run-1", appr.approval_id, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_NOT_APPROVED


# Extra — deciding an already-decided approval fails closed
def test_double_decision_fails_closed():
    store = _store_with_run()
    appr = _approved(store)
    with pytest.raises(ApprovalError):
        store.decide_approval(appr.approval_id, decision="approve", approver="owner")
