"""Full startup validation for the durable stores (Step 7A.1).

Both stores validate their whole database at construction and fail closed — the constructor
raises rather than opening and surfacing corruption lazily on a later read. Authority runs
``integrity_check`` + ``foreign_key_check`` and typed-reconstructs every run/approval (enums,
JSON tuples, timestamps, strict booleans, binding consistency, autonomy bounds); evidence adds a
redundant identity-column/envelope cross-check. Timestamps normalize to UTC. Partial-startup
failures release every resource, and a clean reopen succeeds once the fault is removed.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from private_ai_gateway.approvals import _now
from private_ai_gateway.approvals_sqlite import (
    SqliteApprovalStore,
    _dt_to_text,
    _text_to_dt,
)
from private_ai_gateway.sqlite_util import DatabaseOwnership, DurableStoreError

HASH_A = "sha256:" + "a" * 64


def _authority_with_approval(tmp_path):
    """Create authority.sqlite3 with one run + one pending approval; return (path, approval_id)."""
    path = str(tmp_path / "authority.sqlite3")
    s = SqliteApprovalStore(path)
    s.create_run(
        run_id="r1", principal_id="hermes", canonical_plan_hash=HASH_A,
        effective_autonomy=2, policy_ceiling=3,
    )
    appr = s.create_pending_approval("r1", target_resources=("a.py",))
    s.close()
    return path, appr.approval_id


def _corrupt(path, sql, params=()):
    raw = sqlite3.connect(path)
    raw.execute(sql, params)
    raw.commit()
    raw.close()


# --- authority startup: typed-field corruption fails at the constructor --------------
def test_malformed_boolean_fails_at_constructor(tmp_path):
    path, aid = _authority_with_approval(tmp_path)
    _corrupt(path, "UPDATE approvals SET single_use=2 WHERE approval_id=?", (aid,))
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_malformed_timestamp_fails_at_constructor(tmp_path):
    path, aid = _authority_with_approval(tmp_path)
    _corrupt(path, "UPDATE approvals SET created_at='not-a-time' WHERE approval_id=?", (aid,))
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_naive_stored_timestamp_fails_at_constructor(tmp_path):
    path, aid = _authority_with_approval(tmp_path)
    _corrupt(path, "UPDATE approvals SET created_at='2026-07-05T00:00:00' WHERE approval_id=?",
             (aid,))
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_malformed_json_tuple_fails_at_constructor(tmp_path):
    path, aid = _authority_with_approval(tmp_path)
    _corrupt(path, "UPDATE approvals SET target_resources='{not json' WHERE approval_id=?",
             (aid,))
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_foreign_key_violation_fails_at_constructor(tmp_path):
    path, _ = _authority_with_approval(tmp_path)
    # Point the approval at a non-existent run (raw connection: FK enforcement off).
    _corrupt(path, "UPDATE approvals SET run_id='ghost'")
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_binding_mismatch_fails_at_constructor(tmp_path):
    path, aid = _authority_with_approval(tmp_path)
    # Approval's principal no longer matches its run's principal.
    _corrupt(path, "UPDATE approvals SET principal_id='someone-else' WHERE approval_id=?", (aid,))
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_impossible_autonomy_bounds_fail_at_constructor(tmp_path):
    path, _ = _authority_with_approval(tmp_path)
    _corrupt(path, "UPDATE runs SET effective_autonomy=9 WHERE run_id='r1'")
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


# --- evidence startup: identity-column/envelope mismatch -----------------------------
def test_evidence_identity_column_mismatch_fails_at_constructor(tmp_path):
    from openclaw.sink import EmitterKeyRegistry
    from openclaw.sink_sqlite import SqliteEvidenceSink
    from openclaw.sqlite_util import DurableStoreError as EvErr
    from tests.unit.test_durable_evidence import _registry, _signed

    path = str(tmp_path / "evidence.sqlite3")
    s = SqliteEvidenceSink("sink-durable-1", _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    # Tamper only the redundant evidence_id column; the signed envelope still says otherwise.
    _corrupt(path, "UPDATE records SET evidence_id=? WHERE seq=0", ("ev-" + "b" * 32,))
    with pytest.raises(EvErr):
        SqliteEvidenceSink("sink-durable-1", _registry(), path=path)
    assert EmitterKeyRegistry  # imported for symmetry with sibling tests


# --- timestamp UTC normalization -----------------------------------------------------
def test_non_utc_aware_timestamp_persists_and_reconstructs_as_utc(tmp_path):
    path = str(tmp_path / "authority.sqlite3")
    s = SqliteApprovalStore(path)
    s.create_run(
        run_id="r1", principal_id="p", canonical_plan_hash=HASH_A,
        effective_autonomy=1, policy_ceiling=3,
    )
    appr = s.create_pending_approval("r1")
    # Decide with a non-UTC aware instant (+05:00).
    east = timezone(timedelta(hours=5))
    decided = datetime(2026, 7, 5, 12, 0, 0, tzinfo=east)
    s.decide_approval(appr.approval_id, decision="approve", approver="owner", now=decided)
    s.close()

    s2 = SqliteApprovalStore(path)
    got = s2.get_approval(appr.approval_id).decided_at
    assert got.utcoffset() == timedelta(0)  # stored/reconstructed as UTC
    assert got == decided  # same instant preserved
    s2.close()


def test_dt_helpers_reject_naive_and_roundtrip_deterministically():
    with pytest.raises(DurableStoreError):
        _dt_to_text(datetime(2026, 7, 5, 0, 0, 0))  # naive rejected
    with pytest.raises(DurableStoreError):
        _text_to_dt("2026-07-05T00:00:00")  # stored naive rejected
    utc = _now()
    once = _dt_to_text(utc)
    twice = _dt_to_text(_text_to_dt(once))
    assert once == twice  # deterministic UTC round trip
    assert _text_to_dt(once) == utc  # instant preserved


# --- partial-startup cleanup ---------------------------------------------------------
def test_clean_reopen_succeeds_after_fault_removed(tmp_path):
    path, _ = _authority_with_approval(tmp_path)
    _corrupt(path, "UPDATE runs SET status='bogus' WHERE run_id='r1'")
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)
    # Failed construction released ownership + connection; fix and reopen cleanly.
    _corrupt(path, "UPDATE runs SET status='open' WHERE run_id='r1'")
    s = SqliteApprovalStore(path)
    assert s.get_run("r1") is not None
    s.close()


def test_authority_closed_when_evidence_init_fails(tmp_path):
    from openclaw.sink_sqlite import SqliteEvidenceSink
    from openclaw.sqlite_util import DurableStoreError as ClawDurableError
    from tests.unit.test_durable_evidence import _registry

    from private_ai_gateway.state import (
        AUTHORITY_DB_FILENAME,
        EVIDENCE_DB_FILENAME,
        StateConfig,
        open_backend,
    )

    auth_path = str(tmp_path / AUTHORITY_DB_FILENAME)
    ev_path = str(tmp_path / EVIDENCE_DB_FILENAME)
    SqliteApprovalStore(auth_path).close()
    SqliteEvidenceSink("sink-durable-1", _registry(), path=ev_path).close()
    # Corrupt only the evidence database's schema version -> its init fails at open.
    _corrupt(ev_path, "UPDATE schema_meta SET value='999' WHERE key='schema_version'")

    cfg = StateConfig.from_env(
        {"PRIVATE_AI_STATE_BACKEND": "sqlite", "PRIVATE_AI_STATE_DIR": str(tmp_path)}
    )
    # Evidence init raises the verifier package's own durable-store error; it propagates.
    with pytest.raises((DurableStoreError, ClawDurableError)):
        open_backend(cfg)
    # The authority store opened first must have been closed: its lock is free again.
    own = DatabaseOwnership(auth_path)
    own.release()
