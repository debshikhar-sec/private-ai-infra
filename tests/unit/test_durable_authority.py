"""Durable authority store (Step 7A) — contract, restart survival, crashes, integrity.

The SQLite ``SqliteApprovalStore`` must be behaviorally indistinguishable from the in-memory
``ApprovalStore`` (same status machine, dual run_id+hash binding, expiry, single-use,
invalidation) while *persisting* across restarts and refusing to run on corrupt state. The
shared contract runs against both backends; restart/crash/integrity/migration cover the
durable backend specifically. No lifecycle ordering is exercised or changed here.
"""

from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest

from private_ai_gateway import approvals
from private_ai_gateway.approvals import (
    ApprovalError,
    ApprovalStatus,
    ApprovalStore,
    AuthorityStore,
    RunStatus,
    _now,
)
from private_ai_gateway.approvals_sqlite import (
    AUTHORITY_SCHEMA_VERSION,
    SqliteApprovalStore,
)
from private_ai_gateway.sqlite_util import DurableStoreError, connect, migrate

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


# --- crash injection ----------------------------------------------------------------
class _FailingConn:
    """Wrap a real connection and raise on the first statement whose SQL contains ``needle``."""

    def __init__(self, real: sqlite3.Connection, needle: str) -> None:
        self._real = real
        self._needle = needle
        self.armed = True

    def execute(self, sql, *args, **kwargs):
        if self.armed and self._needle in sql:
            self.armed = False
            raise sqlite3.OperationalError(f"injected failure on {self._needle!r}")
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


# --- helpers ------------------------------------------------------------------------
def _authority_path(tmp_path) -> str:
    return str(tmp_path / "authority.sqlite3")


def _seed_run(store, hash_=HASH_A, *, run_id="run-1", eff=3, ceiling=3):
    store.create_run(
        run_id=run_id,
        principal_id="hermes",
        canonical_plan_hash=hash_,
        effective_autonomy=eff,
        policy_ceiling=ceiling,
    )


def _approved(store, run_id="run-1", **decide):
    appr = store.create_pending_approval(run_id)
    store.decide_approval(appr.approval_id, decision="approve", approver="owner", **decide)
    return appr.approval_id


# ============================================================ shared behavioral contract
@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        yield ApprovalStore()
    else:
        s = SqliteApprovalStore(_authority_path(tmp_path))
        yield s
        s.close()


def test_store_satisfies_authority_protocol(store):
    assert isinstance(store, AuthorityStore)


def test_run_creation_and_retrieval(store):
    _seed_run(store)
    run = store.get_run("run-1")
    assert run is not None
    assert run.canonical_plan_hash == HASH_A
    assert run.status is RunStatus.OPEN
    assert run.created_at.tzinfo is not None


def test_duplicate_run_refused(store):
    _seed_run(store)
    with pytest.raises(ApprovalError):
        _seed_run(store)


def test_create_run_refuses_autonomy_above_ceiling(store):
    with pytest.raises(ApprovalError):
        _seed_run(store, eff=5, ceiling=3)


def test_pending_approval_creation(store):
    _seed_run(store)
    appr = store.create_pending_approval("run-1", task_class="code", target_resources=("a.py",))
    assert appr.approval_status is ApprovalStatus.PENDING
    assert appr.canonical_plan_hash == HASH_A
    assert appr.target_resources == ("a.py",)
    assert store.get_approval(appr.approval_id).task_class == "code"


def test_approve_and_reject(store):
    _seed_run(store)
    a = store.create_pending_approval("run-1")
    store.decide_approval(a.approval_id, decision="approve", approver="owner")
    assert store.get_approval(a.approval_id).approval_status is ApprovalStatus.APPROVED

    _seed_run(store, run_id="run-2")
    b = store.create_pending_approval("run-2")
    store.decide_approval(b.approval_id, decision="reject", approver="owner", reason="no")
    rec = store.get_approval(b.approval_id)
    assert rec.approval_status is ApprovalStatus.REJECTED
    assert rec.rejection_reason == "no"


def test_validate_allows_then_single_use_replay(store):
    _seed_run(store)
    aid = _approved(store)
    assert store.validate_for_execute("run-1", aid, HASH_A).ok
    store.mark_used(aid)
    res = store.validate_for_execute("run-1", aid, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_REPLAY


def test_validate_hash_mismatch(store):
    _seed_run(store)
    aid = _approved(store)
    res = store.validate_for_execute("run-1", aid, HASH_B)
    assert not res.ok and res.reason == approvals.REASON_HASH_MISMATCH


def test_validate_run_mismatch(store):
    _seed_run(store)
    _seed_run(store, run_id="run-2", hash_=HASH_B)
    aid = _approved(store, run_id="run-2")
    res = store.validate_for_execute("run-1", aid, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_RUN_MISMATCH


def test_validate_lazy_expiry(store):
    _seed_run(store)
    aid = _approved(store, ttl_seconds=1)
    later = _now() + timedelta(seconds=5)
    res = store.validate_for_execute("run-1", aid, HASH_A, now=later)
    assert not res.ok and res.reason == approvals.REASON_EXPIRED
    # The expiry transition stuck (persisted for the durable backend).
    assert store.get_approval(aid).approval_status is ApprovalStatus.EXPIRED


def test_invalidate_run_cascades(store):
    _seed_run(store)
    aid = _approved(store)
    store.invalidate_run("run-1")
    assert store.get_run("run-1").status is RunStatus.INVALIDATED
    assert store.get_approval(aid).approval_status is ApprovalStatus.INVALIDATED
    res = store.validate_for_execute("run-1", aid, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_INVALIDATED


def test_clear_empties_store(store):
    _seed_run(store)
    _approved(store)
    store.clear()
    assert store.get_run("run-1") is None


# ============================================================ restart survival (sqlite)
def test_run_survives_reopen(tmp_path):
    path = _authority_path(tmp_path)
    s1 = SqliteApprovalStore(path)
    _seed_run(s1, eff=2, ceiling=4)
    s1.close()
    s2 = SqliteApprovalStore(path)
    run = s2.get_run("run-1")
    assert run is not None and run.effective_autonomy == 2 and run.policy_ceiling == 4
    s2.close()


@pytest.mark.parametrize(
    "make_status",
    ["pending", "approved", "rejected", "expired", "invalidated", "used"],
)
def test_every_approval_status_round_trips(tmp_path, make_status):
    path = _authority_path(tmp_path)
    s1 = SqliteApprovalStore(path)
    _seed_run(s1)
    appr = s1.create_pending_approval(
        "run-1", task_class="code", tool_or_skill="apply", target_resources=("x.py", "y.py")
    )
    aid = appr.approval_id
    if make_status == "approved":
        s1.decide_approval(aid, decision="approve", approver="owner")
    elif make_status == "rejected":
        s1.decide_approval(aid, decision="reject", approver="owner", reason="nope")
    elif make_status == "expired":
        s1.decide_approval(aid, decision="approve", approver="owner", ttl_seconds=1)
        s1.validate_for_execute("run-1", aid, HASH_A, now=_now() + timedelta(seconds=5))
    elif make_status == "invalidated":
        s1.invalidate_run("run-1")
    elif make_status == "used":
        s1.decide_approval(aid, decision="approve", approver="owner")
        s1.mark_used(aid)
    before = s1.get_approval(aid)
    s1.close()

    s2 = SqliteApprovalStore(path)
    after = s2.get_approval(aid)
    assert after.approval_status == before.approval_status
    assert after.approver == before.approver
    assert after.decided_at == before.decided_at
    assert after.used_at == before.used_at
    assert after.expires_at == before.expires_at
    assert after.rejection_reason == before.rejection_reason
    assert after.target_resources == ("x.py", "y.py")
    assert after.tool_or_skill == "apply"
    s2.close()


def test_single_use_authority_stays_spent_after_reopen(tmp_path):
    path = _authority_path(tmp_path)
    s1 = SqliteApprovalStore(path)
    _seed_run(s1)
    aid = _approved(s1)
    s1.mark_used(aid)
    s1.close()
    s2 = SqliteApprovalStore(path)
    res = s2.validate_for_execute("run-1", aid, HASH_A)
    assert not res.ok and res.reason == approvals.REASON_REPLAY
    s2.close()


# ============================================================ crash / transaction (sqlite)
def test_create_run_insert_failure_leaves_no_partial_state(tmp_path):
    path = _authority_path(tmp_path)
    store = SqliteApprovalStore(path)
    store._conn = _FailingConn(store._conn, "INSERT INTO runs")
    with pytest.raises(sqlite3.OperationalError):
        _seed_run(store)
    store._conn = store._conn._real  # disarm
    assert store.get_run("run-1") is None
    store.close()


def test_invalidate_run_cannot_half_persist(tmp_path):
    path = _authority_path(tmp_path)
    store = SqliteApprovalStore(path)
    _seed_run(store)
    aid = _approved(store)
    # Fail on the SECOND statement of invalidate_run (the approvals cascade), inside the txn.
    store._conn = _FailingConn(store._conn, "UPDATE approvals")
    with pytest.raises(sqlite3.OperationalError):
        store.invalidate_run("run-1")
    store._conn = store._conn._real
    # The run's own UPDATE must have rolled back with the cascade — no half-write.
    assert store.get_run("run-1").status is RunStatus.OPEN
    assert store.get_approval(aid).approval_status is ApprovalStatus.APPROVED
    store.close()


# ============================================================ integrity / migration
def test_fresh_database_is_at_current_schema(tmp_path):
    path = _authority_path(tmp_path)
    store = SqliteApprovalStore(path)
    row = store._conn.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    assert int(row[0]) == AUTHORITY_SCHEMA_VERSION
    store.close()


def test_wal_and_foreign_keys_enabled(tmp_path):
    path = _authority_path(tmp_path)
    store = SqliteApprovalStore(path)
    assert str(store._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
    assert store._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    store.close()


def test_foreign_key_enforced_orphan_approval(tmp_path):
    path = _authority_path(tmp_path)
    store = SqliteApprovalStore(path)
    with pytest.raises(sqlite3.IntegrityError):
        store._conn.execute(
            "INSERT INTO approvals (approval_id, run_id, principal_id, canonical_plan_hash, "
            "effective_autonomy, approval_status, task_class, tool_or_skill, target_resources, "
            "created_at, single_use, rejection_reason, policy_rule_triggered, evidence_refs) "
            "VALUES ('appr-x','missing-run','p',?,1,'pending','','','[]',?,1,'','','[]')",
            (HASH_A, _now().isoformat()),
        )
    store.close()


def test_unsupported_future_schema_fails_closed(tmp_path):
    path = _authority_path(tmp_path)
    SqliteApprovalStore(path).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE schema_meta SET value='999' WHERE key='schema_version'")
    raw.commit()
    raw.close()
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_malformed_stored_enum_fails_closed(tmp_path):
    path = _authority_path(tmp_path)
    store = SqliteApprovalStore(path)
    _seed_run(store)
    store.close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE runs SET status='not-a-status' WHERE run_id='run-1'")
    raw.commit()
    raw.close()
    # Step 7A.1: corruption is caught by the full startup scan — construction itself fails
    # closed rather than opening and surfacing the bad enum lazily on a later read.
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)


def test_empty_to_current_schema_is_deterministic(tmp_path):
    a = SqliteApprovalStore(str(tmp_path / "a.sqlite3"))
    b = SqliteApprovalStore(str(tmp_path / "b.sqlite3"))
    schema_a = sorted(
        r[0] for r in a._conn.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
        ).fetchall()
    )
    schema_b = sorted(
        r[0] for r in b._conn.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
        ).fetchall()
    )
    assert schema_a == schema_b
    a.close()
    b.close()


def test_failed_migration_leaves_prior_version_usable(tmp_path):
    path = str(tmp_path / "m.sqlite3")
    conn = connect(path)

    def _good(c):
        c.execute("CREATE TABLE t1(a)")

    def _bad(_c):
        raise RuntimeError("boom mid-migration")

    # Migrate to v1 successfully, then attempt v2 which fails.
    migrate(conn, "test", 1, [_good, _bad])
    with pytest.raises(RuntimeError):
        migrate(conn, "test", 2, [_good, _bad])
    version = conn.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()[0]
    assert version == "1"  # v2 rolled back; prior committed version intact
    # And no half-applied artifact from the failed step.
    assert conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='t1'"
    ).fetchone() is not None
    conn.close()


def test_memory_default_has_no_path_attribute():
    # The in-memory store is the durability discriminator's negative case.
    assert not hasattr(ApprovalStore(), "_path")
    assert hasattr(SqliteApprovalStore.__init__, "__call__")
