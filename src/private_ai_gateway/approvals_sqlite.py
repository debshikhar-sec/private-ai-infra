"""Durable, single-node SQLite authority store (Step 7A).

A SQLite-backed implementation of the same authority surface as
:class:`private_ai_gateway.approvals.ApprovalStore` — runs and approvals, the status
machine, dual ``run_id``+hash binding, expiry, single-use, and invalidation — that
*persists* across process restarts instead of living only in memory.

Step 7A scope, deliberately narrow:

  * This store makes today's authority **durable and independently integrity-checked**. It
    does **not** change lifecycle ordering, add new run/approval states, introduce
    reservations/idempotency/reconciliation, or claim runtime crash-safety. Those are Step
    7B/7C. Every observable method preserves the in-memory store's exact semantics.
  * Every mutation is a single committed transaction or no change at all. ``invalidate_run``
    updates the run and all its non-terminal approvals atomically; the lazy expiry inside
    ``validate_for_execute`` is persisted.
  * On open the store validates the database schema version (forward-only), and every read
    reconstructs typed records without trusting anything it cannot re-derive — a malformed
    stored enum, a broken run/approval relationship, or an unsupported schema version fails
    closed rather than being silently repaired.

Standard library only (``sqlite3``, ``json``, ``threading``). Parameterized SQL only; no
pickle or executable serialization; no secret/key material is stored here.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime

from private_ai_gateway.approvals import (
    REASON_APPROVAL_MISSING,
    REASON_AUTONOMY_EXCEEDED,
    REASON_EXPIRED,
    REASON_HASH_MISMATCH,
    REASON_INVALIDATED,
    REASON_NOT_APPROVED,
    REASON_REJECTED,
    REASON_REPLAY,
    REASON_RUN_MISMATCH,
    REASON_RUN_NOT_FOUND,
    ApprovalError,
    ApprovalRecord,
    ApprovalStatus,
    RunRecord,
    RunStatus,
    ValidationResult,
    _now,
)
from private_ai_gateway.sqlite_util import (
    DurableStoreError,
    connect,
    migrate,
    transaction,
)

# This store's own schema-version domain — deliberately separate from the evidence-envelope
# SCHEMA_VERSION and from the evidence database's schema domain. Bump only via a forward
# migration step appended to ``_MIGRATIONS``.
AUTHORITY_SCHEMA_VERSION = 1

# Individual statements (never ``executescript``, which would COMMIT our explicit migration
# transaction out from under us). Each runs via ``conn.execute`` inside the migration txn.
_CREATE_STATEMENTS_V1 = [
    """
    CREATE TABLE runs (
        run_id              TEXT PRIMARY KEY,
        principal_id        TEXT NOT NULL,
        canonical_plan_hash TEXT NOT NULL,
        effective_autonomy  INTEGER NOT NULL,
        policy_ceiling      INTEGER NOT NULL,
        created_at          TEXT NOT NULL,
        status              TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE approvals (
        approval_id           TEXT PRIMARY KEY,
        run_id                TEXT NOT NULL REFERENCES runs(run_id),
        principal_id          TEXT NOT NULL,
        canonical_plan_hash   TEXT NOT NULL,
        effective_autonomy    INTEGER NOT NULL,
        approval_status       TEXT NOT NULL,
        approver              TEXT,
        requested_autonomy    INTEGER,
        task_class            TEXT NOT NULL,
        tool_or_skill         TEXT NOT NULL,
        target_resources      TEXT NOT NULL,
        created_at            TEXT NOT NULL,
        expires_at            TEXT,
        decided_at            TEXT,
        single_use            INTEGER NOT NULL,
        used_at               TEXT,
        rejection_reason      TEXT NOT NULL,
        policy_rule_triggered TEXT NOT NULL,
        evidence_refs         TEXT NOT NULL
    )
    """,
    "CREATE INDEX idx_approvals_run_id ON approvals(run_id)",
]


def _migrate_to_v1(conn: sqlite3.Connection) -> None:
    """Forward migration 0 -> 1: create the initial authority schema."""
    for statement in _CREATE_STATEMENTS_V1:
        conn.execute(statement)


# Forward-only migration ladder: index i upgrades schema version i -> i+1.
_MIGRATIONS = [_migrate_to_v1]


# --- serialization helpers ----------------------------------------------------------
def _dt_to_text(value: datetime | None) -> str | None:
    """Serialize a timezone-aware UTC datetime deterministically (ISO 8601), or ``None``."""
    if value is None:
        return None
    if value.tzinfo is None:
        raise DurableStoreError("refusing to persist a naive (tz-unaware) datetime")
    return value.isoformat()


def _text_to_dt(value: str | None) -> datetime | None:
    """Parse a stored ISO 8601 timestamp back to a tz-aware datetime, or ``None``.

    A malformed timestamp or a naive value is a stored-integrity failure (fail closed).
    """
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise DurableStoreError(f"malformed stored timestamp {value!r}") from exc
    if dt.tzinfo is None:
        raise DurableStoreError(f"stored timestamp {value!r} is not timezone-aware")
    return dt


def _tuple_to_text(value: tuple[str, ...]) -> str:
    """Serialize a string tuple as deterministic JSON (order preserved)."""
    return json.dumps(list(value), separators=(",", ":"), ensure_ascii=False)


def _text_to_tuple(value: str) -> tuple[str, ...]:
    """Parse a stored JSON array back to a string tuple; fail closed on a malformed shape."""
    try:
        items = json.loads(value)
    except (ValueError, TypeError) as exc:
        raise DurableStoreError(f"malformed stored JSON array {value!r}") from exc
    if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
        raise DurableStoreError(f"stored value {value!r} is not a JSON array of strings")
    return tuple(items)


def _run_status(value: str) -> RunStatus:
    try:
        return RunStatus(value)
    except ValueError as exc:
        raise DurableStoreError(f"malformed stored run status {value!r}") from exc


def _approval_status(value: str) -> ApprovalStatus:
    try:
        return ApprovalStatus(value)
    except ValueError as exc:
        raise DurableStoreError(f"malformed stored approval status {value!r}") from exc


def _row_to_run(row: sqlite3.Row) -> RunRecord:
    return RunRecord(
        run_id=row["run_id"],
        principal_id=row["principal_id"],
        canonical_plan_hash=row["canonical_plan_hash"],
        effective_autonomy=row["effective_autonomy"],
        policy_ceiling=row["policy_ceiling"],
        created_at=_text_to_dt(row["created_at"]),
        status=_run_status(row["status"]),
    )


def _row_to_approval(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        approval_id=row["approval_id"],
        run_id=row["run_id"],
        principal_id=row["principal_id"],
        canonical_plan_hash=row["canonical_plan_hash"],
        effective_autonomy=row["effective_autonomy"],
        approval_status=_approval_status(row["approval_status"]),
        approver=row["approver"],
        requested_autonomy=row["requested_autonomy"],
        task_class=row["task_class"],
        tool_or_skill=row["tool_or_skill"],
        target_resources=_text_to_tuple(row["target_resources"]),
        created_at=_text_to_dt(row["created_at"]),
        expires_at=_text_to_dt(row["expires_at"]),
        decided_at=_text_to_dt(row["decided_at"]),
        single_use=bool(row["single_use"]),
        used_at=_text_to_dt(row["used_at"]),
        rejection_reason=row["rejection_reason"],
        policy_rule_triggered=row["policy_rule_triggered"],
        evidence_refs=_text_to_tuple(row["evidence_refs"]),
    )


class SqliteApprovalStore:
    """Durable authority store — the same surface as ``ApprovalStore``, backed by SQLite.

    A single owned connection serialized by a lock (mirroring the in-memory store's
    ``threading.Lock``); WAL + ``busy_timeout`` cover any cross-connection contention. The
    presence of ``_path`` is what distinguishes a durable store from the in-memory default.
    """

    def __init__(self, path: str) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = connect(self._path)
        migrate(self._conn, "authority", AUTHORITY_SCHEMA_VERSION, _MIGRATIONS)

    def close(self) -> None:
        self._conn.close()

    # -- runs --------------------------------------------------------------------------
    def create_run(
        self,
        *,
        run_id: str,
        principal_id: str,
        canonical_plan_hash: str,
        effective_autonomy: int,
        policy_ceiling: int,
    ) -> RunRecord:
        """Record a run. Fails closed if it would grant autonomy above the ceiling."""
        if not run_id:
            raise ApprovalError("run_id is required")
        if effective_autonomy > policy_ceiling:
            raise ApprovalError(
                f"effective_autonomy L{effective_autonomy} exceeds policy ceiling "
                f"L{policy_ceiling}"
            )
        run = RunRecord(
            run_id=run_id,
            principal_id=principal_id,
            canonical_plan_hash=canonical_plan_hash,
            effective_autonomy=effective_autonomy,
            policy_ceiling=policy_ceiling,
        )
        with self._lock:
            if self._conn.execute(
                "SELECT 1 FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise ApprovalError(f"run {run_id!r} already exists")
            with transaction(self._conn):  # atomic: BEGIN ... COMMIT (or ROLLBACK on error)
                self._conn.execute(
                    "INSERT INTO runs (run_id, principal_id, canonical_plan_hash, "
                    "effective_autonomy, policy_ceiling, created_at, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        run.run_id,
                        run.principal_id,
                        run.canonical_plan_hash,
                        run.effective_autonomy,
                        run.policy_ceiling,
                        _dt_to_text(run.created_at),
                        run.status.value,
                    ),
                )
        return run

    def get_run(self, run_id: str) -> RunRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        return _row_to_run(row) if row is not None else None

    def invalidate_run(self, run_id: str) -> None:
        """Invalidate a run and all its non-terminal approvals — atomically."""
        with self._lock, transaction(self._conn):
            self._conn.execute(
                "UPDATE runs SET status = ? WHERE run_id = ?",
                (RunStatus.INVALIDATED.value, run_id),
            )
            self._conn.execute(
                "UPDATE approvals SET approval_status = ? "
                "WHERE run_id = ? AND approval_status IN (?, ?)",
                (
                    ApprovalStatus.INVALIDATED.value,
                    run_id,
                    ApprovalStatus.PENDING.value,
                    ApprovalStatus.APPROVED.value,
                ),
            )

    # -- approvals ---------------------------------------------------------------------
    def create_pending_approval(
        self,
        run_id: str,
        *,
        requested_autonomy: int | None = None,
        task_class: str = "",
        tool_or_skill: str = "",
        target_resources: tuple[str, ...] = (),
        single_use: bool = True,
        policy_rule_triggered: str = "",
    ) -> ApprovalRecord:
        """Create a pending approval bound to an open run's id and canonical plan hash."""
        import uuid

        with self._lock:
            run_row = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run_row is None:
                raise ApprovalError(f"unknown run {run_id!r}")
            run = _row_to_run(run_row)
            if run.status is not RunStatus.OPEN:
                raise ApprovalError(f"run {run_id!r} is not open ({run.status.value})")
            record = ApprovalRecord(
                approval_id="appr-" + uuid.uuid4().hex,
                run_id=run_id,
                principal_id=run.principal_id,
                canonical_plan_hash=run.canonical_plan_hash,
                effective_autonomy=run.effective_autonomy,
                requested_autonomy=requested_autonomy,
                task_class=task_class,
                tool_or_skill=tool_or_skill,
                target_resources=tuple(target_resources),
                single_use=single_use,
                policy_rule_triggered=policy_rule_triggered,
            )
            with transaction(self._conn):
                self._insert_approval(record)
        return record

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
        return _row_to_approval(row) if row is not None else None

    def decide_approval(
        self,
        approval_id: str,
        *,
        decision: str,
        approver: str,
        reason: str = "",
        ttl_seconds: int = 300,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Approve or reject a pending approval. Rejection is a governed success."""
        from datetime import timedelta

        if decision not in ("approve", "reject"):
            raise ApprovalError(f"decision must be 'approve' or 'reject', got {decision!r}")
        if not approver:
            raise ApprovalError("approver is required")
        now = now or _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                raise ApprovalError(f"unknown approval {approval_id!r}")
            appr = _row_to_approval(row)
            if appr.approval_status is not ApprovalStatus.PENDING:
                raise ApprovalError(
                    f"approval {approval_id!r} is not pending "
                    f"({appr.approval_status.value})"
                )
            appr.approver = approver
            appr.decided_at = now
            if decision == "approve":
                appr.approval_status = ApprovalStatus.APPROVED
                appr.expires_at = now + timedelta(seconds=ttl_seconds)
            else:
                appr.approval_status = ApprovalStatus.REJECTED
                appr.rejection_reason = reason
            with transaction(self._conn):
                self._update_approval(appr)
        return appr

    def validate_for_execute(
        self,
        run_id: str,
        approval_id: str | None,
        canonical_plan_hash: str,
        *,
        now: datetime | None = None,
    ) -> ValidationResult:
        """Governed allow/deny for an execute. Never raises for a normal deny.

        Mirrors the in-memory store branch-for-branch; the only write is the durable lazy
        expiry transition (approved-but-expired -> expired), committed before the deny.
        """
        now = now or _now()
        with self._lock:
            run_row = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run_row is None:
                return ValidationResult(False, REASON_RUN_NOT_FOUND)
            run = _row_to_run(run_row)
            if run.status is RunStatus.INVALIDATED:
                return ValidationResult(False, REASON_INVALIDATED)
            if not approval_id:
                return ValidationResult(False, REASON_APPROVAL_MISSING)
            appr_row = self._conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if appr_row is None:
                return ValidationResult(False, REASON_APPROVAL_MISSING)
            appr = _row_to_approval(appr_row)
            if appr.run_id != run_id:
                return ValidationResult(False, REASON_RUN_MISMATCH, appr)
            if appr.approval_status is ApprovalStatus.INVALIDATED:
                return ValidationResult(False, REASON_INVALIDATED, appr)
            if appr.approval_status is ApprovalStatus.REJECTED:
                return ValidationResult(False, REASON_REJECTED, appr)
            if appr.approval_status is ApprovalStatus.USED:
                return ValidationResult(False, REASON_REPLAY, appr)
            if appr.approval_status is ApprovalStatus.EXPIRED:
                return ValidationResult(False, REASON_EXPIRED, appr)
            if appr.approval_status is not ApprovalStatus.APPROVED:
                return ValidationResult(False, REASON_NOT_APPROVED, appr)
            # Lazily transition an approved-but-expired approval — durably.
            if appr.expires_at is not None and now >= appr.expires_at:
                appr.approval_status = ApprovalStatus.EXPIRED
                with transaction(self._conn):
                    self._update_approval(appr)
                return ValidationResult(False, REASON_EXPIRED, appr)
            # Bind to BOTH the hash on the approval and the hash on the run.
            if appr.canonical_plan_hash != canonical_plan_hash:
                return ValidationResult(False, REASON_HASH_MISMATCH, appr)
            if run.canonical_plan_hash != canonical_plan_hash:
                return ValidationResult(False, REASON_HASH_MISMATCH, appr)
            # Defensive: autonomy can never exceed the recorded ceiling.
            if appr.effective_autonomy > run.policy_ceiling:
                return ValidationResult(False, REASON_AUTONOMY_EXCEEDED, appr)
            return ValidationResult(True, "", appr)

    def mark_used(
        self, approval_id: str, *, now: datetime | None = None
    ) -> ApprovalRecord:
        """Consume a single-use approval after a successful validation."""
        now = now or _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if row is None:
                raise ApprovalError(f"unknown approval {approval_id!r}")
            appr = _row_to_approval(row)
            if appr.approval_status is not ApprovalStatus.APPROVED:
                raise ApprovalError(
                    f"approval {approval_id!r} is not in an approved state "
                    f"({appr.approval_status.value})"
                )
            if appr.single_use:
                appr.approval_status = ApprovalStatus.USED
            appr.used_at = now
            with transaction(self._conn):
                self._update_approval(appr)
        return appr

    def clear(self) -> None:
        """Drop all runs and approvals (a durable wipe) — atomically."""
        with self._lock, transaction(self._conn):
            self._conn.execute("DELETE FROM approvals")
            self._conn.execute("DELETE FROM runs")

    # -- internal row writers (must run inside an open transaction) --------------------
    def _insert_approval(self, appr: ApprovalRecord) -> None:
        self._conn.execute(
            "INSERT INTO approvals (approval_id, run_id, principal_id, canonical_plan_hash, "
            "effective_autonomy, approval_status, approver, requested_autonomy, task_class, "
            "tool_or_skill, target_resources, created_at, expires_at, decided_at, "
            "single_use, used_at, rejection_reason, policy_rule_triggered, evidence_refs) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._approval_params(appr),
        )

    def _update_approval(self, appr: ApprovalRecord) -> None:
        params = self._approval_params(appr)
        self._conn.execute(
            "UPDATE approvals SET run_id = ?, principal_id = ?, canonical_plan_hash = ?, "
            "effective_autonomy = ?, approval_status = ?, approver = ?, "
            "requested_autonomy = ?, task_class = ?, tool_or_skill = ?, "
            "target_resources = ?, created_at = ?, expires_at = ?, decided_at = ?, "
            "single_use = ?, used_at = ?, rejection_reason = ?, policy_rule_triggered = ?, "
            "evidence_refs = ? WHERE approval_id = ?",
            params[1:] + (params[0],),
        )

    @staticmethod
    def _approval_params(appr: ApprovalRecord) -> tuple:
        return (
            appr.approval_id,
            appr.run_id,
            appr.principal_id,
            appr.canonical_plan_hash,
            appr.effective_autonomy,
            appr.approval_status.value,
            appr.approver,
            appr.requested_autonomy,
            appr.task_class,
            appr.tool_or_skill,
            _tuple_to_text(appr.target_resources),
            _dt_to_text(appr.created_at),
            _dt_to_text(appr.expires_at),
            _dt_to_text(appr.decided_at),
            1 if appr.single_use else 0,
            _dt_to_text(appr.used_at),
            appr.rejection_reason,
            appr.policy_rule_triggered,
            _tuple_to_text(appr.evidence_refs),
        )
