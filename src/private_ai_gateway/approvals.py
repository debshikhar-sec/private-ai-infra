"""In-process approval store — the durable authority primitive for the governed loop.

Implements the storage/validation half of ``docs/run-id-approval-design.md``: a
process-local store of runs and approvals, a status machine, expiry, single-use, and
restart-invalidation *by design* (the store lives in memory, so a fresh ``ApprovalStore``
is a restart). It performs no file I/O and holds no persistence — a durable-on-disk
approval would be a forgeable artifact until the verifier-owned evidence sink exists.

Scope note (Step B): this module only stores and validates. It does not mint ``run_id``,
does not wire into the app/orchestration, and does not touch ``canonical.py`` — it holds
the ``canonical_plan_hash`` as an opaque string and binds an approval to *both* the
``run_id`` and that hash. Enforcement wiring is a later step.

Security invariants enforced here:
  * an approval binds to both ``run_id`` and ``canonical_plan_hash``; a match on only one
    is refused;
  * ``effective_autonomy`` is policy-derived input captured at run creation and can never
    exceed the recorded ``policy_ceiling`` — an approval cannot raise autonomy;
  * the approver is set only via an explicit argument to :meth:`decide_approval`, never a
    free-form body field (in production it is the authenticated principal, never model
    text);
  * rejection is a governed successful outcome (a record state), not an exception.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

DEFAULT_APPROVAL_TTL_SECONDS = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalError(Exception):
    """A creation-time policy violation — fail closed (not a governed deny outcome)."""


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    USED = "used"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"


class RunStatus(str, Enum):
    OPEN = "open"
    INVALIDATED = "invalidated"


# --- deny reason codes returned by validate_for_execute (governed outcomes) ----------
REASON_RUN_NOT_FOUND = "run_not_found"
REASON_APPROVAL_MISSING = "approval_missing"
REASON_RUN_MISMATCH = "run_mismatch"
REASON_NOT_APPROVED = "not_approved"
REASON_REJECTED = "rejected"
REASON_EXPIRED = "expired"
REASON_REPLAY = "replay"
REASON_HASH_MISMATCH = "hash_mismatch"
REASON_INVALIDATED = "invalidated"
REASON_AUTONOMY_EXCEEDED = "autonomy_exceeded"


@dataclass
class RunRecord:
    """One governed run: the plan proposal it corresponds to and its policy envelope."""

    run_id: str
    principal_id: str
    canonical_plan_hash: str
    effective_autonomy: int
    policy_ceiling: int
    created_at: datetime = field(default_factory=_now)
    status: RunStatus = RunStatus.OPEN


@dataclass
class ApprovalRecord:
    """A durable approval, bound to a run and a canonical plan hash."""

    approval_id: str
    run_id: str
    principal_id: str
    canonical_plan_hash: str
    effective_autonomy: int
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approver: str | None = None
    requested_autonomy: int | None = None
    task_class: str = ""
    tool_or_skill: str = ""
    target_resources: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=_now)
    expires_at: datetime | None = None
    decided_at: datetime | None = None
    single_use: bool = True
    used_at: datetime | None = None
    rejection_reason: str = ""
    policy_rule_triggered: str = ""
    evidence_refs: tuple[str, ...] = ()  # placeholder; filled once the evidence sink exists


@dataclass
class ValidationResult:
    """Result of :meth:`ApprovalStore.validate_for_execute` — a governed allow/deny."""

    ok: bool
    reason: str = ""
    record: ApprovalRecord | None = None


class ApprovalStore:
    """Process-local store of runs and approvals. A fresh instance models a restart."""

    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}
        self._approvals: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

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
        with self._lock:
            if run_id in self._runs:
                raise ApprovalError(f"run {run_id!r} already exists")
            run = RunRecord(
                run_id=run_id,
                principal_id=principal_id,
                canonical_plan_hash=canonical_plan_hash,
                effective_autonomy=effective_autonomy,
                policy_ceiling=policy_ceiling,
            )
            self._runs[run_id] = run
            return run

    def get_run(self, run_id: str) -> RunRecord | None:
        return self._runs.get(run_id)

    def invalidate_run(self, run_id: str) -> None:
        """Invalidate a run and all its non-terminal approvals (fail closed downstream)."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is not None:
                run.status = RunStatus.INVALIDATED
            for appr in self._approvals.values():
                if appr.run_id == run_id and appr.approval_status in (
                    ApprovalStatus.PENDING,
                    ApprovalStatus.APPROVED,
                ):
                    appr.approval_status = ApprovalStatus.INVALIDATED

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
        """Create a pending approval bound to an open run's id and canonical plan hash.

        Note there is deliberately no ``approver`` parameter here: the approver is set only
        at decision time, via an explicit argument (never a body field / model text).
        """
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise ApprovalError(f"unknown run {run_id!r}")
            if run.status is not RunStatus.OPEN:
                raise ApprovalError(f"run {run_id!r} is not open ({run.status.value})")
            approval_id = "appr-" + uuid.uuid4().hex
            record = ApprovalRecord(
                approval_id=approval_id,
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
            self._approvals[approval_id] = record
            return record

    def get_approval(self, approval_id: str) -> ApprovalRecord | None:
        return self._approvals.get(approval_id)

    def decide_approval(
        self,
        approval_id: str,
        *,
        decision: str,
        approver: str,
        reason: str = "",
        ttl_seconds: int = DEFAULT_APPROVAL_TTL_SECONDS,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        """Approve or reject a pending approval. Rejection is a governed success.

        ``approver`` is a required explicit argument — the authenticated human identity in
        production, never taken from a request body or model output.
        """
        if decision not in ("approve", "reject"):
            raise ApprovalError(f"decision must be 'approve' or 'reject', got {decision!r}")
        if not approver:
            raise ApprovalError("approver is required")
        now = now or _now()
        with self._lock:
            appr = self._approvals.get(approval_id)
            if appr is None:
                raise ApprovalError(f"unknown approval {approval_id!r}")
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

        Requires a match on BOTH ``run_id`` and ``canonical_plan_hash``, an ``approved``
        non-expired non-used approval, and ``effective_autonomy`` within the run's ceiling.
        """
        now = now or _now()
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return ValidationResult(False, REASON_RUN_NOT_FOUND)
            if run.status is RunStatus.INVALIDATED:
                return ValidationResult(False, REASON_INVALIDATED)
            if not approval_id:
                return ValidationResult(False, REASON_APPROVAL_MISSING)
            appr = self._approvals.get(approval_id)
            if appr is None:
                return ValidationResult(False, REASON_APPROVAL_MISSING)
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
            # Lazily transition an approved-but-expired approval.
            if appr.expires_at is not None and now >= appr.expires_at:
                appr.approval_status = ApprovalStatus.EXPIRED
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

    def mark_used(self, approval_id: str, *, now: datetime | None = None) -> ApprovalRecord:
        """Consume a single-use approval after a successful validation."""
        now = now or _now()
        with self._lock:
            appr = self._approvals.get(approval_id)
            if appr is None:
                raise ApprovalError(f"unknown approval {approval_id!r}")
            if appr.approval_status is not ApprovalStatus.APPROVED:
                raise ApprovalError(
                    f"approval {approval_id!r} is not in an approved state "
                    f"({appr.approval_status.value})"
                )
            if appr.single_use:
                appr.approval_status = ApprovalStatus.USED
            appr.used_at = now
            return appr

    # -- restart modeling --------------------------------------------------------------
    def clear(self) -> None:
        """Drop all runs and approvals — models a process restart (nothing persists)."""
        with self._lock:
            self._runs.clear()
            self._approvals.clear()
