"""Governed delegation: tasks handed between agents under attenuating authority.

A2A agent cards (:mod:`private_ai_gateway.a2a`) let agents *discover* each other from
policy-derived facts. This module governs what happens next: one agent handing work to
another. Delegation is exactly where capability quietly becomes authority — a planner
that can "ask" an executor to move money has, in effect, the executor's privileges — so
the hand-off itself is a policy decision, enforced and audited like any other.

The model has two axes, deliberately separate:

  * **Skill possession** (``allowed_skills``) — the right to *hold or route* a task type.
    A delegator may only delegate a skill it holds; a delegatee may only be handed a
    skill it holds. You cannot hand off authority you were never granted.
  * **Autonomy ceiling** (``max_autonomy_level``) — the right to *execute* at a level.
    The requested level must not exceed the delegatee's own policy ceiling, and in a
    chain it must not exceed the parent grant.

Consequently a low-autonomy planner (L1) can route an L3 task to an executor that
policy grants L3 — the executor's authority comes from policy, not from the planner —
but no request can ever *amplify* authority: chains only narrow, never widen, and depth
is bounded. Only the current holder of a task (its delegatee) may sub-delegate it, and
only the delegatee may report its result.

The ledger is in-process state for the task lifecycle; the durable record of every
allow/deny is the gateway decision audit, same as all other enforcement.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from private_ai_gateway.policy import Principal

# Task lifecycle states. A delegation is created ``submitted`` and ends in exactly one
# of the terminal states, reported by its delegatee.
SUBMITTED = "submitted"
COMPLETED = "completed"
FAILED = "failed"
TERMINAL = (COMPLETED, FAILED)

DEFAULT_MAX_DEPTH = 3


class DelegationError(Exception):
    """A refused delegation operation, carrying its audit code and HTTP status."""

    def __init__(self, code: str, message: str, status: int = 403):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


@dataclass(frozen=True)
class Delegation:
    """One governed hand-off: who gave what task to whom, under which authority."""

    id: str
    parent_id: str | None
    delegator: str
    delegatee: str
    skill: str
    granted_level: int
    depth: int
    created_at: str
    status: str = SUBMITTED
    task: str = ""      # short description of the delegated work
    result: str = ""    # delegatee-reported outcome summary
    verdict: str = ""   # optional structured outcome (e.g. PASS / FAIL)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "parent_id": self.parent_id,
            "delegator": self.delegator,
            "delegatee": self.delegatee,
            "skill": self.skill,
            "granted_level": self.granted_level,
            "depth": self.depth,
            "created_at": self.created_at,
            "status": self.status,
            "task": self.task,
            "result": self.result,
            "verdict": self.verdict,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DelegationLedger:
    """Thread-safe in-process ledger of delegations and their lifecycle."""

    def __init__(self) -> None:
        self._by_id: dict[str, Delegation] = {}
        self._lock = threading.Lock()

    # -- creation (the enforcement point) -------------------------------------

    def create(
        self,
        *,
        delegator: Principal,
        delegatee: Principal,
        skill: str,
        requested_level: int,
        delegatee_ceiling: int | None,
        parent_id: str | None = None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        task: str = "",
    ) -> Delegation:
        """Create a delegation if — and only if — every governance check passes.

        Raises :class:`DelegationError` with a stable ``code`` otherwise; the caller
        records that code in the decision audit.
        """
        if delegator.name == delegatee.name:
            raise DelegationError(
                "self_delegation",
                "A principal cannot delegate to itself; submit a plain task instead.",
                status=400,
            )

        # Skill axis: both ends must hold the skill. The delegator check is the
        # confused-deputy guard — an agent cannot route authority it was never granted.
        if not delegator.may_use_skill(skill):
            raise DelegationError(
                "skill_not_delegable",
                f"Principal '{delegator.name}' does not hold skill '{skill}' "
                "and therefore cannot delegate it.",
            )
        if not delegatee.may_use_skill(skill):
            raise DelegationError(
                "skill_not_allowed",
                f"Delegatee '{delegatee.name}' is not granted skill '{skill}'.",
            )

        # Autonomy axis: the request must fit inside the delegatee's own policy
        # ceiling. Asking a peer to operate above its ceiling is amplification.
        if delegatee_ceiling is not None and requested_level > delegatee_ceiling:
            raise DelegationError(
                "autonomy_amplification",
                f"Requested L{requested_level} exceeds delegatee "
                f"'{delegatee.name}' ceiling L{delegatee_ceiling}; "
                "delegation cannot amplify authority.",
            )

        depth = 1
        if parent_id is not None:
            with self._lock:
                parent = self._by_id.get(parent_id)
            if parent is None:
                raise DelegationError(
                    "unknown_parent_task", f"No delegation '{parent_id}'.", status=404
                )
            # Chain custody: only the current holder of the parent task may split it.
            if parent.delegatee != delegator.name:
                raise DelegationError(
                    "not_task_holder",
                    f"Only '{parent.delegatee}' (the delegatee of '{parent_id}') "
                    "may sub-delegate it.",
                )
            if parent.status != SUBMITTED:
                raise DelegationError(
                    "parent_not_active",
                    f"Parent task '{parent_id}' is '{parent.status}'; "
                    "only active tasks can be sub-delegated.",
                    status=409,
                )
            # Chains narrow, never widen: a sub-task cannot carry more authority
            # than its parent grant …
            if requested_level > parent.granted_level:
                raise DelegationError(
                    "delegation_widening",
                    f"Requested L{requested_level} exceeds the parent grant "
                    f"L{parent.granted_level}; sub-delegation cannot widen authority.",
                )
            # … and cannot recurse forever.
            depth = parent.depth + 1
            if depth > max_depth:
                raise DelegationError(
                    "delegation_too_deep",
                    f"Sub-delegation depth {depth} exceeds the policy "
                    f"maximum of {max_depth}.",
                )

        record = Delegation(
            id=f"dg-{uuid.uuid4().hex[:12]}",
            parent_id=parent_id,
            delegator=delegator.name,
            delegatee=delegatee.name,
            skill=skill,
            granted_level=requested_level,
            depth=depth,
            created_at=_now(),
            task=task,
        )
        with self._lock:
            self._by_id[record.id] = record
        return record

    # -- lifecycle -------------------------------------------------------------

    def get(self, delegation_id: str) -> Delegation | None:
        with self._lock:
            return self._by_id.get(delegation_id)

    def report(
        self,
        delegation_id: str,
        *,
        reporter: str,
        status: str,
        result: str = "",
        verdict: str = "",
    ) -> Delegation:
        """Record the delegatee's outcome. Only the delegatee may report, once."""
        if status not in TERMINAL:
            raise DelegationError(
                "invalid_status",
                f"Result status must be one of {TERMINAL}, got '{status}'.",
                status=400,
            )
        with self._lock:
            record = self._by_id.get(delegation_id)
            if record is None:
                raise DelegationError(
                    "unknown_task", f"No delegation '{delegation_id}'.", status=404
                )
            if record.delegatee != reporter:
                raise DelegationError(
                    "not_task_holder",
                    f"Only the delegatee '{record.delegatee}' may report on "
                    f"'{delegation_id}'.",
                )
            if record.status != SUBMITTED:
                raise DelegationError(
                    "already_reported",
                    f"Task '{delegation_id}' is already '{record.status}'.",
                    status=409,
                )
            updated = replace(record, status=status, result=result, verdict=verdict)
            self._by_id[delegation_id] = updated
            return updated

    # -- queries ----------------------------------------------------------------

    def chain(self, delegation_id: str) -> list[Delegation]:
        """The chain from root grant to the given delegation, in order."""
        out: list[Delegation] = []
        with self._lock:
            current = self._by_id.get(delegation_id)
            while current is not None:
                out.append(current)
                current = (
                    self._by_id.get(current.parent_id) if current.parent_id else None
                )
        return list(reversed(out))

    def for_principal(
        self, name: str, *, role: str = "delegatee", status: str | None = None
    ) -> list[Delegation]:
        """Tasks where the principal is the delegatee (its inbox) or delegator."""
        with self._lock:
            records = list(self._by_id.values())
        key = (lambda d: d.delegatee) if role == "delegatee" else (lambda d: d.delegator)
        picked = [d for d in records if key(d) == name]
        if status:
            picked = [d for d in picked if d.status == status]
        return sorted(picked, key=lambda d: d.created_at)

    def all(self) -> list[Delegation]:
        with self._lock:
            return sorted(self._by_id.values(), key=lambda d: d.created_at)
