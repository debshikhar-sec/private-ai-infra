"""Step 7B.2 — startup cross-store reconciliation.

After the authority store and the evidence chain have each independently passed their own
integrity validation, one pass joins them and asks a single question per approval: *what
do the durable facts say happened, and what is the minimal safe thing to do about it?*

The doctrine this encodes:

  * **Evidence proves facts; evidence never grants authority.** No authority row is ever
    created from an evidence record, and a missing failure record never implies success.
  * **Never auto-retry a mutation that may have occurred.** Nothing here executes anything
    (see :func:`reconcile` — it is handed stores, never an executor).
  * **Classify first, act second.** The whole cross-store shape is read and classified into
    immutable findings *before* any state changes, so a repair can never erase the evidence
    a later classification depends on.
  * **Unable to inspect is not clean.** Any unexpected failure while reading either store
    raises :class:`ReconciliationError`; startup fails closed rather than assuming nothing
    happened.

Six classes (the ratified set), keyed on the append-first ordering shipped in Step 7B.1
(``validate -> execute_validated reservation -> mark_used -> mutate -> apply_result``):

===== ================= ============================== ==========================
class  authority         evidence                       action
===== ================= ============================== ==========================
1      APPROVED          no reservation                 clean — nothing started
2      APPROVED          reservation, no apply_result   invalidate — crash before
                                                        consumption; the mutation
                                                        provably never began
3      USED              reservation, no *valid linked* invalidate — dirty; the
                         apply_result                   outcome is unknown
4      USED              reservation + valid linked      clean — complete
                         apply_result
5      (no compatible authority projection for evidence) fail closed — evidence
                                                        never becomes authority
6      USED              no reservation                 fail closed — legacy,
                                                        evidence loss, or tampering
===== ================= ============================== ==========================

Class 4 is deliberately the *only* clean terminal shape, and it requires the signed
linkage to hold — ``approval_decided <-approval_ref- execute_validated <-execute_ref-
apply_result`` — resolved with OpenClaw's own reference logic. "An apply_result exists" is
never sufficient. Anything ambiguous (more than one reservation, conflicting outcomes,
mismatched bindings) fails closed rather than being normalized.

The terminal safety barrier is the existing ``RunStatus.INVALIDATED``. This module adds no
run/approval states, no schema, and no persisted findings — Step 7C's signed verdicts and
terminal disposition remain future.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from private_ai_gateway.approvals import ApprovalStatus, RunStatus

logger = logging.getLogger("AuditTrail")

RECORD_RESERVATION = "execute_validated"
RECORD_APPLY = "apply_result"
RECORD_DECISION = "approval_decided"

# Outcomes an operator reads off a finding.
OUTCOME_CLEAN = "clean"
OUTCOME_INVALIDATED = "invalidated"
OUTCOME_ATTENTION = "attention_required"


class ReconciliationError(Exception):
    """The cross-store state could not be inspected; startup must fail closed."""


@dataclass(frozen=True)
class ReconciliationFinding:
    """One immutable classification. Produced before any action is taken."""

    class_id: int
    outcome: str
    run_id: str
    approval_id: str
    reason: str

    def __str__(self) -> str:  # operator-facing, safe by construction
        return (
            f"class={self.class_id} outcome={self.outcome} run={self.run_id or '-'} "
            f"approval={self.approval_id or '-'} reason={self.reason}"
        )


@dataclass(frozen=True)
class ReconciliationReport:
    """The result of one startup pass."""

    findings: tuple[ReconciliationFinding, ...] = ()

    @property
    def invalidated(self) -> tuple[ReconciliationFinding, ...]:
        return tuple(f for f in self.findings if f.outcome == OUTCOME_INVALIDATED)

    @property
    def attention(self) -> tuple[ReconciliationFinding, ...]:
        return tuple(f for f in self.findings if f.outcome == OUTCOME_ATTENTION)

    @property
    def is_clean(self) -> bool:
        return not self.invalidated and not self.attention

    def by_class(self, class_id: int) -> tuple[ReconciliationFinding, ...]:
        return tuple(f for f in self.findings if f.class_id == class_id)


# --- inspection (no mutation) ---------------------------------------------------------

def _evidence_index(evidence_sink) -> dict[str, dict[str, list]]:
    """Group evidence records by ``approval_id`` and record type.

    Reads the chain the sink already verified at open. Any unexpected failure is an unsafe
    startup condition, never an empty (and therefore "clean-looking") result.
    """
    try:
        records = tuple(evidence_sink.records)
    except Exception as exc:  # noqa: BLE001 — deliberately broad: unreadable != clean
        raise ReconciliationError(
            f"evidence chain could not be read for reconciliation: {exc}"
        ) from exc

    index: dict[str, dict[str, list]] = {}
    try:
        for rec in records:
            env = getattr(rec, "envelope", None)
            if env is None:
                raise ReconciliationError(
                    "evidence record without a signing envelope; refusing to classify"
                )
            approval_id = env.approval_id or ""
            if not approval_id:
                continue  # not execution-bound; nothing to reconcile against authority
            index.setdefault(approval_id, {}).setdefault(env.record_type, []).append(rec)
    except ReconciliationError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ReconciliationError(
            f"evidence chain could not be indexed for reconciliation: {exc}"
        ) from exc
    return index


def _authority_snapshot(authority_store):
    try:
        return tuple(authority_store.snapshot_approvals())
    except Exception as exc:  # noqa: BLE001 — unreadable authority != clean
        raise ReconciliationError(
            f"authority store could not be enumerated for reconciliation: {exc}"
        ) from exc


def _linked_apply_is_valid(evidence_sink, reservation, applies, *, run_id, approval_id):
    """Is there exactly one ``apply_result`` validly bound to this reservation?

    Reuses OpenClaw's own reference resolution (:func:`resolve_evidence_ref`) rather than a
    weaker parallel check: the embedded ``execute_ref`` must resolve, by stable evidence
    identity and recomputed digest, to *this* reservation, and both records must agree on
    run and approval. Returns ``(ok, reason)``.
    """
    from openclaw.sink import EvidenceError, EvidenceRef, resolve_evidence_ref

    if not applies:
        return False, "no apply_result recorded for the reserved execution"
    if len(applies) > 1:
        return False, f"{len(applies)} apply_result records for one approval (ambiguous)"

    apply_rec = applies[0]
    try:
        records = tuple(evidence_sink.records)
        sink_id = evidence_sink.sink_id
        payload = apply_rec.payload
        if not isinstance(payload, dict) or "execute_ref" not in payload:
            return False, "apply_result carries no execute_ref linking it to the reservation"
        ref = EvidenceRef.from_mapping(payload["execute_ref"])
        resolved = resolve_evidence_ref(records, ref, sink_id=sink_id)
    except EvidenceError as exc:
        return False, f"apply_result execute_ref does not resolve: {exc}"
    except Exception as exc:  # noqa: BLE001 — a malformed graph is not a clean run
        return False, f"apply_result linkage could not be evaluated: {exc}"

    if resolved.envelope.evidence_id != reservation.envelope.evidence_id:
        return False, "apply_result links to a different execute_validated record"
    for rec, label in ((apply_rec, "apply_result"), (resolved, "execute_validated")):
        if (rec.envelope.run_id or "") != run_id:
            return False, f"{label} run_id does not match the authority run"
        if (rec.envelope.approval_id or "") != approval_id:
            return False, f"{label} approval_id does not match the authority approval"
    return True, ""


# --- classification (still no mutation) -----------------------------------------------

def _classify(authority_store, evidence_sink, approvals, index) -> list[ReconciliationFinding]:
    findings: list[ReconciliationFinding] = []
    known_ids = {appr.approval_id for appr in approvals}

    for appr in approvals:
        approval_id = appr.approval_id
        run_id = appr.run_id
        by_type = index.get(approval_id, {})
        reservations = by_type.get(RECORD_RESERVATION, [])
        applies = by_type.get(RECORD_APPLY, [])
        status = appr.approval_status

        # Cross-store binding: evidence must agree with the authority row it claims.
        mismatched = [
            r for r in reservations + applies
            if (r.envelope.run_id or "") != run_id
        ]
        if mismatched:
            findings.append(ReconciliationFinding(
                5, OUTCOME_ATTENTION, run_id, approval_id,
                "evidence run_id does not match the authority approval's run_id; evidence "
                "cannot be used to synthesize authority",
            ))
            continue

        # More than one reservation is ambiguous authority evidence. Step 7B.1 prevents it
        # at the source; if the durable graph shows it anyway, fail closed — never pick one.
        if len(reservations) > 1:
            findings.append(ReconciliationFinding(
                5, OUTCOME_ATTENTION, run_id, approval_id,
                f"{len(reservations)} execute_validated records for one approval "
                f"(ambiguous authority evidence; not resolved by picking one)",
            ))
            continue

        # A run already invalidated is terminal. Late evidence may legitimately append, but
        # nothing here reopens it, recreates authority, or converts evidence into authority.
        run = authority_store.get_run(run_id)
        if status is ApprovalStatus.INVALIDATED or (
            run is not None and run.status is RunStatus.INVALIDATED
        ):
            if applies:
                findings.append(ReconciliationFinding(
                    3, OUTCOME_ATTENTION, run_id, approval_id,
                    "apply evidence exists for an already-invalidated run; the run stays "
                    "invalidated and the evidence grants nothing",
                ))
            continue

        if status is ApprovalStatus.APPROVED:
            if not reservations:
                findings.append(ReconciliationFinding(
                    1, OUTCOME_CLEAN, run_id, approval_id,
                    "approved with no execution reserved; nothing started",
                ))
            elif not applies:
                findings.append(ReconciliationFinding(
                    2, OUTCOME_INVALIDATED, run_id, approval_id,
                    "execution reserved but authority never consumed (crash before "
                    "mark_used); the mutation provably never started, so the run is "
                    "invalidated and fresh authority is required",
                ))
            else:
                # apply evidence without consumed authority: the stores disagree about
                # whether authority was ever spent. Never reconcilable in this direction.
                findings.append(ReconciliationFinding(
                    5, OUTCOME_ATTENTION, run_id, approval_id,
                    "apply evidence exists while authority was never consumed; evidence "
                    "cannot retroactively grant or confirm authority",
                ))
        elif status is ApprovalStatus.USED:
            if not reservations:
                findings.append(ReconciliationFinding(
                    6, OUTCOME_INVALIDATED, run_id, approval_id,
                    "authority consumed with no execution reservation (pre-7B.1 legacy, "
                    "evidence loss, or inconsistency); the run is invalidated and no "
                    "evidence is synthesized",
                ))
            else:
                ok, why = _linked_apply_is_valid(
                    evidence_sink, reservations[0], applies,
                    run_id=run_id, approval_id=approval_id,
                )
                if ok:
                    findings.append(ReconciliationFinding(
                        4, OUTCOME_CLEAN, run_id, approval_id,
                        "complete recorded execution: reservation and a uniquely-bound, "
                        "signature-linked apply_result",
                    ))
                else:
                    findings.append(ReconciliationFinding(
                        3, OUTCOME_INVALIDATED, run_id, approval_id,
                        f"authority consumed but the outcome is unknown — the mutation may "
                        f"or may not have happened ({why}); the run is invalidated and is "
                        f"never automatically retried",
                    ))
        # PENDING / REJECTED / EXPIRED carry no execution authority. A reservation against
        # one is a cross-store inconsistency, not a normal shape.
        elif reservations or applies:
            findings.append(ReconciliationFinding(
                5, OUTCOME_ATTENTION, run_id, approval_id,
                f"execution evidence exists for an approval in state "
                f"{status.value!r}, which never granted execution authority",
            ))

    # Evidence whose approval has no authority projection at all.
    for approval_id, by_type in sorted(index.items()):
        if approval_id in known_ids:
            continue
        if not (by_type.get(RECORD_RESERVATION) or by_type.get(RECORD_APPLY)):
            continue
        any_rec = (by_type.get(RECORD_RESERVATION) or by_type.get(RECORD_APPLY))[0]
        findings.append(ReconciliationFinding(
            5, OUTCOME_ATTENTION, any_rec.envelope.run_id or "", approval_id,
            "execution evidence references an approval with no authority record; the "
            "evidence is retained append-only and grants nothing",
        ))
    return findings


# --- action (only after the complete scan succeeded) ----------------------------------

def reconcile(authority_store, evidence_sink) -> ReconciliationReport:
    """Classify the cross-store state, then apply only the permitted repairs.

    Called at durable startup *after* both stores have passed their own integrity
    validation. Inspection is complete and immutable before the first mutation, so a repair
    can never destroy the shape a later classification depends on.

    The only action this takes is :meth:`invalidate_run` — the existing terminal barrier.
    It creates nothing, deletes nothing, retries nothing, and executes nothing. Callers
    receive the findings for logging and operator attention; nothing is persisted.
    """
    if evidence_sink is None:
        return ReconciliationReport()

    # -- phase 1: inspect + classify (no mutation) --
    approvals = _authority_snapshot(authority_store)
    index = _evidence_index(evidence_sink)
    findings = tuple(_classify(authority_store, evidence_sink, approvals, index))

    # -- phase 2: act --
    for finding in findings:
        if finding.outcome != OUTCOME_INVALIDATED or not finding.run_id:
            continue
        try:
            authority_store.invalidate_run(finding.run_id)
        except Exception as exc:  # noqa: BLE001 — a failed repair must not look clean
            raise ReconciliationError(
                f"could not invalidate run {finding.run_id!r} during reconciliation "
                f"(class {finding.class_id}): {exc}"
            ) from exc

    report = ReconciliationReport(findings)
    for finding in report.invalidated + report.attention:
        logger.warning("STARTUP_RECONCILIATION | %s", finding)
    return report
