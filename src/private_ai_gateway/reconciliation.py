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
3      USED              no usable signed graph         invalidate — dirty; the
                                                        outcome is unknown
4      USED              full signed graph resolves     clean — complete
5      (no compatible authority projection for evidence) invalidate the extant
                                                        authority run, or (nothing
                                                        extant) attention only
6      USED              no reservation                 fail closed — legacy,
                                                        evidence loss, or tampering
===== ================= ============================== ==========================

Class 4 is deliberately the *only* clean terminal shape, and it is defined as exactly
OpenClaw's own full signed graph — ``apply_result -> execute_validated ->
approval_decided``, including emitter identity, record uniqueness, ``decision == approve``
and canonical-plan-hash agreement, via
:func:`openclaw.evidence.load_evidence_graph_from_sink`. This module deliberately keeps no
weaker parallel notion of "complete": "an apply_result exists" is never sufficient, and
neither is "its execute_ref resolves". Class 2 is likewise gated on a genuinely linked
reservation (:func:`openclaw.evidence.load_execution_reservation_from_sink`), so malformed
execution evidence is never mistaken for a clean crash-after-reservation story.

Step 7C.2 adds a second, strictly separate question. Classification above establishes what
the *history* was; a valid terminal ``run_disposition`` then answers whether a human has
already closed that history. The two never mix: a dirty run stays class 3 and stays
invalidated forever, but once disposed it is no longer *outstanding* and stops being
resurfaced at every startup. No class is weakened by the presence of a disposition, and a
disposition that does not fully re-validate fails startup closed rather than being ignored —
"unreadable" must never read as "not yet disposed".

Anything ambiguous (more than one reservation, conflicting outcomes, mismatched bindings)
fails closed rather than being normalized — and *failing closed means acting*: a class-5
inconsistency that can be tied to an extant authority run invalidates that run, because
reporting alone would leave an approval with incompatible execution evidence executable.
Only an orphan evidence fact with no corresponding authority run is attention-only, since
acting there would mean letting evidence create or select authority.

The terminal safety barrier is the existing ``RunStatus.INVALIDATED``. This module adds no
run/approval states, no schema, and no persisted findings; the one durable thing that can
retire a finding is a human's signed disposition, which this module only ever *reads*.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

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
    # Step 7C.2 — a valid terminal ``run_disposition`` exists for this run. Deliberately a
    # separate field rather than a fourth outcome: the outcome records what the *history*
    # was and never softens because a human later closed it. Only "is this still
    # outstanding?" changes.
    disposition: str = ""

    @property
    def disposed(self) -> bool:
        return bool(self.disposition)

    def __str__(self) -> str:  # operator-facing, safe by construction
        disposed = f" disposition={self.disposition}" if self.disposition else ""
        return (
            f"class={self.class_id} outcome={self.outcome} run={self.run_id or '-'} "
            f"approval={self.approval_id or '-'}{disposed} reason={self.reason}"
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

    @property
    def disposed(self) -> tuple[ReconciliationFinding, ...]:
        """Findings whose run a human has already terminally closed (Step 7C.2)."""
        return tuple(f for f in self.findings if f.disposed)

    @property
    def outstanding(self) -> tuple[ReconciliationFinding, ...]:
        """Anomalies still awaiting a human — everything not clean and not yet disposed.

        This, not :attr:`is_clean`, is what an operator should watch: a dirty run that was
        genuinely dirty stays classified as dirty forever, but once disposed it stops being
        work.
        """
        return tuple(
            f for f in self.findings
            if f.outcome != OUTCOME_CLEAN and not f.disposed
        )

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


def _graph_reader(evidence_sink):
    """One chain-verified view of the evidence log, shared by every classification.

    Step 7B.2.1: the reconciler asks OpenClaw's own verifier whether a signed graph holds
    rather than maintaining a weaker parallel notion of "complete". A chain that does not
    re-derive is an unsafe startup condition, not an absent graph — it fails closed here.
    """
    from openclaw.evidence import SinkGraphReader

    try:
        reader = SinkGraphReader(evidence_sink)
    except Exception as exc:  # noqa: BLE001 — unverifiable != clean
        raise ReconciliationError(
            f"evidence chain could not be verified for reconciliation: {exc}"
        ) from exc
    if reader.chain_error:
        raise ReconciliationError(
            f"evidence chain did not verify during reconciliation: {reader.chain_error}"
        )
    return reader


# --- classification (still no mutation) -----------------------------------------------

def _class_5(authority_store, run_id, approval_id, reason) -> ReconciliationFinding:
    """A class-5 inconsistency, made as fail-closed as the authority projection allows.

    Step 7B.2.1 closed a real gap here: class 5 used to be *reported* and never acted on, so
    an approval whose execution evidence was incompatible or ambiguous could leave its run
    OPEN and executable. The rule is now:

      * inconsistency tied to an **extant, non-terminal authority run** -> invalidate it;
      * inconsistency tied to nothing the authority store knows -> ``attention_required``
        and no mutation at all.

    Evidence still never creates authority: ``run_id`` is only ever acted on when the
    authority store already holds that run, so an evidence-supplied identifier can neither
    synthesize a run nor cause an unrelated one to be closed.
    """
    run = authority_store.get_run(run_id) if run_id else None
    if run is None:
        return ReconciliationFinding(
            5, OUTCOME_ATTENTION, run_id, approval_id,
            f"{reason}; no authority run exists to close, so nothing is mutated",
        )
    if run.status is RunStatus.INVALIDATED:
        return ReconciliationFinding(
            5, OUTCOME_ATTENTION, run_id, approval_id,
            f"{reason}; the authority run is already invalidated",
        )
    return ReconciliationFinding(
        5, OUTCOME_INVALIDATED, run_id, approval_id,
        f"{reason}; the extant authority run is invalidated so it can never execute",
    )


def _classify(authority_store, reader, approvals, index) -> list[ReconciliationFinding]:
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
            findings.append(_class_5(
                authority_store, run_id, approval_id,
                "evidence run_id does not match the authority approval's run_id; evidence "
                "cannot be used to synthesize authority",
            ))
            continue

        # More than one reservation is ambiguous authority evidence. Step 7B.1 prevents it
        # at the source; if the durable graph shows it anyway, fail closed — never pick one.
        if len(reservations) > 1:
            findings.append(_class_5(
                authority_store, run_id, approval_id,
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
            elif applies:
                # apply evidence without consumed authority: the stores disagree about
                # whether authority was ever spent. Never reconcilable in this direction.
                findings.append(_class_5(
                    authority_store, run_id, approval_id,
                    "apply evidence exists while authority was never consumed; evidence "
                    "cannot retroactively grant or confirm authority",
                ))
            else:
                # Step 7B.2.1 — a reservation only proves "crashed after reserving" if it is
                # a genuine Gateway-authored reservation whose authorization edge resolves.
                # Malformed execution evidence is a cross-store inconsistency, not a clean
                # crash story, so it is class 5 rather than class 2.
                view = reader.reservation(run_id=run_id, approval_id=approval_id)
                if view.usable:
                    findings.append(ReconciliationFinding(
                        2, OUTCOME_INVALIDATED, run_id, approval_id,
                        "execution reserved but authority never consumed (crash before "
                        "mark_used); the mutation provably never started, so the run is "
                        "invalidated and fresh authority is required",
                    ))
                else:
                    findings.append(_class_5(
                        authority_store, run_id, approval_id,
                        f"execution evidence for this approval is not a valid signed "
                        f"reservation ({view.reason})",
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
                # Step 7B.2.1 — "complete" is exactly OpenClaw's full signed graph
                # (apply_result -> execute_validated -> approval_decided, uniqueness,
                # emitter identity, decision == approve, canonical plan hash). Nothing
                # weaker may be class 4.
                view = reader.graph(run_id=run_id, approval_id=approval_id)
                if view.usable:
                    findings.append(ReconciliationFinding(
                        4, OUTCOME_CLEAN, run_id, approval_id,
                        "complete recorded execution: the full signed evidence graph "
                        "apply_result -> execute_validated -> approval_decided resolves",
                    ))
                else:
                    findings.append(ReconciliationFinding(
                        3, OUTCOME_INVALIDATED, run_id, approval_id,
                        f"authority consumed but the outcome is unknown — the mutation may "
                        f"or may not have happened ({view.reason}); the run is invalidated "
                        f"and is never automatically retried",
                    ))
        # PENDING / REJECTED / EXPIRED carry no execution authority. A reservation against
        # one is a cross-store inconsistency, not a normal shape.
        elif reservations or applies:
            findings.append(_class_5(
                authority_store, run_id, approval_id,
                f"execution evidence exists for an approval in state "
                f"{status.value!r}, which never granted execution authority",
            ))

    # Evidence whose approval has no authority projection at all. The run_id here comes from
    # evidence, so it is acted on only when the authority store already holds that exact run
    # (see :func:`_class_5`) — a truly orphaned fact mutates nothing.
    for approval_id, by_type in sorted(index.items()):
        if approval_id in known_ids:
            continue
        if not (by_type.get(RECORD_RESERVATION) or by_type.get(RECORD_APPLY)):
            continue
        any_rec = (by_type.get(RECORD_RESERVATION) or by_type.get(RECORD_APPLY))[0]
        findings.append(_class_5(
            authority_store, any_rec.envelope.run_id or "", approval_id,
            "execution evidence references an approval with no authority record; the "
            "evidence is retained append-only and grants nothing",
        ))
    return findings


# --- terminal disposition (Step 7C.2, still no mutation) ------------------------------

def _disposed_runs(authority_store, reader) -> tuple[dict, list[ReconciliationFinding]]:
    """Every valid terminal ``run_disposition`` on the chain, keyed by ``run_id``.

    Runs over the *whole* verified log rather than only the runs that produced a finding, so
    a malformed disposition cannot hide behind a run that classified quietly. The outcomes
    follow the same doctrine as the rest of this module:

      * valid disposition for an extant, already-sealed run -> terminal; the run stops being
        outstanding;
      * disposition naming a run the authority store does not hold -> nothing is mutated and
        nothing is synthesized (evidence never creates authority); any evidence-driven
        class-5 finding for that run is simply marked disposed;
      * disposition naming an extant run that is somehow **not** invalidated -> a cross-store
        contradiction, handled exactly like any other class-5 inconsistency: the extant run is
        invalidated;
      * anything that does not re-validate (bad basis, wrong binding, wrong emitter, two
        records for one run) -> :class:`ReconciliationError`; startup fails closed.
    """
    from private_ai_gateway.disposition import (
        RUN_DISPOSITION_RECORD_TYPE,
        DispositionError,
        disposition_for_run,
    )

    run_ids = sorted({
        rec.envelope.run_id or ""
        for rec in reader.records
        if rec.envelope.record_type == RUN_DISPOSITION_RECORD_TYPE
    })
    disposed: dict[str, str] = {}
    extra: list[ReconciliationFinding] = []
    for run_id in run_ids:
        try:
            validated = disposition_for_run(
                reader.records, sink_id=reader.sink_id, run_id=run_id
            )
        except DispositionError as exc:
            raise ReconciliationError(
                f"run_disposition for run {run_id!r} did not validate ({exc.code}): "
                f"{exc.detail}"
            ) from exc
        if validated is None:  # pragma: no cover - run_ids came from these very records
            continue
        run = authority_store.get_run(run_id) if run_id else None
        if run is not None and run.status is not RunStatus.INVALIDATED:
            extra.append(_class_5(
                authority_store, run_id, validated.approval_id,
                "a terminal run_disposition exists for a run that is not invalidated",
            ))
            continue
        disposed[run_id] = validated.disposition
    return disposed, extra


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
    reader = _graph_reader(evidence_sink)
    findings = list(_classify(authority_store, reader, approvals, index))

    # -- phase 1b: terminal disposition, applied *over* the classification, never into it --
    disposed, extra = _disposed_runs(authority_store, reader)
    findings.extend(extra)
    if disposed:
        findings = [
            replace(f, disposition=disposed[f.run_id])
            if f.run_id in disposed and not f.disposition else f
            for f in findings
        ]
    findings = tuple(findings)

    # -- phase 2: act --
    # Driven by the classification, deliberately *not* by whether a disposition exists: a
    # disposed run is already sealed (that is what recording the disposition did), so this is
    # idempotent — but it means a disposition can never be the reason a dirty run escapes the
    # terminal barrier.
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
    for finding in report.outstanding:
        logger.warning("STARTUP_RECONCILIATION | %s", finding)
    for finding in report.disposed:
        logger.info("STARTUP_RECONCILIATION_DISPOSED | %s", finding)
    return report
