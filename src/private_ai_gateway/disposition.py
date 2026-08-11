"""Step 7C.2 — terminal ``run_disposition``: a human's closure of a dirty run, signed.

Reconciliation can already tell a clean run from a dirty one, and it invalidates the dirty
ones so they can never execute again. What it cannot do is *finish the story*: a dirty run
stays outstanding forever, resurfacing at every startup, because nothing durable records
that a human looked at it and closed it. OpenClaw's Step 7C.1 verdict does not close it
either — verdicts are plural and deliberately non-terminal.

This module adds the missing fact. Doctrine, in the order it matters:

  * **A human decides; the runtime only records.** The disposition is owner-gated, the
    ``human_actor`` is the authenticated owner identity, and no model, planner, executor or
    verifier may issue one. OpenClaw reaches verdicts; it never disposes.
  * **The gateway signs it.** Disposition is an authority-plane fact about a run, so it is
    emitted under the gateway's existing emitter key — no new key, no new custody.
  * **The caller never hands over an evidence envelope.** The client names a *basis* by
    typed :class:`~openclaw.sink.EvidenceRef`; the server re-resolves it against the
    verified chain (recomputing the digest), checks its type, emitter and run/approval
    binding, and constructs and signs the record itself.
  * **Evidence still never grants authority.** A disposition is only accepted for a run the
    authority store already holds, and only when nothing on that run could still execute.
    The one authority effect it has is monotone and restricting — it *seals* the run through
    the existing ``invalidate_run`` barrier, so terminality is enforced where every other
    check already looks rather than living only in the evidence log. Nothing is reopened,
    restored, retried, or granted.

**The basis model** is the part that needed correcting from the original sketch. A verdict
reference cannot be mandatory: the archetypal run needing disposition is a Class-3 dirty run
whose authority was consumed and whose mutation may have started but which has **no valid
``apply_result``** — and a 7C.1 ``verification_result`` is apply-bound, so no legitimate
verdict can exist for it. Requiring one would make exactly the runs that need human closure
permanently undisposable. So the basis is explicit and narrow:

===================== ==================================================================
``basis_type``         what it means
===================== ==================================================================
``verification_result`` a specific OpenClaw verdict the human read before deciding
``execute_validated``   the exact reservation that established the possibly-started
                        execution, for a run where no verdict can legitimately exist
===================== ==================================================================

There is no third option and no "no basis" path, and when several verdicts exist the caller
must name **one** — this module never picks latest, never picks first, and never infers.

**The disposition values** are kept as small as honesty allows.
:data:`DISPOSITION_CLOSED_UNKNOWN` is the default and the only one that asserts nothing: the
runtime cannot determine whether the mutation landed, a human acknowledges that, and the run
is closed permanently as *unknown*. The two ``human_asserted_*`` values exist because a human
who went and looked at the target may genuinely know more than the runtime does — their names
say whose claim it is. Nothing derives them: not OpenClaw, not reconciliation, not this
module. They do not convert unknown system evidence into known fact.

**Terminality.** At most one disposition per run, enforced under a per-run critical section
and re-checked against the verified chain. A second attempt is refused with
:data:`CODE_ALREADY_DISPOSED` rather than superseding the first; late ``apply_result`` or
``verification_result`` records may still append (the log is append-only) but cannot
resurrect the run or supersede its closure.

Out of scope here, deliberately: rollback and containment (Step 7C.3).
"""

from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

from private_ai_gateway.approvals import ApprovalStatus, RunStatus

RUN_DISPOSITION_RECORD_TYPE = "run_disposition"

# --- the basis vocabulary -------------------------------------------------------------
BASIS_VERIFICATION_RESULT = "verification_result"
BASIS_EXECUTION_RESERVATION = "execute_validated"
BASIS_TYPES = (BASIS_VERIFICATION_RESULT, BASIS_EXECUTION_RESERVATION)

# --- the disposition vocabulary -------------------------------------------------------
DISPOSITION_CLOSED_UNKNOWN = "closed_unknown"
DISPOSITION_HUMAN_ASSERTED_APPLIED = "human_asserted_applied"
DISPOSITION_HUMAN_ASSERTED_NOT_APPLIED = "human_asserted_not_applied"
DISPOSITIONS = (
    DISPOSITION_CLOSED_UNKNOWN,
    DISPOSITION_HUMAN_ASSERTED_APPLIED,
    DISPOSITION_HUMAN_ASSERTED_NOT_APPLIED,
)

# --- refusal codes (governed, client-safe) --------------------------------------------
CODE_INVALID_DISPOSITION = "invalid_disposition"
CODE_INVALID_BASIS_TYPE = "invalid_basis_type"
CODE_BASIS_MALFORMED = "basis_malformed"
CODE_BASIS_UNRESOLVED = "basis_unresolved"
CODE_BASIS_TYPE_MISMATCH = "basis_type_mismatch"
CODE_BASIS_EMITTER_INVALID = "basis_emitter_invalid"
CODE_BASIS_RUN_MISMATCH = "basis_run_mismatch"
CODE_BASIS_APPROVAL_MISMATCH = "basis_approval_mismatch"
CODE_RUN_NOT_FOUND = "run_not_found"
CODE_APPROVAL_NOT_FOUND = "approval_not_found"
CODE_RUN_NOT_TERMINAL = "run_not_terminal"
CODE_ALREADY_DISPOSED = "already_disposed"
CODE_AMBIGUOUS_DISPOSITION = "ambiguous_disposition"
CODE_HUMAN_ACTOR_REQUIRED = "human_actor_required"
CODE_EVIDENCE_UNAVAILABLE = "disposition_evidence_unavailable"

# Which emitter is allowed to have authored each kind of basis. A verdict signed by anyone
# but the verifier, or a reservation signed by anyone but the gateway, is not a basis.
_BASIS_EMITTERS = {
    BASIS_VERIFICATION_RESULT: "openclaw",
    BASIS_EXECUTION_RESERVATION: "gateway",
}


class DispositionError(Exception):
    """A disposition was refused. ``code`` is the governed, client-safe reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


@dataclass(frozen=True)
class ValidatedDisposition:
    """One ``run_disposition`` record that survived full re-validation."""

    run_id: str
    approval_id: str
    disposition: str
    basis_type: str
    human_actor: str
    evidence_id: str

    @property
    def asserts_outcome(self) -> bool:
        """True when a *human* claimed an outcome the runtime could not determine."""
        return self.disposition != DISPOSITION_CLOSED_UNKNOWN


# --- the per-run critical section -----------------------------------------------------
# Same argument as the Step 7B.1 reservation lock, and sound for the same reason: both
# durable stores are held under an exclusive ``flock`` for the owning process's lifetime, so
# there is no second writer to coordinate with. Without it, two concurrent disposals could
# each pass the "already disposed?" check and each append, leaving two terminal records for
# one run — which this module then (correctly) treats as an unreadable, fail-closed state.
_DISPOSITION_LOCKS: dict[str, threading.Lock] = {}
_DISPOSITION_WAITERS: dict[str, int] = {}
_DISPOSITION_LOCKS_GUARD = threading.Lock()


@contextmanager
def _run_disposition_lock(run_id: str):
    """Serialize check -> append for one ``run_id``; entries are reference-counted."""
    with _DISPOSITION_LOCKS_GUARD:
        entry = _DISPOSITION_LOCKS.get(run_id)
        if entry is None:
            entry = _DISPOSITION_LOCKS[run_id] = threading.Lock()
        _DISPOSITION_WAITERS[run_id] = _DISPOSITION_WAITERS.get(run_id, 0) + 1
    try:
        with entry:
            yield
    finally:
        with _DISPOSITION_LOCKS_GUARD:
            remaining = _DISPOSITION_WAITERS.get(run_id, 1) - 1
            if remaining <= 0:
                _DISPOSITION_WAITERS.pop(run_id, None)
                _DISPOSITION_LOCKS.pop(run_id, None)
            else:
                _DISPOSITION_WAITERS[run_id] = remaining


# --- reading dispositions off a verified chain ----------------------------------------
def _disposition_records(records, run_id: str) -> list:
    """Every gateway-emitted ``run_disposition`` naming ``run_id`` (no validation yet)."""
    out = []
    for rec in records:
        env = getattr(rec, "envelope", None)
        if env is None or env.record_type != RUN_DISPOSITION_RECORD_TYPE:
            continue
        if (env.run_id or "") != run_id:
            continue
        out.append(rec)
    return out


def validate_disposition_record(record, records, *, sink_id: str) -> ValidatedDisposition:
    """Fully re-validate one ``run_disposition`` against the verified chain.

    Checks authorship (the gateway, under the authority plane's own key — enforced by the
    sink's signature verification plus the emitter check here), the payload shape, the
    disposition vocabulary, and then the basis: it must resolve to exactly one record in this
    sink by ``evidence_id`` **and recomputed digest**, be of the declared type, be authored by
    the emitter entitled to author that type, and be bound to the same run and approval.

    Raises :class:`DispositionError` on any failure — a disposition that does not re-validate
    is never treated as absent, because "unreadable" must not read as "not yet disposed".
    """
    from openclaw.sink import EMITTER_GATEWAY, EvidenceError, EvidenceRef

    env = record.envelope
    if env.emitter != EMITTER_GATEWAY:
        raise DispositionError(
            CODE_BASIS_EMITTER_INVALID,
            f"run_disposition emitter is {env.emitter!r}, not the authority plane",
        )
    payload = record.payload if isinstance(record.payload, dict) else None
    if payload is None:
        raise DispositionError(CODE_BASIS_MALFORMED, "run_disposition payload is not a mapping")

    disposition = payload.get("disposition")
    if disposition not in DISPOSITIONS:
        raise DispositionError(
            CODE_INVALID_DISPOSITION, f"unknown disposition {disposition!r}"
        )
    basis_type = payload.get("basis_type")
    if basis_type not in BASIS_TYPES:
        raise DispositionError(CODE_INVALID_BASIS_TYPE, f"unknown basis_type {basis_type!r}")
    human_actor = payload.get("human_actor") or ""
    if not human_actor:
        raise DispositionError(CODE_HUMAN_ACTOR_REQUIRED, "run_disposition names no human")

    try:
        ref = EvidenceRef.from_mapping(payload.get("basis_ref"))
    except EvidenceError as exc:
        raise DispositionError(CODE_BASIS_MALFORMED, str(exc)) from exc
    _resolve_basis(
        records,
        ref,
        sink_id=sink_id,
        basis_type=basis_type,
        run_id=env.run_id or "",
        approval_id=env.approval_id or "",
    )
    return ValidatedDisposition(
        run_id=env.run_id or "",
        approval_id=env.approval_id or "",
        disposition=disposition,
        basis_type=basis_type,
        human_actor=human_actor,
        evidence_id=env.evidence_id,
    )


def disposition_for_run(records, *, sink_id: str, run_id: str) -> ValidatedDisposition | None:
    """The one valid terminal disposition for ``run_id``, or ``None`` if there is none.

    Fails closed rather than guessing: more than one ``run_disposition`` for a run is
    :data:`CODE_AMBIGUOUS_DISPOSITION` (never "latest wins"), and a single one that does not
    re-validate raises whatever its validation failure was.
    """
    found = _disposition_records(records, run_id)
    if not found:
        return None
    if len(found) > 1:
        raise DispositionError(
            CODE_AMBIGUOUS_DISPOSITION,
            f"{len(found)} run_disposition records for run {run_id!r}",
        )
    return validate_disposition_record(found[0], records, sink_id=sink_id)


def live_authority(authority_store, run_id: str) -> tuple:
    """Approvals on ``run_id`` that could still authorize an execute.

    "Terminal" for disposition purposes is defined by *authority*, not by run status alone: a
    run whose graph completed is still OPEN, and a run reconciliation invalidated is closed.
    Both are finished history. What must never be disposed is a run something could still
    execute against.
    """
    run = authority_store.get_run(run_id)
    if run is not None and run.status is RunStatus.INVALIDATED:
        return ()
    return tuple(
        appr for appr in authority_store.snapshot_approvals()
        if appr.run_id == run_id
        and appr.approval_status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)
    )


# --- recording a disposition ----------------------------------------------------------
def dispose_run(
    authority_store,
    evidence_sink,
    *,
    run_id: str,
    approval_id: str,
    disposition: str,
    basis_type: str,
    basis_ref: object,
    human_actor: str,
    signing_key: bytes,
    key_id: str,
) -> ValidatedDisposition:
    """Record one terminal ``run_disposition``; refuse anything that is not exactly that.

    The order is deliberate: cheap vocabulary checks, then the **authority** projection (the
    run and approval must exist, and no approval on the run may still be executable), then the
    chain is verified, then the basis is resolved against it, then — inside the run's critical
    section and after a final terminal-record re-check — the run is sealed and the record is
    signed and appended.

    Authority is touched in exactly one way, and only in the restricting direction:
    :meth:`invalidate_run`, so "terminal" is enforced by the same barrier everything else
    already respects rather than living only in the evidence log. Nothing is reopened,
    restored, retried or granted. The seal is applied *before* the append, so the worst
    residue of a failed append is a run closed slightly early — never a run recorded as
    disposed while it is still able to execute.
    """
    from openclaw.sink import (
        EMITTER_GATEWAY,
        SCHEMA_VERSION,
        EvidenceError,
        EvidenceRef,
        SigningEnvelope,
        new_evidence_id,
        payload_digest,
        sign_envelope,
    )

    if disposition not in DISPOSITIONS:
        raise DispositionError(CODE_INVALID_DISPOSITION, f"unknown disposition {disposition!r}")
    if basis_type not in BASIS_TYPES:
        raise DispositionError(CODE_INVALID_BASIS_TYPE, f"unknown basis_type {basis_type!r}")
    if not human_actor:
        raise DispositionError(CODE_HUMAN_ACTOR_REQUIRED, "an authenticated human is required")
    if evidence_sink is None:
        raise DispositionError(
            CODE_EVIDENCE_UNAVAILABLE, "no evidence sink is configured to record a disposition"
        )
    if not signing_key or not key_id:
        raise DispositionError(
            CODE_EVIDENCE_UNAVAILABLE, "no authority-plane signing key is configured"
        )
    try:
        ref = EvidenceRef.from_mapping(basis_ref)
    except EvidenceError as exc:
        raise DispositionError(CODE_BASIS_MALFORMED, str(exc)) from exc

    # Authority projection first: evidence may never conjure the run it closes.
    run = authority_store.get_run(run_id)
    if run is None:
        raise DispositionError(CODE_RUN_NOT_FOUND, f"unknown run {run_id!r}")
    approval = authority_store.get_approval(approval_id)
    if approval is None or approval.run_id != run_id:
        raise DispositionError(
            CODE_APPROVAL_NOT_FOUND, f"approval {approval_id!r} does not belong to this run"
        )
    live = live_authority(authority_store, run_id)
    if live:
        # Disposition closes finished history. A run with authority still standing is not
        # finished, and disposal must never double as a covert kill switch for a live run.
        raise DispositionError(
            CODE_RUN_NOT_TERMINAL,
            f"run {run_id!r} still has {len(live)} executable approval(s); only a run with "
            f"no standing authority can be disposed",
        )

    payload = {
        "disposition": disposition,
        "basis_type": basis_type,
        "basis_ref": ref.to_mapping(),
        "human_actor": human_actor,
    }

    with _run_disposition_lock(run_id):
        # Re-verify inside the lock: the chain must re-derive, the basis must resolve against
        # it, and no terminal record may already exist. Everything below is one indivisible
        # check-then-append for this run.
        try:
            evidence_sink.verify_chain()
            records = tuple(evidence_sink.records)
        except EvidenceError as exc:
            raise DispositionError(
                CODE_EVIDENCE_UNAVAILABLE, f"evidence chain did not verify: {exc}"
            ) from exc

        existing = disposition_for_run(records, sink_id=evidence_sink.sink_id, run_id=run_id)
        if existing is not None:
            raise DispositionError(
                CODE_ALREADY_DISPOSED,
                f"run {run_id!r} is already disposed as {existing.disposition!r}",
            )

        _resolve_basis(
            records,
            ref,
            sink_id=evidence_sink.sink_id,
            basis_type=basis_type,
            run_id=run_id,
            approval_id=approval_id,
        )

        # Seal the run before recording the closure. ``invalidate_run`` is monotone and
        # restricting: with no standing approval it only moves the run to INVALIDATED, so
        # from here no fresh approval can be created against it and no execute can validate.
        try:
            authority_store.invalidate_run(run_id)
        except Exception as exc:  # noqa: BLE001 — an unsealed run must not read as disposed
            raise DispositionError(
                CODE_EVIDENCE_UNAVAILABLE, f"the run could not be sealed before closure: {exc}"
            ) from exc

        envelope = SigningEnvelope(
            schema_version=SCHEMA_VERSION,
            evidence_id=new_evidence_id(),
            sink_id=evidence_sink.sink_id,
            run_id=run_id,
            approval_id=approval_id,
            emitter=EMITTER_GATEWAY,
            emitter_key_id=key_id,
            record_type=RUN_DISPOSITION_RECORD_TYPE,
            payload_hash=payload_digest(payload),
            ts=datetime.now(timezone.utc).isoformat(),
            nonce=uuid.uuid4().hex,
        )
        try:
            appended = evidence_sink.append(
                envelope, payload, sign_envelope(envelope, bytes(signing_key))
            )
        except EvidenceError as exc:
            raise DispositionError(
                CODE_EVIDENCE_UNAVAILABLE, f"run_disposition could not be appended: {exc}"
            ) from exc

    return ValidatedDisposition(
        run_id=run_id,
        approval_id=approval_id,
        disposition=disposition,
        basis_type=basis_type,
        human_actor=human_actor,
        evidence_id=appended.envelope.evidence_id,
    )


def _resolve_basis(records, ref, *, sink_id, basis_type, run_id, approval_id):
    """Resolve and bind the caller-named basis; raise :class:`DispositionError` on any miss.

    The single place the basis rules live, so recording and re-validation cannot drift: the
    reference must name exactly one record whose **recomputed** digest matches, of the
    declared type, authored by the emitter entitled to author that type, bound to this run
    and this approval.
    """
    from openclaw.sink import EvidenceError, resolve_evidence_ref

    if ref.record_type != basis_type:
        raise DispositionError(
            CODE_BASIS_TYPE_MISMATCH,
            f"basis_ref record_type is {ref.record_type!r}, not {basis_type!r}",
        )
    try:
        basis = resolve_evidence_ref(records, ref, sink_id=sink_id)
    except EvidenceError as exc:
        raise DispositionError(CODE_BASIS_UNRESOLVED, str(exc)) from exc
    env = basis.envelope
    if env.emitter != _BASIS_EMITTERS[basis_type]:
        raise DispositionError(
            CODE_BASIS_EMITTER_INVALID,
            f"a {basis_type} basis authored by {env.emitter!r} is not authoritative",
        )
    if (env.run_id or "") != run_id:
        raise DispositionError(CODE_BASIS_RUN_MISMATCH, "the basis belongs to a different run")
    if (env.approval_id or "") != approval_id:
        raise DispositionError(
            CODE_BASIS_APPROVAL_MISMATCH, "the basis belongs to a different approval"
        )
    return basis
