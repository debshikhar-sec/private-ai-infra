"""Step 7C.3B — governed rollback: the authority half, and why it is a plan, not a button.

A rollback undoes a mutation, which makes it a **mutation**. It therefore gets exactly the
same treatment as any other write in this runtime, and reuses exactly the same machinery
rather than inventing a privileged repair path:

  ``plan -> owner approval (hash-bound) -> validate -> reserve -> mutate -> signed outcome``

That is the Step 7B.1 append-first ordering, unchanged. A rollback is a **new governed run**
with its own ``run_id``, its own single-use approval, and its own canonical plan hash — so
there is no second approval system, no reuse of the original run's spent authority, and no
way for an agent to grant itself an undo.

What the plan hash commits to is the whole point. It covers the original run, the original
approval, the exact signed ``apply_result`` being reversed, and the pre-image snapshot's
identity **and digest**. An owner approving a rollback is therefore approving one specific
restoration of one specific tree to one specific recorded state — not "undo something".

Fail-closed properties this holds:

  * **No pre-image, no rollback.** A run whose apply predates Step 7C.3A has no snapshot and
    can never be rolled back. Nothing is fabricated for it, and the refusal says so plainly.
  * **The workspace is confined.** A caller names a workspace *relative to* a configured
    sandbox runtime root; anything that escapes that root is refused before anything is read.
  * **Reconciliation never triggers a rollback.** This module is called only from an
    owner-authenticated request. Nothing schedules it, retries it, or infers it.
  * **A failure is never a success.** A refusal before the reservation spends no authority
    and touches nothing — there is no unknown state, so nothing is contained. A failure after
    it means the sandbox may have been written to: the executor contains the workspace, signs
    a *failed* outcome, and the rollback run is invalidated. No partial success, no retry.
  * **OpenClaw judges it, not the executor.** The executor signs *what it did*; whether that
    is a correct restoration is the verifier's signed verdict (Step 7C.1's rule, extended to
    carry a ``rollback_ref``).

Out of scope, hard: git operations, deployment rollback, system configuration, production
external rollback, any path outside the sandbox runtime root.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

ROLLBACK_VALIDATED_RECORD_TYPE = "rollback_validated"

CODE_APPLY_NOT_FOUND = "apply_not_found"
CODE_NOT_REVERSIBLE = "run_not_reversible"
CODE_WORKSPACE_UNCONFINED = "workspace_unconfined"
CODE_WORKSPACE_MISSING = "workspace_missing"
CODE_SNAPSHOT_UNUSABLE = "snapshot_unusable"
CODE_RUN_DISPOSED = "run_already_disposed"
CODE_EVIDENCE_UNAVAILABLE = "rollback_evidence_unavailable"
CODE_NOT_AUTHORIZED = "rollback_not_authorized"
CODE_RESERVATION_FAILED = "rollback_reservation_failed"
CODE_ALREADY_ROLLED_BACK = "already_rolled_back"


class RollbackError(Exception):
    """A rollback was refused. ``code`` is the governed, client-safe reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


@dataclass(frozen=True)
class RollbackPlan:
    """One specific restoration, ready for an owner to approve or refuse."""

    rollback_run_id: str
    canonical_plan_hash: str
    origin_run_id: str
    origin_approval_id: str
    workspace: str
    snapshot_id: str
    snapshot_digest: str
    restores: tuple[str, ...]

    def to_mapping(self) -> dict:
        return {
            "rollback_run_id": self.rollback_run_id,
            "canonical_plan_hash": self.canonical_plan_hash,
            "origin_run_id": self.origin_run_id,
            "origin_approval_id": self.origin_approval_id,
            "workspace": self.workspace,
            "snapshot_id": self.snapshot_id,
            "snapshot_digest": self.snapshot_digest,
            "restores": list(self.restores),
        }


def _confined_workspace(runtime_root, workspace: str) -> Path:
    """Select an existing sandbox workspace **by name**, never by path.

    The obvious implementation — join the caller's string to the root, resolve, and check the
    result is still underneath — is a path built *from untrusted input*, and it is only as
    safe as the check that follows it. This does not build one. It enumerates the immediate
    child directories of the configured root and looks the name up among them, so the path
    that reaches the filesystem comes from ``iterdir()`` and the caller's string is only ever
    compared for equality.

    That closes the whole class rather than one instance of it: traversal, absolute paths,
    nesting, and a symlinked entry pointing outside the root are all excluded by
    construction, not by a predicate someone has to keep correct.
    """
    if not runtime_root:
        raise RollbackError(
            CODE_WORKSPACE_UNCONFINED, "no sandbox runtime root is configured"
        )
    if not workspace or "/" in workspace or "\\" in workspace or workspace.startswith("."):
        raise RollbackError(
            CODE_WORKSPACE_UNCONFINED,
            "a workspace is named, not pathed: one immediate child of the runtime root",
        )
    root = Path(runtime_root)
    try:
        children = {
            entry.name: entry
            for entry in root.iterdir()
            if entry.is_dir() and not entry.is_symlink()
        }
    except OSError as exc:
        raise RollbackError(
            CODE_WORKSPACE_UNCONFINED, f"the sandbox runtime root is unreadable: {exc}"
        ) from exc
    resolved = children.get(workspace)
    if resolved is None:
        raise RollbackError(CODE_WORKSPACE_MISSING, "no such sandbox workspace")
    return resolved


def _apply_record(records, *, run_id, approval_id):
    from openclaw.evidence import APPLY_RESULT_RECORD_TYPE
    from openclaw.sink import EMITTER_OPENCODE, EvidenceError, find_unique_record

    try:
        return find_unique_record(
            records, emitter=EMITTER_OPENCODE, record_type=APPLY_RESULT_RECORD_TYPE,
            run_id=run_id, approval_id=approval_id,
        )
    except EvidenceError as exc:
        raise RollbackError(
            CODE_APPLY_NOT_FOUND, f"no unique signed apply_result for this run: {exc}"
        ) from exc


def plan_rollback(
    authority_store,
    evidence_sink,
    *,
    origin_run_id: str,
    origin_approval_id: str,
    workspace: str,
    runtime_root,
    principal_id: str,
    policy_ceiling: int,
) -> RollbackPlan:
    """Build one specific, hash-bound restoration and register it as a new governed run.

    Reads only. It creates the run an owner will approve against — the same object any other
    mutation is approved against — and creates no approval of its own, because a plan is
    capability and an approval is authority.
    """
    from openclaw.evidence import SinkGraphReader
    from openclaw.sink import payload_digest

    if evidence_sink is None:
        raise RollbackError(CODE_EVIDENCE_UNAVAILABLE, "no evidence sink is configured")
    reader = SinkGraphReader(evidence_sink)
    if reader.chain_error:
        raise RollbackError(CODE_EVIDENCE_UNAVAILABLE, reader.chain_error)

    _refuse_if_disposed(reader, origin_run_id)
    _refuse_if_already_rolled_back(reader.records, origin_run_id, origin_approval_id)

    apply_rec = _apply_record(
        reader.records, run_id=origin_run_id, approval_id=origin_approval_id
    )
    payload = apply_rec.payload if isinstance(apply_rec.payload, dict) else {}
    preimage = payload.get("preimage")
    if not isinstance(preimage, dict) or not preimage.get("snapshot_id"):
        # An apply that predates Step 7C.3A carries no pre-image and never will. Saying so
        # is the honest answer; inventing reversibility for it would not be.
        raise RollbackError(
            CODE_NOT_REVERSIBLE,
            "this apply recorded no pre-image, so it is not reversible; only applies made "
            "with a snapshot store can be rolled back",
        )

    resolved = _confined_workspace(runtime_root, workspace)
    snapshot = _load_snapshot(resolved, preimage)

    plan_mapping = {
        "action": "sandbox_rollback",
        "origin_run_id": origin_run_id,
        "origin_approval_id": origin_approval_id,
        "apply_evidence_id": apply_rec.envelope.evidence_id,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_digest": snapshot.digest,
        "workspace": workspace,
        "restores": sorted(e.path for e in snapshot.entries),
    }
    canonical_plan_hash = payload_digest(plan_mapping)

    rollback_run_id = "rbrun-" + uuid.uuid4().hex
    authority_store.create_run(
        run_id=rollback_run_id,
        principal_id=principal_id,
        canonical_plan_hash=canonical_plan_hash,
        effective_autonomy=policy_ceiling,
        policy_ceiling=policy_ceiling,
    )
    return RollbackPlan(
        rollback_run_id=rollback_run_id,
        canonical_plan_hash=canonical_plan_hash,
        origin_run_id=origin_run_id,
        origin_approval_id=origin_approval_id,
        workspace=workspace,
        snapshot_id=snapshot.snapshot_id,
        snapshot_digest=snapshot.digest,
        restores=tuple(plan_mapping["restores"]),
    )


def _load_snapshot(resolved_workspace: Path, preimage: dict):
    from opencode_sandbox.preimage import PreimageError, load_preimage

    try:
        snapshot = load_preimage(resolved_workspace / "preimage", preimage["snapshot_id"])
    except PreimageError as exc:
        raise RollbackError(
            CODE_SNAPSHOT_UNUSABLE, f"{exc.code}: {exc.detail}"
        ) from exc
    if snapshot.digest != preimage.get("snapshot_digest"):
        raise RollbackError(
            CODE_SNAPSHOT_UNUSABLE,
            "the snapshot in this workspace is not the one the signed apply evidence names",
        )
    return snapshot


def _refuse_if_disposed(reader, origin_run_id: str) -> None:
    """A terminally disposed run is closed. Undoing it would reopen closed history."""
    from private_ai_gateway.disposition import DispositionError, disposition_for_run

    try:
        existing = disposition_for_run(
            reader.records, sink_id=reader.sink_id, run_id=origin_run_id
        )
    except DispositionError as exc:
        raise RollbackError(CODE_EVIDENCE_UNAVAILABLE, f"{exc.code}: {exc.detail}") from exc
    if existing is not None:
        raise RollbackError(
            CODE_RUN_DISPOSED,
            f"run {origin_run_id!r} was terminally disposed as {existing.disposition!r}; "
            "a closed run is not reopened to be undone",
        )


def _refuse_if_already_rolled_back(records, origin_run_id, origin_approval_id) -> None:
    """One rollback per apply. A second is a new unknown state, not a second chance."""
    from opencode_sandbox.rollback import RESTORED, ROLLBACK_RESULT_RECORD_TYPE

    for rec in records:
        env = rec.envelope
        if env.record_type != ROLLBACK_RESULT_RECORD_TYPE:
            continue
        payload = rec.payload if isinstance(rec.payload, dict) else {}
        if payload.get("origin_run_id") != origin_run_id:
            continue
        if payload.get("status") == RESTORED:
            raise RollbackError(
                CODE_ALREADY_ROLLED_BACK,
                f"run {origin_run_id!r} has already been rolled back",
            )


def execute_rollback(
    gw,
    *,
    rollback_run_id: str,
    approval_id: str,
    origin_run_id: str,
    origin_approval_id: str,
    workspace: str,
) -> dict:
    """Validate, reserve, restore, and record — in that order, once.

    The ordering is Step 7B.1's, for Step 7B.1's reason: the durable ``rollback_validated``
    reservation is appended **before** the single-use approval is consumed, so a crash in that
    window cannot leave spent authority with no trace. Startup reconciliation then treats the
    rollback run exactly as it treats any other — a reservation that outlives a crash is
    invalidated, and a consumed approval with no usable outcome is dirty and never retried.

    Returns a governed transcript. Refusals raise :class:`RollbackError`; nothing here
    executes anything on the strength of the request alone.
    """
    import os

    from openclaw.sink import EvidenceError

    from private_ai_gateway import orchestration

    authority_store = gw.APPROVAL_STORE
    evidence_sink = getattr(gw, "EVIDENCE_SINK", None)
    if evidence_sink is None:
        raise RollbackError(CODE_EVIDENCE_UNAVAILABLE, "no evidence sink is configured")

    run = authority_store.get_run(rollback_run_id)
    if run is None:
        raise RollbackError(CODE_NOT_AUTHORIZED, "unknown rollback run")

    with orchestration._approval_execution_lock(approval_id or rollback_run_id):
        decision = authority_store.validate_for_execute(
            rollback_run_id, approval_id, run.canonical_plan_hash
        )
        if not decision.ok:
            raise RollbackError(
                CODE_NOT_AUTHORIZED,
                f"the rollback is not authorized ({decision.reason})",
            )

        resolved = _confined_workspace(
            getattr(gw, "SANDBOX_RUNTIME_ROOT", None), workspace
        )
        reader_records, sink_id = _verified_records(evidence_sink)
        apply_rec = _apply_record(
            reader_records, run_id=origin_run_id, approval_id=origin_approval_id
        )
        preimage = (apply_rec.payload or {}).get("preimage") or {}
        snapshot = _load_snapshot(resolved, preimage)

        # -- reserve (append-first), then consume --
        emit = orchestration._emit_gateway_evidence(
            gw,
            run_id=rollback_run_id,
            approval_id=approval_id,
            record_type=ROLLBACK_VALIDATED_RECORD_TYPE,
            payload={
                "canonical_plan_hash": run.canonical_plan_hash,
                "validated": True,
                "origin_run_id": origin_run_id,
                "origin_approval_id": origin_approval_id,
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_digest": snapshot.digest,
                "apply_ref": apply_rec.evidence_ref().to_mapping(),
            },
            log_label="ROLLBACK_VALIDATED",
        )
        if not emit.proceed or emit.evidence_ref is None:
            authority_store.invalidate_run(rollback_run_id)
            raise RollbackError(
                CODE_RESERVATION_FAILED,
                "the rollback reservation could not be recorded; nothing was restored",
            )
        authority_store.mark_used(approval_id)

    # -- mutate, under the executor's own key --
    from openclaw.assurance import emitter_signing_key
    from openclaw.sink import EMITTER_OPENCODE
    from opencode_sandbox import rollback as executor

    key, key_id = emitter_signing_key(os.environ, EMITTER_OPENCODE)
    try:
        outcome = executor.perform_rollback(
            workspace=resolved,
            sandbox=resolved / "sandbox",
            snapshot_id=snapshot.snapshot_id,
            snapshot_digest=snapshot.digest,
            reservation_ref=emit.evidence_ref,
            apply_ref=apply_rec.evidence_ref(),
            run_id=rollback_run_id,
            origin_run_id=origin_run_id,
            approval_id=approval_id,
            evidence_sink=evidence_sink,
            evidence_key=key,
            emitter_key_id=key_id,
        )
    except (executor.RollbackExecutionError, EvidenceError) as exc:
        # The outcome could not be recorded. The sandbox may be half-restored, so this is
        # contained and the run invalidated — never reported as anything but a failure.
        executor.contain_workspace(
            resolved, reason=f"rollback outcome unrecordable: {exc}", run_id=rollback_run_id
        )
        authority_store.invalidate_run(rollback_run_id)
        raise RollbackError(CODE_EVIDENCE_UNAVAILABLE, str(exc)) from exc

    if not outcome.restored:
        # A failed rollback closes its own run: the authority was spent and must never be
        # reusable, and the workspace the executor contained stays contained.
        authority_store.invalidate_run(rollback_run_id)

    return {
        "rollback_run_id": rollback_run_id,
        "origin_run_id": origin_run_id,
        "status": outcome.status,
        "restored": outcome.restored,
        "restored_files": list(outcome.restored_files),
        "contained": outcome.contained,
        "reason": outcome.reason,
        "human_action_required": outcome.contained,
        "snapshot_id": snapshot.snapshot_id,
        "scope": "the supported sandbox state only; no external effect is claimed",
    }


def _verified_records(evidence_sink):
    from openclaw.evidence import SinkGraphReader

    reader = SinkGraphReader(evidence_sink)
    if reader.chain_error:
        raise RollbackError(CODE_EVIDENCE_UNAVAILABLE, reader.chain_error)
    return reader.records, reader.sink_id


def rollback_results_for(evidence_sink, *, run_id=None) -> tuple:
    """Every signed rollback outcome for a rollback run, oldest first.

    Plural for the same reason 7C.1's verdicts are: a failed attempt is still a fact, and
    resolving several records to "the real one" would be a hidden authority rule.
    """
    from openclaw.sink import EMITTER_OPENCODE
    from opencode_sandbox.rollback import ROLLBACK_RESULT_RECORD_TYPE

    if evidence_sink is None:
        return ()
    out = []
    for rec in tuple(evidence_sink.records):
        env = getattr(rec, "envelope", None)
        if env is None or env.record_type != ROLLBACK_RESULT_RECORD_TYPE:
            continue
        if env.emitter != EMITTER_OPENCODE:
            continue
        if run_id is not None and (env.run_id or "") != run_id:
            continue
        out.append(rec)
    return tuple(out)


