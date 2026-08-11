"""Step 7C.3B — the executor half of a governed rollback, and containment when it fails.

Step 7C.3A made a future sandbox apply *reversible in principle*: a bounded pre-image is
captured before the first declared write, and :func:`~opencode_sandbox.preimage.restore_into`
can put the tree back byte for byte. Nothing could call it, deliberately. This module is what
calls it — under authority it does not itself hold.

The doctrine that shapes every line here:

  * **A rollback is a mutation, not a repair.** It is not a correction the runtime applies to
    tidy up after itself; it is a fresh write that needs its own owner approval, its own
    single-use reservation, and its own signed outcome. The gateway supplies all three (see
    ``private_ai_gateway.rollback``); this module refuses to run without the reservation it
    is handed.
  * **A rollback failure must never become a success.** Every failure path emits a signed
    ``rollback_result`` with a *failed* status. Nothing is retried, nothing is partially
    reported as restored, and the sandbox is **contained** — marked unusable — so a workspace
    in an unknown half-restored state cannot quietly be reused.
  * **The executor signs its own outcome and nothing else.** It reports what it did; whether
    that constitutes a correct restoration is OpenClaw's judgment, signed with OpenClaw's own
    key (Step 7C.1's rule, unchanged).
  * **Restoring the sandbox is not undoing the world.** A successful rollback says exactly
    one thing: *the supported sandbox state was restored to the recorded pre-image*. There is
    no external mutation in this scope, so there is no external effect to claim was undone.

Out of scope, hard: git operations, deployment rollback, system configuration, any path
outside the sandbox workspace.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from opencode_sandbox.preimage import (
    PreimageError,
    load_preimage,
    restore_into,
)

ROLLBACK_RESULT_RECORD_TYPE = "rollback_result"

# Outcomes. Only ``RESTORED`` is a success, and it is reachable only when every step —
# snapshot re-verification, the restore itself, and the post-restore re-hash — succeeded.
RESTORED = "restored"
FAILED = "failed"

CONTAINMENT_MARKER = ".contained.json"

R_NO_RESERVATION = "no_rollback_reservation"
R_WORKSPACE_CONTAINED = "workspace_contained"
R_SNAPSHOT_UNUSABLE = "snapshot_unusable"
R_RESTORE_FAILED = "restore_failed"
R_POST_RESTORE_MISMATCH = "post_restore_mismatch"


class RollbackExecutionError(Exception):
    """The rollback outcome could not even be recorded — the loudest possible failure."""


@dataclass(frozen=True)
class RollbackOutcome:
    """What the executor did, and whether the workspace is now contained."""

    status: str
    restored_files: tuple[str, ...] = ()
    contained: bool = False
    reason: str = ""
    evidence_ref: object | None = None

    @property
    def restored(self) -> bool:
        return self.status == RESTORED


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def contain_workspace(workspace: str | Path, *, reason: str, run_id: str = "") -> Path:
    """Mark a workspace unusable and say why. Idempotent; never deletes anything.

    Containment is deliberately the *weakest* thing that is still honest. It does not
    quarantine infrastructure, kill processes, or touch anything outside the workspace
    directory — it records that this sandbox is in an unknown state and must not be reused,
    and leaves everything in place for a human to inspect.
    """
    marker = Path(workspace) / CONTAINMENT_MARKER
    if marker.exists():
        return marker
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps(
            {"contained_at": _utc_now_iso(), "run_id": run_id, "reason": reason,
             "human_action_required": True},
            indent=2, sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    return marker


def containment_reason(workspace: str | Path) -> str:
    """The recorded containment reason, or ``""`` when the workspace is usable."""
    marker = Path(workspace) / CONTAINMENT_MARKER
    if not marker.is_file():
        return ""
    try:
        return str(json.loads(marker.read_text(encoding="utf-8")).get("reason", "contained"))
    except (OSError, ValueError):  # an unreadable marker still means contained
        return "contained (marker unreadable)"


def perform_rollback(
    *,
    workspace: str | Path,
    sandbox: str | Path,
    snapshot_id: str,
    snapshot_digest: str,
    reservation_ref,
    apply_ref,
    run_id: str,
    origin_run_id: str,
    approval_id: str,
    evidence_sink,
    evidence_key: bytes,
    emitter_key_id: str,
) -> RollbackOutcome:
    """Restore ``sandbox`` to its recorded pre-image, then sign what happened.

    Ordered so that nothing can look better than it was:

      1. **Refuse without a reservation.** The gateway's signed ``rollback_validated`` is the
         only thing that authorizes this write; absent it, nothing is attempted.
      2. **Refuse a contained workspace.** A prior failure left it in an unknown state, and a
         second rollback over an unknown state is how a bad situation becomes an untraceable
         one.
      3. **Re-verify the snapshot, and bind it.** It must re-derive *and* be the exact
         snapshot the signed apply evidence named — the digest is compared, not trusted.
      4. **Restore**, then **re-hash every restored path** against the pre-image. Restoring
         without re-reading would be self-attestation.
      5. **Emit** a signed ``rollback_result`` either way. Any failure between 3 and 4
         contains the workspace first and is recorded as ``failed`` — never as a partial
         success, never silently.

    Raises :class:`RollbackExecutionError` only when the outcome itself cannot be recorded:
    at that point the sandbox may be half-restored and no durable trace exists, which must be
    loud rather than swallowed.
    """
    workspace = Path(workspace)
    sandbox = Path(sandbox)

    if reservation_ref is None:
        raise RollbackExecutionError(
            f"{R_NO_RESERVATION}: a rollback needs its own signed reservation"
        )

    contained = containment_reason(workspace)
    if contained:
        return _emit(
            evidence_sink, evidence_key, emitter_key_id,
            run_id=run_id, approval_id=approval_id,
            payload=_payload(FAILED, (), snapshot_id, snapshot_digest,
                             reservation_ref, apply_ref, origin_run_id=origin_run_id,
                             contained=True,
                             detail=f"{R_WORKSPACE_CONTAINED}: {contained}"),
            outcome=RollbackOutcome(FAILED, contained=True,
                                    reason=f"{R_WORKSPACE_CONTAINED}: {contained}"),
        )

    def fail(code: str, detail: str) -> RollbackOutcome:
        reason = f"{code}: {detail}"
        contain_workspace(workspace, reason=reason, run_id=run_id)
        return _emit(
            evidence_sink, evidence_key, emitter_key_id,
            run_id=run_id, approval_id=approval_id,
            payload=_payload(FAILED, (), snapshot_id, snapshot_digest,
                             reservation_ref, apply_ref, origin_run_id=origin_run_id,
                             contained=True, detail=reason),
            outcome=RollbackOutcome(FAILED, contained=True, reason=reason),
        )

    # 3. the snapshot must re-derive AND be the one the signed apply evidence named
    try:
        snapshot = load_preimage(workspace / "preimage", snapshot_id)
    except PreimageError as exc:
        return fail(R_SNAPSHOT_UNUSABLE, f"{exc.code}: {exc.detail}")
    if snapshot.digest != snapshot_digest:
        return fail(
            R_SNAPSHOT_UNUSABLE,
            "the snapshot on disk is not the one the signed apply evidence names",
        )

    # 4. restore, then re-read: a restore that is not re-verified is self-attestation
    try:
        restored = restore_into(snapshot, sandbox)
    except (PreimageError, OSError) as exc:
        return fail(R_RESTORE_FAILED, str(exc))

    mismatched = _post_restore_mismatch(snapshot, sandbox)
    if mismatched:
        return fail(R_POST_RESTORE_MISMATCH, f"paths still differ: {mismatched}")

    return _emit(
        evidence_sink, evidence_key, emitter_key_id,
        run_id=run_id, approval_id=approval_id,
        payload=_payload(RESTORED, tuple(restored), snapshot_id, snapshot_digest,
                         reservation_ref, apply_ref, origin_run_id=origin_run_id,
                         contained=False,
                         detail="the supported sandbox state was restored to the recorded "
                                "pre-image; no external effect is claimed to be undone"),
        outcome=RollbackOutcome(RESTORED, tuple(restored)),
    )


def _post_restore_mismatch(snapshot, sandbox: Path) -> list[str]:
    """Paths that do not match the pre-image after the restore — re-read, not assumed."""
    from opencode_sandbox.preimage import _sha256_file

    out: list[str] = []
    for entry in snapshot.entries:
        target = sandbox / entry.path
        if not entry.existed:
            if target.exists():
                out.append(entry.path)
            continue
        if not target.is_file() or _sha256_file(target) != entry.digest:
            out.append(entry.path)
    return sorted(out)


def _payload(status, restored_files, snapshot_id, snapshot_digest, reservation_ref,
             apply_ref, *, origin_run_id, contained, detail) -> dict:
    """The ``rollback_result`` payload: outcome and bindings, never file contents.

    ``origin_run_id`` is in the payload rather than the envelope on purpose: the envelope's
    ``run_id`` is the *rollback* run, which is a different governed run with its own
    authority. Conflating the two would make a rollback look like a second execution of the
    run it reverses.
    """
    payload = {
        "component": "opencode-rollback",
        "status": status,
        "origin_run_id": origin_run_id,
        "restored_files": list(restored_files),
        "snapshot_id": snapshot_id,
        "snapshot_digest": snapshot_digest,
        "contained": bool(contained),
        "rollback_ref": reservation_ref.to_mapping(),
        "detail": detail,
    }
    if apply_ref is not None:
        payload["apply_ref"] = apply_ref.to_mapping()
    return payload


def _emit(evidence_sink, evidence_key, emitter_key_id, *, run_id, approval_id, payload,
          outcome) -> RollbackOutcome:
    """Sign and append the outcome. An unrecordable outcome is raised, never swallowed."""
    from uuid import uuid4

    from openclaw.sink import (
        EMITTER_OPENCODE,
        SCHEMA_VERSION,
        SigningEnvelope,
        new_evidence_id,
        payload_digest,
        sign_envelope,
    )

    if evidence_sink is None:
        raise RollbackExecutionError(
            "a rollback outcome cannot be recorded: no evidence sink is configured"
        )
    envelope = SigningEnvelope(
        schema_version=SCHEMA_VERSION,
        evidence_id=new_evidence_id(),
        sink_id=evidence_sink.sink_id,
        run_id=run_id,
        approval_id=approval_id,
        emitter=EMITTER_OPENCODE,
        emitter_key_id=emitter_key_id,
        record_type=ROLLBACK_RESULT_RECORD_TYPE,
        payload_hash=payload_digest(payload),
        ts=_utc_now_iso(),
        nonce=uuid4().hex,
    )
    try:
        record = evidence_sink.append(
            envelope, payload, sign_envelope(envelope, bytes(evidence_key))
        )
    except Exception as exc:  # noqa: BLE001 — the sandbox may be half-restored; be loud
        raise RollbackExecutionError(
            f"the rollback outcome could not be recorded ({outcome.status}): {exc}"
        ) from exc
    return RollbackOutcome(
        status=outcome.status,
        restored_files=outcome.restored_files,
        contained=outcome.contained,
        reason=outcome.reason,
        evidence_ref=record.evidence_ref(),
    )
