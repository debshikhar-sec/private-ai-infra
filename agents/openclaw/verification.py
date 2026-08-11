"""Step 7C.1 — the verifier's verdict as a signed, durable assurance fact.

Until now OpenClaw's conclusion existed only as returned text: a summary string and an exit
code. Anything downstream that "knew" a run had been verified knew it by hearsay. This
module makes the verdict itself tamper-evident — OpenClaw signs it with its **own** emitter
key and appends it to the same chained log it verifies.

The custody direction is the point. The gateway does not emit verifier conclusions and the
executor does not emit verifier conclusions; the component that *reached* the verdict is the
one that signs it. In the symmetric-HMAC MVP the assurance-owned registry can verify all
three emitters because verification and signing material are the same bytes — so this is
**tamper-evident, not non-repudiation**, and no asymmetric crypto, KMS or HSM is introduced
here.

Two rules make a signed PASS mean something:

  * **A PASS for a mutation binds to the exact ``apply_result`` it judged**, through a typed
    ``apply_ref``. That record already chains upstream to ``execute_validated`` and
    ``approval_decided``, so a verdict inherits the full authorization story rather than
    asserting one.
  * **A broken or missing upstream graph can never produce a signed PASS.** The full graph
    must be ``usable`` under the hardened durable runtime first; otherwise the verdict is
    downgraded and recorded as unverified rather than blessed.

The verifier stays *operationally* read-only: it changes no authority, executes no tool,
mutates no sandbox and repairs no application state. It is now append-only to its own
assurance evidence log — a strictly narrower thing than being able to act.

**Not** in this step: terminal disposition of a dirty run, rollback, containment. Multiple
verification passes may legitimately exist (see :func:`verification_results_for`); nothing
here treats any of them as terminal, and no consumer should. Step 7C.2 will bind terminal
disposition to a *specific* verifier result, explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass

from openclaw.evidence import load_evidence_graph_from_sink
from openclaw.report import VERDICT_FAIL, VERDICT_PASS
from openclaw.sink import (
    EMITTER_OPENCLAW,
    SCHEMA_VERSION,
    EvidenceError,
    EvidenceRef,
    SigningEnvelope,
    find_unique_record,
    new_evidence_id,
    payload_digest,
    sign_envelope,
)

VERIFICATION_RESULT_RECORD_TYPE = "verification_result"

# The statuses in a report's counts, as the payload records them.
_PASS, _FAIL, _INCONCLUSIVE = "pass", "fail", "inconclusive"


class VerificationEmitError(Exception):
    """Signed verification evidence was required and could not be appended."""


@dataclass(frozen=True)
class VerificationEmit:
    """The outcome of one attempt to record a verdict as signed evidence.

    ``advertised_verdict`` is what a caller may honestly report. It is **not** always the
    report's own verdict: if signed evidence was required and could not be appended, a PASS
    is not advertised, because nothing durable supports it.
    """

    appended: bool
    advertised_verdict: str
    evidence_ref: EvidenceRef | None = None
    graph_verified: bool = False
    reason: str = ""

    @property
    def assurance_incomplete(self) -> bool:
        return not self.appended


def build_payload(report, *, apply_ref: EvidenceRef | None, graph_verified: bool,
                  rollback_ref: EvidenceRef | None = None) -> dict:
    """The minimal, non-sensitive verdict payload.

    Control **identifiers** and counts only. Deliberately absent: raw prompts, audit log
    contents, model output, diffs, secrets, key material, and any free-form customer data —
    a signed record is the last place unbounded content should end up. ``run_id`` and
    ``approval_id`` live in the signing envelope, not here.
    """
    counts = report.counts()
    payload: dict = {
        "verdict": report.verdict,
        "control_counts": {
            _PASS: counts.get(_PASS, 0),
            _FAIL: counts.get(_FAIL, 0),
            _INCONCLUSIVE: counts.get(_INCONCLUSIVE, 0),
        },
        "failed_control_ids": sorted(
            f.control_id for f in report.findings if f.status == _FAIL
        ),
        "inconclusive_control_ids": sorted(
            f.control_id for f in report.findings if f.status == _INCONCLUSIVE
        ),
        # Derived from the actual graph walk, never assumed.
        "evidence_graph_verified": bool(graph_verified),
    }
    if apply_ref is not None:
        payload["apply_ref"] = apply_ref.to_mapping()
    if rollback_ref is not None:
        # Step 7C.3B. The verdict's *subject* is a rollback rather than an apply. This is the
        # same record type on purpose: it is still exactly "OpenClaw's signed judgment about
        # one thing that happened", signed with the same key by the same component. What
        # changes is which typed reference names the subject — not the meaning of the record,
        # and not who is entitled to author it.
        payload["rollback_ref"] = rollback_ref.to_mapping()
    return payload


def _apply_ref_for(evidence_sink, *, run_id, approval_id):
    """The typed reference to the exact signed ``apply_result`` this verdict judged."""
    from openclaw.evidence import APPLY_RESULT_RECORD_TYPE
    from openclaw.sink import EMITTER_OPENCODE

    rec = find_unique_record(
        tuple(evidence_sink.records),
        emitter=EMITTER_OPENCODE,
        record_type=APPLY_RESULT_RECORD_TYPE,
        run_id=run_id,
        approval_id=approval_id,
    )
    return rec.evidence_ref()


def emit_verification_result(
    evidence_sink,
    report,
    *,
    run_id: str | None,
    approval_id: str | None,
    signing_key: bytes,
    key_id: str,
    required: bool = False,
    nonce: str | None = None,
) -> VerificationEmit:
    """Sign and append this verdict; return what the caller may honestly advertise.

    A PASS is only ever signed when the full upstream graph
    (``apply_result -> execute_validated -> approval_decided``) resolves. If it does not,
    the verdict is downgraded to FAIL before signing — a signed PASS must never be reachable
    over a broken authorization story.

    When ``required`` is set and the append fails, this raises
    :class:`VerificationEmitError`. The caller must **not** report a verified state: the
    mutation may already have happened, so nothing is retried, nothing is rolled back, and
    the failure is surfaced loudly instead of being papered over with unsigned summary text.
    """
    if evidence_sink is None:
        if required:
            raise VerificationEmitError(
                "signed verification evidence is required but no evidence sink is configured"
            )
        return VerificationEmit(False, report.verdict, reason="no evidence sink configured")

    # 1. Bind to the exact apply_result judged, and establish the upstream graph.
    apply_ref = None
    graph_verified = False
    graph_reason = ""
    try:
        view = load_evidence_graph_from_sink(
            evidence_sink, run_id=run_id, approval_id=approval_id
        )
        graph_verified = bool(view.usable)
        graph_reason = view.reason
        if graph_verified:
            apply_ref = _apply_ref_for(
                evidence_sink, run_id=run_id, approval_id=approval_id
            )
    except EvidenceError as exc:            # a graph that will not resolve is not a PASS
        graph_verified, graph_reason = False, str(exc)

    # 2. A signed PASS requires that graph. Anything else is recorded as a failure.
    verdict = report.verdict
    downgrade = ""
    if verdict == VERDICT_PASS and not graph_verified:
        verdict = VERDICT_FAIL
        downgrade = (
            f"verdict downgraded to {VERDICT_FAIL}: the signed evidence graph is not "
            f"usable ({graph_reason or 'no graph'}), so a signed PASS is not available"
        )

    payload = build_payload(report, apply_ref=apply_ref, graph_verified=graph_verified)
    payload["verdict"] = verdict

    # 3. Sign as OpenClaw and append to the log the verifier already re-derives.
    try:
        envelope = SigningEnvelope(
            schema_version=SCHEMA_VERSION,
            evidence_id=new_evidence_id(),
            sink_id=evidence_sink.sink_id,
            run_id=run_id or "",
            emitter=EMITTER_OPENCLAW,
            emitter_key_id=key_id,
            record_type=VERIFICATION_RESULT_RECORD_TYPE,
            payload_hash=payload_digest(payload),
            ts=_utc_now_iso(),
            nonce=nonce or new_evidence_id(),
            approval_id=approval_id or "",
        )
        record = evidence_sink.append(
            envelope, payload, sign_envelope(envelope, signing_key)
        )
    except Exception as exc:  # noqa: BLE001 — any append failure is an assurance failure
        if required:
            raise VerificationEmitError(
                f"signed verification evidence is required but could not be appended: {exc}"
            ) from exc
        return VerificationEmit(
            False, verdict, graph_verified=graph_verified,
            reason=f"verification_result could not be appended: {exc}",
        )

    return VerificationEmit(
        True, verdict, evidence_ref=record.evidence_ref(),
        graph_verified=graph_verified, reason=downgrade,
    )


def verify_rollback(
    evidence_sink,
    rollback_record,
    *,
    sandbox,
    signing_key: bytes,
    key_id: str,
) -> "VerificationEmit":
    """OpenClaw's own, independent verdict on a rollback (Step 7C.3B).

    The executor signs *what it did*; this decides whether that amounts to a correct
    restoration, and it decides it by **re-reading the tree** rather than by reading the
    executor's claim. The pre-image is re-derived from disk and every entry re-hashed against
    what is actually there now — a creation must be absent, an update or delete must match the
    recorded bytes exactly.

    A PASS is therefore unreachable over a failed, contained, or merely *claimed* rollback,
    for the same reason a 7C.1 PASS is unreachable over a broken graph. The verdict is signed
    with OpenClaw's own key and carries a typed ``rollback_ref`` to the exact outcome it
    judged.
    """
    from openclaw.report import build_report

    payload = rollback_record.payload if isinstance(rollback_record.payload, dict) else {}
    env = rollback_record.envelope
    findings = []
    ok, detail = _rollback_is_restored(payload, sandbox)
    findings.append(_finding("AC-ROLLBACK-RESTORED", ok, detail))

    report = build_report(findings)
    verdict = report.verdict
    apply_ref = None
    raw_apply = payload.get("apply_ref")
    if isinstance(raw_apply, dict):
        try:
            apply_ref = EvidenceRef.from_mapping(raw_apply)
        except EvidenceError:
            apply_ref = None

    body = build_payload(
        report, apply_ref=apply_ref, graph_verified=False,
        rollback_ref=rollback_record.evidence_ref(),
    )
    body["verdict"] = verdict
    try:
        envelope = SigningEnvelope(
            schema_version=SCHEMA_VERSION,
            evidence_id=new_evidence_id(),
            sink_id=evidence_sink.sink_id,
            run_id=env.run_id or "",
            emitter=EMITTER_OPENCLAW,
            emitter_key_id=key_id,
            record_type=VERIFICATION_RESULT_RECORD_TYPE,
            payload_hash=payload_digest(body),
            ts=_utc_now_iso(),
            nonce=new_evidence_id(),
            approval_id=env.approval_id or "",
        )
        record = evidence_sink.append(
            envelope, body, sign_envelope(envelope, signing_key)
        )
    except Exception as exc:  # noqa: BLE001 — an unrecordable verdict is an assurance failure
        raise VerificationEmitError(
            f"the rollback verdict could not be recorded: {exc}"
        ) from exc
    return VerificationEmit(
        True, verdict, evidence_ref=record.evidence_ref(), graph_verified=False,
        reason="" if verdict == VERDICT_PASS else detail,
    )


def _finding(control_id: str, ok: bool, detail: str):
    from openclaw.checks import FAIL, PASS, Finding

    return Finding(
        control_id, "the sandbox matches the recorded pre-image",
        PASS if ok else FAIL, "high", detail,
    )


def _rollback_is_restored(payload: dict, sandbox) -> tuple[bool, str]:
    """Re-read the tree. The executor's own claim is an input, never the conclusion."""
    from pathlib import Path

    from opencode_sandbox.preimage import PreimageError, _sha256_file, load_preimage
    from opencode_sandbox.rollback import RESTORED

    if payload.get("status") != RESTORED:
        return False, f"the executor recorded status {payload.get('status')!r}, not restored"
    if payload.get("contained"):
        return False, "the workspace is contained; a contained rollback is never a success"

    sandbox = Path(sandbox)
    try:
        snapshot = load_preimage(sandbox.parent / "preimage", payload.get("snapshot_id", ""))
    except PreimageError as exc:
        return False, f"the pre-image could not be re-derived: {exc.code}"
    if snapshot.digest != payload.get("snapshot_digest"):
        return False, "the pre-image on disk is not the one the rollback outcome names"

    for entry in snapshot.entries:
        target = sandbox / entry.path
        if not entry.existed:
            if target.exists():
                return False, f"{entry.path!r} exists but the pre-image says it did not"
            continue
        if not target.is_file() or _sha256_file(target) != entry.digest:
            return False, f"{entry.path!r} does not match the recorded pre-image"
    return True, f"all {len(snapshot.entries)} declared path(s) match the recorded pre-image"


def verification_results_for(evidence_sink, *, run_id=None, approval_id=None) -> tuple:
    """Every signed verdict recorded for this run, oldest first.

    Deliberately plural and deliberately unordered-by-authority. Retries and
    re-verification can legitimately produce more than one verdict, each with its own
    ``evidence_id``, and this returns all of them rather than silently resolving to one:
    "pick latest" would be a hidden authority rule, and no consumer may treat any of these
    as a run's terminal disposition. Binding a terminal disposition to one specific verifier
    result is Step 7C.2, and will be explicit when it arrives.
    """
    if evidence_sink is None:
        return ()
    out = []
    for rec in tuple(evidence_sink.records):
        env = getattr(rec, "envelope", None)
        if env is None or env.record_type != VERIFICATION_RESULT_RECORD_TYPE:
            continue
        if env.emitter != EMITTER_OPENCLAW:
            continue
        if run_id is not None and (env.run_id or "") != run_id:
            continue
        if approval_id is not None and (env.approval_id or "") != approval_id:
            continue
        out.append(rec)
    return tuple(out)


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
