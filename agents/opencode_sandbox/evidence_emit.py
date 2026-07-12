"""OpenCode executor → evidence sink: emit a signed ``apply_result`` record (design step 3).

This is the executor side of the verifier-owned evidence sink. After a confined apply
succeeds, the executor pushes a **signed** ``apply_result`` record into the sink instead of
leaving OpenClaw to trust the self-attested ``apply_report.json`` at a path the executor
chose. The sink (the verifier's boundary) still validates authorship and chains the record
before appending — this module only *builds and submits*; it never owns or writes the log.

Scope (step 3 only): emit is **additive and best-effort-but-loud**. It is called only after a
successful apply, signs with an injected per-emitter key, and raises :class:`EvidenceError`
on any failure (never swallowed — a silently-dropped record would reintroduce the exact
self-attestation gap this closes). It does **not** roll back the applied change, gate
verification, populate ``evidence_refs``, load keys from disk/env, or touch the gateway —
those are later, separately-authorized increments.

The record binding closes threat T4 (apply evidence not tied to a run): ``run_id`` and
``approval_id`` live in the **signing envelope** (not the payload), so the record is bound to
the specific authorized run. The payload carries only the apply outcome — no secrets.

Standard library only (plus the merged, frozen ``openclaw.sink`` core).
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from openclaw.sink import (
    EMITTER_OPENCODE,
    REASON_MALFORMED,
    SCHEMA_VERSION,
    AppendedRecord,
    EvidenceError,
    SigningEnvelope,
    new_evidence_id,
    payload_digest,
    sign_envelope,
)

RECORD_TYPE_APPLY_RESULT = "apply_result"


def build_apply_result_payload(report: Any) -> dict:
    """The ``apply_result`` payload for ``report`` — its compact, JSON-only record.

    Delegates to ``report.to_record()`` (the executor's existing secret-free hand-off), so the
    sink payload mirrors what the apply already produces. Pure: it does not mutate ``report``
    and adds **no** ``run_id``/``approval_id`` — those bind at the envelope layer, not here.
    """
    return report.to_record()


def emit_apply_result(
    evidence_sink: Any,
    evidence_key: Any,
    *,
    sink_id: str,
    run_id: str,
    approval_id: str | None,
    emitter_key_id: str,
    report: Any,
    nonce: str | None = None,
    ts: str | None = None,
) -> AppendedRecord:
    """Build, sign, and submit a signed ``apply_result`` record; return the appended record.

    Fail-closed and loud: every structural precondition raises :class:`EvidenceError`
    (``REASON_MALFORMED``) before any work, and the sink's own validation (unknown key,
    sink-id mismatch, bad signature, replay) raises through unchanged. Deterministic given a
    fixed ``nonce``/``ts``; otherwise a fresh ``nonce`` and the report's timestamp are used.
    """
    if evidence_sink is None:
        raise EvidenceError(f"{REASON_MALFORMED}: evidence_sink is required to emit")
    if not isinstance(evidence_key, (bytes, bytearray)) or len(evidence_key) == 0:
        raise EvidenceError(f"{REASON_MALFORMED}: evidence_key must be non-empty bytes")
    if not sink_id:
        raise EvidenceError(f"{REASON_MALFORMED}: sink_id is required")
    if not run_id:
        raise EvidenceError(f"{REASON_MALFORMED}: run_id is required")
    if not emitter_key_id:
        raise EvidenceError(f"{REASON_MALFORMED}: emitter_key_id is required")

    payload = build_apply_result_payload(report)
    payload_hash = payload_digest(payload)
    envelope = SigningEnvelope(
        schema_version=SCHEMA_VERSION,
        evidence_id=new_evidence_id(),
        sink_id=sink_id,
        run_id=run_id,
        approval_id=approval_id,
        emitter=EMITTER_OPENCODE,
        emitter_key_id=emitter_key_id,
        record_type=RECORD_TYPE_APPLY_RESULT,
        payload_hash=payload_hash,
        ts=ts or report.generated_at,
        nonce=nonce or uuid4().hex,
    )
    sig = sign_envelope(envelope, bytes(evidence_key))
    return evidence_sink.append(envelope, payload, sig)
