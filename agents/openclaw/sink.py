"""Verifier-owned evidence sink — record model, canonicalization, and digests (Step 1A).

The evidence sink is the verifier's answer to a specific weakness: OpenClaw reaches its
verdict by reading artifacts *authored by the components it verifies*. The sink inverts
that — emitters push signed records, and the verifier (which owns this module's boundary)
validates authorship and chains them into a tamper-evident, append-only log. See
``docs/evidence-sink-design.md``.

**This file is Step 1A only.** It provides the *deterministic substrate* the rest of the
design builds on — a dedicated canonical serializer, the payload/record digests, the pinned
constants, and the typed record shapes. It deliberately implements **none** of the trust
mechanics yet: no HMAC signing, no emitter-key registry, no ``append``/``verify_chain``, no
replay detection, no persistence, and no wiring into the gateway/agents. Those arrive in
later, separately-authorized increments (1B signing, 1C append + chain).

Design notes pinned here (so later steps cannot drift):

  * **Canonical bytes** are ``json.dumps(sort_keys, compact, ensure_ascii=False)`` UTF-8 —
    the same doctrine as ``canonical.py`` but a *separate* implementation on purpose: that
    module is frozen for plan hashing and must not be coupled to evidence records.
  * ``emitter_sig`` (Step 1B) will cover the **signing envelope** — the emitter-authored
    fields including ``payload_hash`` — never the sink-assigned ``seq``/``prev_hash`` (which
    the emitter cannot know at emit time).
  * ``record_hash`` (Step 1C) covers the **whole record**: envelope fields + ``emitter_sig``
    + the sink-assigned ``seq``/``prev_hash`` — binding authenticated content to position.

Standard library only (``json``, ``hashlib``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# --- pinned constants ---------------------------------------------------------------
# The record shape/version. A record that disagrees is rejected (fail closed) — enforced
# in a later step, but pinned here so the number is defined in exactly one place.
SCHEMA_VERSION = 1

# The genesis link: the first record in a sink (seq 0) chains to this fixed constant, so an
# empty prev_hash can never be confused with a real predecessor.
GENESIS_PREV_HASH = "sha256:" + "0" * 64

# Emitter identities recognised by the design (validation of these is a later step).
EMITTER_GATEWAY = "gateway"
EMITTER_OPENCODE = "opencode"
EMITTER_OPENCLAW = "openclaw"

# --- deny/verify reason codes -------------------------------------------------------
# Defined now so append/verify (later steps) draw from one vocabulary. Unused in 1A.
REASON_SCHEMA_UNSUPPORTED = "schema_unsupported"
REASON_SINK_MISMATCH = "sink_mismatch"
REASON_UNKNOWN_EMITTER = "unknown_emitter"
REASON_SIG_INVALID = "sig_invalid"
REASON_REPLAY = "replay"
REASON_PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
REASON_RECORD_HASH_MISMATCH = "record_hash_mismatch"
REASON_CHAIN_BROKEN = "chain_broken"
REASON_SEQ_GAP = "seq_gap"
REASON_MALFORMED = "malformed"


class EvidenceError(Exception):
    """A record cannot be canonicalized/hashed under the sink's rules — fail closed.

    Deliberately raised (never swallowed): an integrity substrate that silently tolerated a
    non-serializable payload would let un-hashable evidence through.
    """


# --- canonicalization + digests -----------------------------------------------------
def canonicalize(obj: Any) -> bytes:
    """Byte-exact canonical JSON for ``obj`` (sorted keys, compact, UTF-8).

    Same semantic object -> identical bytes on any machine. A value JSON cannot represent
    (a set, an arbitrary object, …) fails closed with :class:`EvidenceError` rather than a
    bare ``TypeError`` — the caller gets one clear, intended failure mode.

    Intentionally *not* imported from ``private_ai_gateway.canonical``: that module is frozen
    for plan hashing; evidence records own their serializer so the two never couple.
    """
    try:
        text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"value is not JSON-serializable for canonicalization: {exc}") from exc
    return text.encode("utf-8")


def _sha256_prefixed(data: bytes) -> str:
    """``sha256:`` + 64 lowercase hex over ``data``."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def payload_digest(payload: Any) -> str:
    """``sha256:<64hex>`` over the canonical bytes of an event ``payload``."""
    return _sha256_prefixed(canonicalize(payload))


def record_digest(record_fields: dict) -> str:
    """``sha256:<64hex>`` over the canonical bytes of a record's hashable field mapping.

    ``record_fields`` is the mapping a later step will assemble for a record's ``record_hash``
    (envelope fields + ``emitter_sig`` + sink-assigned ``seq``/``prev_hash``). Changing any
    value — ``seq``, ``prev_hash``, ``payload_hash``, … — changes the digest.
    """
    if not isinstance(record_fields, dict):
        raise EvidenceError("record_fields must be a mapping")
    return _sha256_prefixed(canonicalize(record_fields))


# --- typed record shapes ------------------------------------------------------------
# These define the record *model* only. No signing, no hashing side effects, no append.
@dataclass(frozen=True)
class SigningEnvelope:
    """The emitter-authored fields — exactly what ``emitter_sig`` will cover (Step 1B).

    Everything an emitter can know at emit time: identity, the target ``sink_id``, the run it
    concerns, the record type, the ``payload_hash`` (not the raw payload), an advisory ``ts``,
    and a per-emitter ``nonce`` (the anti-replay token, enforced in Step 1C). The sink-assigned
    ``seq``/``prev_hash`` are deliberately absent — the emitter cannot know its position.
    """

    schema_version: int
    sink_id: str
    run_id: str
    emitter: str
    emitter_key_id: str
    record_type: str
    payload_hash: str
    ts: str
    nonce: str
    approval_id: str | None = None

    def to_mapping(self) -> dict:
        """The ordered field mapping to be canonicalized for signing (Step 1B)."""
        return {
            "schema_version": self.schema_version,
            "sink_id": self.sink_id,
            "run_id": self.run_id,
            "approval_id": self.approval_id,
            "emitter": self.emitter,
            "emitter_key_id": self.emitter_key_id,
            "record_type": self.record_type,
            "payload_hash": self.payload_hash,
            "ts": self.ts,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class AppendedRecord:
    """A record as it exists once the sink has validated and positioned it (Step 1C).

    Defined here as the target shape; nothing in 1A constructs one through an append path.
    Carries the emitter's ``envelope`` and signature, the raw ``payload`` (so ``payload_hash``
    can be re-derived on verify), and the sink-assigned ``seq``/``prev_hash``/``record_hash``.
    """

    envelope: SigningEnvelope
    payload: Any
    emitter_sig: str
    seq: int
    prev_hash: str
    record_hash: str
    extra: dict = field(default_factory=dict)

    def hashable_fields(self) -> dict:
        """The mapping ``record_hash`` covers (envelope + sig + assigned position).

        Pure: builds and returns the mapping; it does **not** compute or check a hash. The
        actual ``record_hash`` computation and verification live in Step 1C.
        """
        core = self.envelope.to_mapping()
        core["emitter_sig"] = self.emitter_sig
        core["seq"] = self.seq
        core["prev_hash"] = self.prev_hash
        return core
