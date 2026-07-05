"""Verifier-owned evidence sink — record model, hashing, and per-emitter signing (1A + 1B).

The evidence sink is the verifier's answer to a specific weakness: OpenClaw reaches its
verdict by reading artifacts *authored by the components it verifies*. The sink inverts
that — emitters push signed records, and the verifier (which owns this module's boundary)
validates authorship and chains them into a tamper-evident, append-only log. See
``docs/evidence-sink-design.md``.

**This file covers Steps 1A + 1B.**

  * **1A** — the deterministic substrate: a dedicated canonical serializer, the
    payload/record digests, the pinned constants, and the typed record shapes.
  * **1B** — per-emitter HMAC signing of the *signing envelope*, envelope-signature
    verification, and an in-memory emitter-key registry.

It deliberately still implements **none** of the remaining trust mechanics: no
``EvidenceSink.append``, no ``verify_chain``, no replay detection, no persistence, and no
wiring into the gateway/agents. Those arrive in later, separately-authorized increments
(1C append + chain, then emit/consume wiring). Keys are passed in explicitly — there is no
disk/env key loading here.

Design notes pinned here (so later steps cannot drift):

  * **Canonical bytes** are ``json.dumps(sort_keys, compact, ensure_ascii=False)`` UTF-8 —
    the same doctrine as ``canonical.py`` but a *separate* implementation on purpose: that
    module is frozen for plan hashing and must not be coupled to evidence records.
  * ``emitter_sig`` covers the **signing envelope** — the emitter-authored fields including
    ``payload_hash`` — never the sink-assigned ``seq``/``prev_hash``/``record_hash`` (which
    the emitter cannot know at emit time). MVP is symmetric HMAC: tamper-evident, not
    non-repudiable (a holder of the key could forge that emitter's record).
  * ``record_hash`` (Step 1C) covers the **whole record**: envelope fields + ``emitter_sig``
    + the sink-assigned ``seq``/``prev_hash`` — binding authenticated content to position.

Standard library only (``json``, ``hashlib``, ``hmac``).
"""

from __future__ import annotations

import hashlib
import hmac
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

# The only signature algorithm this build understands (Step 1B). MVP is symmetric HMAC —
# tamper-evident, not non-repudiable; asymmetric signing is a later, production step.
SIG_ALGO = "hmac-sha256"

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


# --- per-emitter HMAC signing (Step 1B) ---------------------------------------------
# The emitter authenticates *its own authored content* — the signing envelope — with a
# per-emitter HMAC key. It signs ``payload_hash`` (never the raw payload) and never the
# sink-assigned ``seq``/``prev_hash``/``record_hash`` (which it cannot know at emit time).
# MVP is symmetric HMAC: it proves the record was not altered/forged by a party without the
# key (tamper-evidence), not non-repudiation against a holder of the key.
def _require_key(key: Any) -> bytes:
    """A signing/verification key must be non-empty bytes — structural misuse fails closed."""
    if not isinstance(key, (bytes, bytearray)):
        raise EvidenceError("key must be bytes")
    if len(key) == 0:
        raise EvidenceError("key must not be empty")
    return bytes(key)


def _envelope_mac(envelope: SigningEnvelope, key: bytes) -> str:
    """Raw hex HMAC-SHA256 over the canonical signing-envelope bytes."""
    return hmac.new(key, canonicalize(envelope.to_mapping()), hashlib.sha256).hexdigest()


def sign_envelope(envelope: SigningEnvelope, key: bytes) -> str:
    """Sign the emitter-authored envelope; returns ``hmac-sha256:<64 lowercase hex>``.

    Signs ``canonicalize(envelope.to_mapping())`` — i.e. the emitter's fields including
    ``payload_hash``, never the raw payload and never any sink-assigned field. Deterministic
    for a given (envelope, key).
    """
    key = _require_key(key)
    return f"{SIG_ALGO}:{_envelope_mac(envelope, key)}"


def verify_envelope_signature(
    envelope: SigningEnvelope, signature: str, key: bytes
) -> bool:
    """Constant-time check that ``signature`` is a valid HMAC of ``envelope`` under ``key``.

    Returns ``True`` only for an exact match. Returns ``False`` (never raises) for any
    verification miss: wrong key, any tampered envelope field, a tampered/malformed signature
    string, an unsupported algorithm prefix, a wrong-length or non-hex digest body. Only
    structural misuse of the *key* (non-bytes / empty) raises :class:`EvidenceError`.
    """
    key = _require_key(key)
    if not isinstance(signature, str):
        return False
    algo, sep, digest = signature.partition(":")
    if sep != ":" or algo != SIG_ALGO:
        return False
    # A well-formed hmac-sha256 digest is exactly 64 lowercase hex chars.
    if len(digest) != 64:
        return False
    try:
        bytes.fromhex(digest)
    except ValueError:
        return False
    if digest != digest.lower():
        return False
    expected = _envelope_mac(envelope, key)
    return hmac.compare_digest(digest, expected)


class EmitterKeyRegistry:
    """In-memory map of ``(emitter, key_id) -> key bytes`` — the verifier's key material.

    MVP only: no disk/env loading, no rotation, no key derivation. Symmetric HMAC keys held
    here let the sink verify an emitter's signature; a later production step replaces this
    with asymmetric keys and real key separation.
    """

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], bytes] = {}

    def register(self, emitter: str, key_id: str, key: bytes) -> None:
        """Register a non-empty ``bytes`` key for ``(emitter, key_id)``."""
        if not emitter or not key_id:
            raise EvidenceError("emitter and key_id are required")
        self._keys[(emitter, key_id)] = _require_key(key)

    def get(self, emitter: str, key_id: str) -> bytes:
        """Return the key for ``(emitter, key_id)`` or fail closed if unknown."""
        try:
            return self._keys[(emitter, key_id)]
        except KeyError as exc:
            raise EvidenceError(
                f"{REASON_UNKNOWN_EMITTER}: no key for ({emitter!r}, {key_id!r})"
            ) from exc


def sign_with_registry(envelope: SigningEnvelope, registry: EmitterKeyRegistry) -> str:
    """Sign ``envelope`` with the key the registry holds for its emitter/key_id."""
    key = registry.get(envelope.emitter, envelope.emitter_key_id)
    return sign_envelope(envelope, key)


def verify_with_registry(
    envelope: SigningEnvelope, signature: str, registry: EmitterKeyRegistry
) -> bool:
    """Verify ``signature`` using the registry key for the envelope's emitter/key_id.

    An unknown ``(emitter, key_id)`` is a structural failure (raises via ``registry.get``);
    a key mismatch or tampered record is an ordinary verification miss (returns ``False``).
    """
    key = registry.get(envelope.emitter, envelope.emitter_key_id)
    return verify_envelope_signature(envelope, signature, key)
