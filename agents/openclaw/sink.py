"""Verifier-owned evidence sink — record model, hashing, signing, and the append-only log (1A + 1B + 1C).

The evidence sink is the verifier's answer to a specific weakness: OpenClaw reaches its
verdict by reading artifacts *authored by the components it verifies*. The sink inverts
that — emitters push signed records, and the verifier (which owns this module's boundary)
validates authorship and chains them into a tamper-evident, append-only log. See
``docs/evidence-sink-design.md``.

**This file covers Steps 1A + 1B + 1C.**

  * **1A** — the deterministic substrate: a dedicated canonical serializer, the
    payload/record digests, the pinned constants, and the typed record shapes.
  * **1B** — per-emitter HMAC signing of the *signing envelope*, envelope-signature
    verification, and an in-memory emitter-key registry.
  * **1C** — the verifier-owned, append-only ``EvidenceSink``: a fail-closed ``append``
    that validates then chains a record (sink-assigned ``seq``/``prev_hash``/``record_hash``
    plus per-emitter nonce replay defence and a detached payload snapshot), and
    ``verify_chain`` which re-derives the whole log from scratch.

It deliberately still implements **none** of the remaining wiring: no persistence (the log
is in-memory only), no key loading from disk/env (keys are registered explicitly), and no
emit/consume hooks into the gateway/executor/verifier. Those arrive in later,
separately-authorized increments (executor emit, then verifier consume).

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
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

# --- pinned constants ---------------------------------------------------------------
# The record shape/version. A record that disagrees is rejected (fail closed). Bumped to 2
# when the signed ``evidence_id`` field was added to the envelope (Step 6A): there are no
# durable or external v1 consumers, so v1 is simply unsupported now — no dual-version path.
SCHEMA_VERSION = 2

# A stable evidence identity: ``ev-`` + 32 lowercase hex (a UUIDv4). Distinct from ``nonce``
# (which stays solely the replay-protection token) — this is the record's portable identity,
# signed as part of the envelope and used to build an :class:`EvidenceRef`.
_EVIDENCE_ID_RE = re.compile(r"^ev-[0-9a-f]{32}$")

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
REASON_EVIDENCE_ID_INVALID = "evidence_id_invalid"
# A record's portable identity (``evidence_id``) must be unique within a sink — the same
# invariant enforced by the in-memory ``_seen_evidence_ids`` set and the durable store's
# ``UNIQUE(evidence_id)`` constraint, so both backends reject a duplicate identically.
REASON_DUPLICATE_EVIDENCE_ID = "duplicate_evidence_id"
REASON_SINK_MISMATCH = "sink_mismatch"
REASON_UNKNOWN_EMITTER = "unknown_emitter"
REASON_SIG_INVALID = "sig_invalid"
REASON_REPLAY = "replay"
REASON_PAYLOAD_HASH_MISMATCH = "payload_hash_mismatch"
REASON_RECORD_HASH_MISMATCH = "record_hash_mismatch"
REASON_CHAIN_BROKEN = "chain_broken"
REASON_SEQ_GAP = "seq_gap"
REASON_MALFORMED = "malformed"
# Step 6B — evidence-reference resolution (walking one edge of the signed graph).
REASON_REF_UNRESOLVED = "ref_unresolved"
REASON_REF_AMBIGUOUS = "ref_ambiguous"
REASON_REF_TYPE_MISMATCH = "ref_type_mismatch"
REASON_REF_SINK_MISMATCH = "ref_sink_mismatch"
REASON_REF_DIGEST_MISMATCH = "ref_digest_mismatch"


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


def new_evidence_id() -> str:
    """A fresh stable evidence identity: ``ev-`` + 32 lowercase hex (a UUIDv4).

    Generated by the emitter *before* signing (so it is covered by ``emitter_sig``) and
    before append. Immutable thereafter — it is the record's portable identity.
    """
    return "ev-" + uuid.uuid4().hex


def _valid_evidence_id(value: Any) -> bool:
    """True iff ``value`` is a well-formed evidence id (``ev-`` + 32 lowercase hex)."""
    return isinstance(value, str) and _EVIDENCE_ID_RE.match(value) is not None


def record_digest(record_fields: dict) -> str:
    """``sha256:<64hex>`` over the canonical bytes of a record's hashable field mapping.

    ``record_fields`` is the mapping a later step will assemble for a record's ``record_hash``
    (envelope fields + ``emitter_sig`` + sink-assigned ``seq``/``prev_hash``). Changing any
    value — ``seq``, ``prev_hash``, ``payload_hash``, … — changes the digest.
    """
    if not isinstance(record_fields, dict):
        raise EvidenceError("record_fields must be a mapping")
    return _sha256_prefixed(canonicalize(record_fields))


def _hashable_core(
    envelope: "SigningEnvelope", emitter_sig: str, seq: int, prev_hash: str
) -> dict:
    """The exact mapping ``record_hash`` covers: envelope + ``emitter_sig`` + assigned position.

    The single source of truth for the record-hash field set, shared by ``append`` (which
    computes ``record_hash`` before constructing the frozen record) and
    ``AppendedRecord.hashable_fields`` (which re-derives it on verify) — so the append-time
    and verify-time digests cannot drift. Covers the ten ``SigningEnvelope.to_mapping``
    fields (including ``payload_hash``) plus ``emitter_sig``, ``seq``, and ``prev_hash``. It
    does **not** include the raw ``payload`` (bound indirectly via ``payload_hash``), the
    ``record_hash`` itself, or ``extra``.
    """
    core = envelope.to_mapping()
    core["emitter_sig"] = emitter_sig
    core["seq"] = seq
    core["prev_hash"] = prev_hash
    return core


# --- typed record shapes ------------------------------------------------------------
# These define the record *model* only. No signing, no hashing side effects, no append.
@dataclass(frozen=True)
class SigningEnvelope:
    """The emitter-authored fields — exactly what ``emitter_sig`` will cover (Step 1B).

    Everything an emitter can know at emit time: identity, its stable ``evidence_id``, the
    target ``sink_id``, the run it concerns, the record type, the ``payload_hash`` (not the raw
    payload), an advisory ``ts``, and a per-emitter ``nonce`` (the anti-replay token, enforced
    in Step 1C). The sink-assigned ``seq``/``prev_hash`` are deliberately absent — the emitter
    cannot know its position.

    ``evidence_id`` (``ev-`` + 32 hex) is the record's portable identity, distinct in purpose
    from ``nonce`` (replay defence only). Both are signed via ``to_mapping``.
    """

    schema_version: int
    evidence_id: str
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
            "evidence_id": self.evidence_id,
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


# --- stable, chain-independent evidence identity (Step 6A) ---------------------------
# ``evidence_digest`` and ``EvidenceRef`` give each record a portable identity that does NOT
# depend on its chain position. ``record_hash`` keeps its own, separate job (sink-local chain
# integrity, binding seq/prev_hash); this identity is what later linkage (Step 6B) will point
# at. No record refers to another record yet — that is Step 6B.
def evidence_digest(envelope: "SigningEnvelope", emitter_sig: str) -> str:
    """Chain-independent ``sha256:`` digest of the signed attestation (envelope + signature).

    Covers every signed envelope field (via ``to_mapping`` — including ``schema_version``,
    ``evidence_id``, ``payload_hash`` and ``nonce``) plus ``emitter_sig``. It deliberately
    **excludes** the sink-assigned ``seq``/``prev_hash``/``record_hash``, the raw payload, and
    ``extra`` — so the same signed attestation has the same digest regardless of where (or in
    which sink) it lands. Reuses :func:`record_digest`'s canonicalization (one serializer).
    """
    core = envelope.to_mapping()
    core["emitter_sig"] = emitter_sig
    return record_digest(core)


@dataclass(frozen=True)
class EvidenceRef:
    """A stable, portable reference to one evidence record — the anchor for Step 6B linkage.

    Identity is ``evidence_id`` + ``evidence_digest`` (what the record *is*); ``record_type``
    lets a consumer assert the expected kind; ``sink_id`` is a **locator hint / origin marker**
    only — never a chain sequence or record-position identity. Nothing here embeds ``seq`` or
    ``record_hash``. Not yet placed into any evidence payload (that is Step 6B).
    """

    evidence_id: str
    evidence_digest: str
    record_type: str
    sink_id: str

    def to_mapping(self) -> dict:
        """The ordered, canonicalizable field mapping (for Step 6B embedding)."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_digest": self.evidence_digest,
            "record_type": self.record_type,
            "sink_id": self.sink_id,
        }

    @classmethod
    def from_mapping(cls, mapping: Any) -> "EvidenceRef":
        """Build an :class:`EvidenceRef` from a mapping; fail closed on a malformed shape."""
        if not isinstance(mapping, dict):
            raise EvidenceError(f"{REASON_MALFORMED}: EvidenceRef mapping must be a dict")
        try:
            return cls(
                evidence_id=mapping["evidence_id"],
                evidence_digest=mapping["evidence_digest"],
                record_type=mapping["record_type"],
                sink_id=mapping["sink_id"],
            )
        except (KeyError, TypeError) as exc:
            raise EvidenceError(f"{REASON_MALFORMED}: EvidenceRef mapping incomplete: {exc}") from exc


def evidence_ref_for(envelope: "SigningEnvelope", emitter_sig: str) -> EvidenceRef:
    """The :class:`EvidenceRef` for a signed attestation — computable before append.

    Derived only from the signed envelope and its signature, so the reference obtained here
    (pre-append) is byte-identical to the one an :class:`AppendedRecord` yields post-append.
    """
    return EvidenceRef(
        evidence_id=envelope.evidence_id,
        evidence_digest=evidence_digest(envelope, emitter_sig),
        record_type=envelope.record_type,
        sink_id=envelope.sink_id,
    )


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

        Pure: builds and returns the mapping (via the shared :func:`_hashable_core` builder);
        it does **not** compute or check a hash.
        """
        return _hashable_core(self.envelope, self.emitter_sig, self.seq, self.prev_hash)

    def evidence_ref(self) -> EvidenceRef:
        """This record's stable, chain-independent :class:`EvidenceRef`.

        Identical to :func:`evidence_ref_for` computed from the signed envelope before append —
        it depends only on the signed attestation, never on ``seq``/``prev_hash``/``record_hash``.
        """
        return evidence_ref_for(self.envelope, self.emitter_sig)


# --- signed-graph reference resolution (Step 6B) ------------------------------------
# Pure functions that walk one edge of the signed evidence graph: given a portable
# :class:`EvidenceRef` (or a (emitter, record_type, run, approval) context), find the *unique*
# record it names among an already-obtained records sequence. Identity is ``evidence_id`` +
# recomputed ``evidence_digest`` — never ``seq`` or ``record_hash`` (chain-local, not portable).
# The caller is responsible for having verified the chain first (``verify_chain``); these do not
# re-verify, so one verification can back many edge resolutions. Fail-closed: any miss raises
# :class:`EvidenceError` with a ``REASON_REF_*`` code — a resolver that guessed would defeat the
# point of a signed reference.
def resolve_evidence_ref(records, ref: EvidenceRef, *, sink_id: str) -> AppendedRecord:
    """Resolve ``ref`` to the one record it names in ``records``; fail closed on any miss.

    Requires exactly one record whose envelope ``evidence_id`` equals ``ref.evidence_id``
    (zero -> ``REASON_REF_UNRESOLVED``, many -> ``REASON_REF_AMBIGUOUS``), then binds the
    reference to it: ``ref.sink_id`` must equal ``sink_id`` (the current single sink),
    ``record_type`` must match, and the record's **recomputed** ``evidence_digest`` must equal
    ``ref.evidence_digest``. Never resolves by ``seq`` or ``record_hash``.
    """
    if not isinstance(ref, EvidenceRef):
        raise EvidenceError(f"{REASON_MALFORMED}: ref must be an EvidenceRef")
    matches = [
        r for r in records
        if getattr(getattr(r, "envelope", None), "evidence_id", None) == ref.evidence_id
    ]
    if not matches:
        raise EvidenceError(f"{REASON_REF_UNRESOLVED}: no record for {ref.evidence_id!r}")
    if len(matches) > 1:
        raise EvidenceError(
            f"{REASON_REF_AMBIGUOUS}: {len(matches)} records share {ref.evidence_id!r}"
        )
    rec = matches[0]
    if ref.sink_id != sink_id:
        raise EvidenceError(f"{REASON_REF_SINK_MISMATCH}: {ref.sink_id!r} != {sink_id!r}")
    if rec.envelope.record_type != ref.record_type:
        raise EvidenceError(
            f"{REASON_REF_TYPE_MISMATCH}: {rec.envelope.record_type!r} != {ref.record_type!r}"
        )
    if evidence_digest(rec.envelope, rec.emitter_sig) != ref.evidence_digest:
        raise EvidenceError(f"{REASON_REF_DIGEST_MISMATCH}: {ref.evidence_id!r}")
    return rec


def find_unique_record(
    records,
    *,
    emitter: str,
    record_type: str,
    run_id: str | None = None,
    approval_id: str | None = None,
) -> AppendedRecord:
    """The unique record matching ``emitter``/``record_type`` (and run/approval when given).

    A contextual locator for authority records: zero matches -> ``REASON_REF_UNRESOLVED``,
    more than one -> ``REASON_REF_AMBIGUOUS`` (deliberately **not** "latest wins" — an
    ambiguous authority record is a failure, not a tie to be broken).
    """
    matches = []
    for r in records:
        env = getattr(r, "envelope", None)
        if env is None:
            continue
        if env.emitter != emitter or env.record_type != record_type:
            continue
        if run_id is not None and env.run_id != run_id:
            continue
        if approval_id is not None and env.approval_id != approval_id:
            continue
        matches.append(r)
    if not matches:
        raise EvidenceError(
            f"{REASON_REF_UNRESOLVED}: no {emitter}/{record_type} "
            f"for run={run_id!r} approval={approval_id!r}"
        )
    if len(matches) > 1:
        raise EvidenceError(
            f"{REASON_REF_AMBIGUOUS}: {len(matches)} {emitter}/{record_type} "
            f"for run={run_id!r} approval={approval_id!r}"
        )
    return matches[0]


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


# --- detached snapshots -------------------------------------------------------------
# The sink must never hold a reference to a caller's mutable payload (a later mutation of
# the caller's object would silently change stored evidence). Round-tripping through the
# canonical serializer yields a fresh, deeply-detached, JSON-only structure whose canonical
# bytes are identical to the original's — so ``payload_digest`` of the snapshot still equals
# the emitter's ``payload_hash``.
def _detached_payload(payload: Any) -> Any:
    """A deep, JSON-compatible copy of ``payload`` with no shared mutable references.

    ``canonicalize`` has already succeeded (append validates the payload hash first), so the
    round-trip cannot fail here; ``canonicalize(_detached_payload(p)) == canonicalize(p)``.
    """
    return json.loads(canonicalize(payload))


def _detach_record(record: AppendedRecord) -> AppendedRecord:
    """A record whose mutable members (``payload``, ``extra``) are detached copies.

    The frozen scalar fields and the (immutable) ``SigningEnvelope`` are shared safely; only
    the mutable containers are copied so a caller cannot reach back into the sink's stored
    state through a handed-out record.
    """
    return AppendedRecord(
        envelope=record.envelope,
        payload=_detached_payload(record.payload),
        emitter_sig=record.emitter_sig,
        seq=record.seq,
        prev_hash=record.prev_hash,
        record_hash=record.record_hash,
        extra=dict(record.extra),
    )


# --- the append-only evidence sink (Step 1C) ----------------------------------------
class EvidenceSink:
    """Verifier-owned, in-memory, append-only log of validated, chained evidence records.

    The sink — not the emitter — decides what is accepted. ``append`` fully validates a
    submitted record (schema, target sink, authorship, payload binding, replay) *before*
    assigning it a position and chaining it; any failure raises :class:`EvidenceError` with a
    ``REASON_*`` code and leaves the log untouched (no partial state). ``verify_chain``
    re-derives the entire chain from scratch, trusting no stored derived value.

    MVP scope: no persistence (in-memory only), no key loading (keys come from the injected
    :class:`EmitterKeyRegistry`), and no wiring into the gateway/executor/verifier.
    """

    def __init__(self, sink_id: str, registry: EmitterKeyRegistry) -> None:
        if not sink_id:
            raise EvidenceError("sink_id is required")
        if not isinstance(registry, EmitterKeyRegistry):
            raise EvidenceError("registry must be an EmitterKeyRegistry")
        self._sink_id = sink_id
        self._registry = registry
        self._records: list[AppendedRecord] = []
        self._seen_nonces: set[tuple[str, str]] = set()
        self._seen_evidence_ids: set[str] = set()

    def __len__(self) -> int:
        return len(self._records)

    @property
    def sink_id(self) -> str:
        return self._sink_id

    @property
    def head_hash(self) -> str:
        """``record_hash`` of the last appended record, or ``GENESIS_PREV_HASH`` when empty."""
        if not self._records:
            return GENESIS_PREV_HASH
        return self._records[-1].record_hash

    @property
    def records(self) -> tuple:
        """An immutable snapshot: a tuple of **detached** records (mutating them is inert).

        Neither the returned tuple nor any record it holds is the sink's internal state — a
        caller cannot mutate the log or a stored payload through this property.
        """
        return tuple(_detach_record(rec) for rec in self._records)

    def _validate_submission(
        self, envelope: SigningEnvelope, payload: Any, emitter_sig: str
    ) -> None:
        """Run every append precondition; raise on the first failure, leaving no state change.

        The full validation sequence shared by the in-memory ``append`` and any durable
        subclass that positions/persists a record itself: structural shape → schema →
        evidence identity → target sink → nonce present → emitter key resolvable → emitter
        signature → payload binding → replay. It never touches ``_records``/``_seen_nonces``.
        """
        # 1. Structural shape.
        if not isinstance(envelope, SigningEnvelope):
            raise EvidenceError(f"{REASON_MALFORMED}: envelope must be a SigningEnvelope")
        if not isinstance(emitter_sig, str):
            raise EvidenceError(f"{REASON_MALFORMED}: emitter_sig must be a string")
        # 2. Schema.
        if envelope.schema_version != SCHEMA_VERSION:
            raise EvidenceError(
                f"{REASON_SCHEMA_UNSUPPORTED}: {envelope.schema_version!r}"
            )
        # 2b. Evidence identity: a well-formed, signed stable id (``ev-`` + 32 hex).
        if not _valid_evidence_id(envelope.evidence_id):
            raise EvidenceError(
                f"{REASON_EVIDENCE_ID_INVALID}: {envelope.evidence_id!r}"
            )
        # 3. Target sink.
        if envelope.sink_id != self._sink_id:
            raise EvidenceError(
                f"{REASON_SINK_MISMATCH}: {envelope.sink_id!r} != {self._sink_id!r}"
            )
        # 4. Nonce present (the anti-replay token cannot be empty/missing).
        if not envelope.nonce:
            raise EvidenceError(f"{REASON_MALFORMED}: nonce is required")
        # 5. Emitter key resolvable (unknown emitter/key_id raises REASON_UNKNOWN_EMITTER).
        key = self._registry.get(envelope.emitter, envelope.emitter_key_id)
        # 6. Emitter signature authenticates the envelope.
        if not verify_envelope_signature(envelope, emitter_sig, key):
            raise EvidenceError(f"{REASON_SIG_INVALID}: emitter signature did not verify")
        # 7. Payload binding: the raw payload must hash to the signed payload_hash.
        if payload_digest(payload) != envelope.payload_hash:
            raise EvidenceError(
                f"{REASON_PAYLOAD_HASH_MISMATCH}: payload does not match payload_hash"
            )
        # 8. Replay: this (emitter, nonce) must not have been appended before.
        if (envelope.emitter, envelope.nonce) in self._seen_nonces:
            raise EvidenceError(
                f"{REASON_REPLAY}: duplicate (emitter, nonce) "
                f"{(envelope.emitter, envelope.nonce)!r}"
            )
        # 8b. Portable identity: this evidence_id must not have been appended before (the
        # in-memory equivalent of the durable store's UNIQUE(evidence_id) constraint).
        if envelope.evidence_id in self._seen_evidence_ids:
            raise EvidenceError(
                f"{REASON_DUPLICATE_EVIDENCE_ID}: {envelope.evidence_id!r}"
            )

    def append(
        self, envelope: SigningEnvelope, payload: Any, emitter_sig: str
    ) -> AppendedRecord:
        """Validate, then chain, one evidence record. Fail-closed; returns a detached copy.

        Validation runs to completion before any state change: structural shape → schema →
        target sink → nonce present → emitter key resolvable → emitter signature → payload
        binding → replay. Only if every check passes is the record snapshotted, positioned
        (sink-assigned ``seq``/``prev_hash``/``record_hash``), appended, and its nonce
        recorded — atomically. The returned record is a detached snapshot.
        """
        self._validate_submission(envelope, payload, emitter_sig)
        # All checks passed — snapshot, position, chain, and commit atomically.
        snapshot = _detached_payload(payload)
        seq = len(self._records)
        prev_hash = self.head_hash
        record_hash = record_digest(_hashable_core(envelope, emitter_sig, seq, prev_hash))
        record = AppendedRecord(
            envelope=envelope,
            payload=snapshot,
            emitter_sig=emitter_sig,
            seq=seq,
            prev_hash=prev_hash,
            record_hash=record_hash,
            extra={},
        )
        self._records.append(record)
        self._seen_nonces.add((envelope.emitter, envelope.nonce))
        self._seen_evidence_ids.add(envelope.evidence_id)
        # Hand back a detached copy so the caller cannot reach internal state.
        return _detach_record(record)

    def verify_chain(self) -> None:
        """Re-derive the whole log from scratch; raise on the first violation, else return None.

        Trusts no stored derived value: it recomputes ``payload_hash`` from the stored
        payload, re-verifies each emitter signature through the registry, recomputes every
        ``record_hash``, re-walks the ``seq``/``prev_hash`` chain from genesis, and rebuilds
        the seen-nonce set independently of the live ``_seen_nonces``.
        """
        seen: set[tuple[str, str]] = set()
        seen_ids: set[str] = set()
        for i, record in enumerate(self._records):
            # Structural: a stored record must be well-formed.
            if not isinstance(record, AppendedRecord) or not isinstance(
                record.envelope, SigningEnvelope
            ):
                raise EvidenceError(f"{REASON_MALFORMED}: record at index {i} is malformed")
            env = record.envelope
            if env.schema_version != SCHEMA_VERSION:
                raise EvidenceError(f"{REASON_SCHEMA_UNSUPPORTED}: index {i}")
            if not _valid_evidence_id(env.evidence_id):
                raise EvidenceError(f"{REASON_EVIDENCE_ID_INVALID}: index {i}")
            if env.sink_id != self._sink_id:
                raise EvidenceError(f"{REASON_SINK_MISMATCH}: index {i}")
            if not env.nonce:
                raise EvidenceError(f"{REASON_MALFORMED}: index {i} has no nonce")
            # Position: seq must equal the index (catches gaps and reorders).
            if record.seq != i:
                raise EvidenceError(f"{REASON_SEQ_GAP}: index {i} has seq {record.seq!r}")
            # Chain: genesis for the first record, else the prior record_hash.
            expected_prev = (
                GENESIS_PREV_HASH if i == 0 else self._records[i - 1].record_hash
            )
            if record.prev_hash != expected_prev:
                raise EvidenceError(f"{REASON_CHAIN_BROKEN}: index {i}")
            # Payload binding: recompute from the stored payload.
            if payload_digest(record.payload) != env.payload_hash:
                raise EvidenceError(f"{REASON_PAYLOAD_HASH_MISMATCH}: index {i}")
            # Authorship: re-verify the emitter signature (unknown key -> REASON_UNKNOWN_EMITTER).
            key = self._registry.get(env.emitter, env.emitter_key_id)
            if not verify_envelope_signature(env, record.emitter_sig, key):
                raise EvidenceError(f"{REASON_SIG_INVALID}: index {i}")
            # Integrity: recompute the record hash over the shared core.
            expected_hash = record_digest(
                _hashable_core(env, record.emitter_sig, record.seq, record.prev_hash)
            )
            if expected_hash != record.record_hash:
                raise EvidenceError(f"{REASON_RECORD_HASH_MISMATCH}: index {i}")
            # Replay, from scratch: no (emitter, nonce) may recur.
            replay_key = (env.emitter, env.nonce)
            if replay_key in seen:
                raise EvidenceError(f"{REASON_REPLAY}: index {i} duplicate {replay_key!r}")
            seen.add(replay_key)
            # Portable identity, from scratch: no evidence_id may recur.
            if env.evidence_id in seen_ids:
                raise EvidenceError(
                    f"{REASON_DUPLICATE_EVIDENCE_ID}: index {i} duplicate {env.evidence_id!r}"
                )
            seen_ids.add(env.evidence_id)
