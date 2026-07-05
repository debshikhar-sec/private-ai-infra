"""Evidence sink — Steps 1A + 1B + 1C.

1A pins the deterministic substrate (canonicalization, digests, constants). 1B pins
per-emitter HMAC signing and the key registry. 1C pins the verifier-owned, append-only
``EvidenceSink``: fail-closed ``append`` with sink-assigned ``seq``/``prev_hash``/
``record_hash`` chaining, per-emitter nonce replay defence, a detached payload snapshot so
the sink never shares a caller's mutable object, and ``verify_chain`` which re-derives the
whole log from scratch (tamper/reorder/replay/malformed all break it). None of this wires
into the gateway/agents or touches the filesystem.
"""

import json
import re
from dataclasses import replace

import pytest
from openclaw import sink

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


# 1 + 2 — canonical bytes: deterministic and key-order independent
def test_canonical_bytes_are_deterministic():
    obj = {"b": 1, "a": [1, 2, 3], "c": {"y": 2, "x": 1}}
    assert sink.canonicalize(obj) == sink.canonicalize(dict(obj))


def test_canonical_bytes_independent_of_key_order():
    a = {"a": 1, "b": 2, "c": {"m": 1, "n": 2}}
    b = {"c": {"n": 2, "m": 1}, "b": 2, "a": 1}  # same content, different insertion order
    assert sink.canonicalize(a) == sink.canonicalize(b)


# 3 + 4 — payload_digest: formatted and content-sensitive
def test_payload_digest_is_deterministic_and_formatted():
    payload = {"status": "applied", "changed_files": ["a.py", "b.py"]}
    d1 = sink.payload_digest(payload)
    d2 = sink.payload_digest(dict(payload))
    assert d1 == d2
    assert SHA256_RE.match(d1)


def test_payload_digest_changes_when_payload_changes():
    base = {"status": "applied", "changed_files": ["a.py"]}
    changed = {"status": "applied", "changed_files": ["a.py", "b.py"]}
    assert sink.payload_digest(base) != sink.payload_digest(changed)


# 5..8 — record_digest: formatted and sensitive to each hashable field
def _record_fields(**overrides):
    fields = {
        "schema_version": sink.SCHEMA_VERSION,
        "sink_id": "sink-1",
        "run_id": "run-abc",
        "emitter": sink.EMITTER_OPENCODE,
        "record_type": "apply_result",
        "payload_hash": "sha256:" + "1" * 64,
        "emitter_sig": "hmac-sha256:" + "2" * 64,
        "seq": 0,
        "prev_hash": sink.GENESIS_PREV_HASH,
    }
    fields.update(overrides)
    return fields


def test_record_digest_is_deterministic_and_formatted():
    fields = _record_fields()
    assert sink.record_digest(fields) == sink.record_digest(dict(fields))
    assert SHA256_RE.match(sink.record_digest(fields))


def test_record_digest_changes_when_seq_changes():
    assert sink.record_digest(_record_fields(seq=0)) != sink.record_digest(_record_fields(seq=1))


def test_record_digest_changes_when_prev_hash_changes():
    a = sink.record_digest(_record_fields(prev_hash=sink.GENESIS_PREV_HASH))
    b = sink.record_digest(_record_fields(prev_hash="sha256:" + "a" * 64))
    assert a != b


def test_record_digest_changes_when_payload_hash_changes():
    a = sink.record_digest(_record_fields(payload_hash="sha256:" + "1" * 64))
    b = sink.record_digest(_record_fields(payload_hash="sha256:" + "9" * 64))
    assert a != b


# 9 + 10 — pinned constants
def test_genesis_prev_hash_is_sha256_of_64_zeros():
    assert sink.GENESIS_PREV_HASH == "sha256:" + "0" * 64
    assert SHA256_RE.match(sink.GENESIS_PREV_HASH)


def test_schema_version_is_one():
    assert sink.SCHEMA_VERSION == 1


# 11 — the serializer is pure: no filesystem writes / runtime-log side effects
def test_canonicalization_does_not_touch_the_filesystem(monkeypatch):
    def _no_open(*args, **kwargs):  # pragma: no cover - only fires on a violation
        raise AssertionError("canonicalization must not open/write any file")

    monkeypatch.setattr("builtins.open", _no_open)
    # All three still work with open() disabled -> they perform no file I/O.
    assert SHA256_RE.match(sink.payload_digest({"k": "v"}))
    assert SHA256_RE.match(sink.record_digest(_record_fields()))
    assert sink.canonicalize({"a": 1}) == b'{"a":1}'


# 12 — non-JSON-serializable payload fails closed with a clear exception
def test_non_serializable_payload_fails_closed():
    with pytest.raises(sink.EvidenceError):
        sink.canonicalize({"bad": {1, 2, 3}})  # a set is not JSON-serializable
    with pytest.raises(sink.EvidenceError):
        sink.payload_digest({"bad": object()})  # arbitrary object is not serializable


# Record-model shapes exist and serialize deterministically (defined, not yet wired).
def test_signing_envelope_to_mapping_is_stable():
    env = sink.SigningEnvelope(
        schema_version=sink.SCHEMA_VERSION,
        sink_id="sink-1",
        run_id="run-abc",
        emitter=sink.EMITTER_GATEWAY,
        emitter_key_id="gateway-hmac-1",
        record_type="approval_decided",
        payload_hash="sha256:" + "1" * 64,
        ts="2026-07-05T00:00:00Z",
        nonce="n-1",
        approval_id="appr-xyz",
    )
    m = env.to_mapping()
    assert m["approval_id"] == "appr-xyz"
    assert m["sink_id"] == "sink-1"
    # Deterministic canonical form (no signing performed here).
    assert sink.canonicalize(m) == sink.canonicalize(env.to_mapping())


# =========================== Step 1B: per-emitter HMAC signing ===========================

SIG_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_KEY = b"emitter-key-0123456789abcdef0123"
_KEY2 = b"a-different-emitter-key-abcdef012"


def _envelope(**overrides):
    fields = {
        "schema_version": sink.SCHEMA_VERSION,
        "sink_id": "sink-1",
        "run_id": "run-abc",
        "emitter": sink.EMITTER_OPENCODE,
        "emitter_key_id": "opencode-hmac-1",
        "record_type": "apply_result",
        "payload_hash": "sha256:" + "1" * 64,
        "ts": "2026-07-05T00:00:00Z",
        "nonce": "n-1",
        "approval_id": "appr-xyz",
    }
    fields.update(overrides)
    return sink.SigningEnvelope(**fields)


# 1 + 2 — sign then verify happy path
def test_sign_envelope_returns_hmac_sha256_format():
    sig = sink.sign_envelope(_envelope(), _KEY)
    assert SIG_RE.match(sig)


def test_verify_accepts_matching_envelope_key_signature():
    env = _envelope()
    sig = sink.sign_envelope(env, _KEY)
    assert sink.verify_envelope_signature(env, sig, _KEY) is True


# 3 — wrong key
def test_verify_wrong_key_returns_false():
    env = _envelope()
    sig = sink.sign_envelope(env, _KEY)
    assert sink.verify_envelope_signature(env, sig, _KEY2) is False


# 4..7 — tampered envelope fields (verify a mutated envelope against the original signature)
def test_verify_tampered_run_id_returns_false():
    sig = sink.sign_envelope(_envelope(), _KEY)
    assert sink.verify_envelope_signature(_envelope(run_id="run-evil"), sig, _KEY) is False


def test_verify_tampered_sink_id_returns_false():
    sig = sink.sign_envelope(_envelope(), _KEY)
    assert sink.verify_envelope_signature(_envelope(sink_id="sink-evil"), sig, _KEY) is False


def test_verify_tampered_payload_hash_returns_false():
    sig = sink.sign_envelope(_envelope(), _KEY)
    tampered = _envelope(payload_hash="sha256:" + "9" * 64)
    assert sink.verify_envelope_signature(tampered, sig, _KEY) is False


def test_verify_tampered_nonce_returns_false():
    sig = sink.sign_envelope(_envelope(), _KEY)
    assert sink.verify_envelope_signature(_envelope(nonce="n-evil"), sig, _KEY) is False


# 8 — tampered signature digest
def test_verify_tampered_signature_returns_false():
    env = _envelope()
    sig = sink.sign_envelope(env, _KEY)
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    assert sink.verify_envelope_signature(env, flipped, _KEY) is False


# 9..12 — malformed / unsupported signature strings
def test_verify_signature_without_prefix_returns_false():
    env = _envelope()
    bare = sink.sign_envelope(env, _KEY).split(":", 1)[1]  # digest only, no algo prefix
    assert sink.verify_envelope_signature(env, bare, _KEY) is False


def test_verify_signature_bad_hex_returns_false():
    env = _envelope()
    assert sink.verify_envelope_signature(env, "hmac-sha256:" + "z" * 64, _KEY) is False


def test_verify_signature_wrong_length_returns_false():
    env = _envelope()
    assert sink.verify_envelope_signature(env, "hmac-sha256:" + "a" * 63, _KEY) is False
    assert sink.verify_envelope_signature(env, "hmac-sha256:" + "a" * 65, _KEY) is False


def test_verify_unsupported_algorithm_returns_false():
    env = _envelope()
    good_digest = sink.sign_envelope(env, _KEY).split(":", 1)[1]
    assert sink.verify_envelope_signature(env, "hmac-sha512:" + good_digest, _KEY) is False
    assert sink.verify_envelope_signature(env, "sha256:" + good_digest, _KEY) is False


# 13..17 — registry
def test_registry_register_get_round_trip():
    reg = sink.EmitterKeyRegistry()
    reg.register(sink.EMITTER_OPENCODE, "opencode-hmac-1", _KEY)
    assert reg.get(sink.EMITTER_OPENCODE, "opencode-hmac-1") == _KEY


def test_registry_unknown_emitter_raises():
    reg = sink.EmitterKeyRegistry()
    reg.register(sink.EMITTER_OPENCODE, "opencode-hmac-1", _KEY)
    with pytest.raises(sink.EvidenceError):
        reg.get("nobody", "opencode-hmac-1")


def test_registry_unknown_key_id_raises():
    reg = sink.EmitterKeyRegistry()
    reg.register(sink.EMITTER_OPENCODE, "opencode-hmac-1", _KEY)
    with pytest.raises(sink.EvidenceError):
        reg.get(sink.EMITTER_OPENCODE, "opencode-hmac-2")


def test_registry_empty_key_refused():
    reg = sink.EmitterKeyRegistry()
    with pytest.raises(sink.EvidenceError):
        reg.register(sink.EMITTER_OPENCODE, "opencode-hmac-1", b"")


def test_registry_non_bytes_key_refused():
    reg = sink.EmitterKeyRegistry()
    with pytest.raises(sink.EvidenceError):
        reg.register(sink.EMITTER_OPENCODE, "opencode-hmac-1", "not-bytes")


# 18..20 — determinism + sensitivity
def test_signature_is_deterministic():
    env = _envelope()
    assert sink.sign_envelope(env, _KEY) == sink.sign_envelope(env, _KEY)


def test_signature_changes_when_approval_id_changes():
    a = sink.sign_envelope(_envelope(approval_id="appr-1"), _KEY)
    b = sink.sign_envelope(_envelope(approval_id="appr-2"), _KEY)
    assert a != b


def test_signature_changes_when_record_type_changes():
    a = sink.sign_envelope(_envelope(record_type="apply_result"), _KEY)
    b = sink.sign_envelope(_envelope(record_type="approval_decided"), _KEY)
    assert a != b


# 21 — sign/verify are pure (no filesystem)
def test_sign_and_verify_do_not_touch_the_filesystem(monkeypatch):
    def _no_open(*args, **kwargs):  # pragma: no cover - only fires on a violation
        raise AssertionError("sign/verify must not open/write any file")

    monkeypatch.setattr("builtins.open", _no_open)
    env = _envelope()
    sig = sink.sign_envelope(env, _KEY)
    assert sink.verify_envelope_signature(env, sig, _KEY) is True


# also — sign_envelope / verify structural misuse of the key
def test_sign_envelope_rejects_empty_and_non_bytes_key():
    with pytest.raises(sink.EvidenceError):
        sink.sign_envelope(_envelope(), b"")
    with pytest.raises(sink.EvidenceError):
        sink.sign_envelope(_envelope(), "not-bytes")


# 22 — registry-convenience helpers
def test_sign_and_verify_with_registry_happy_path():
    reg = sink.EmitterKeyRegistry()
    env = _envelope(emitter=sink.EMITTER_OPENCODE, emitter_key_id="opencode-hmac-1")
    reg.register(env.emitter, env.emitter_key_id, _KEY)
    sig = sink.sign_with_registry(env, reg)
    assert SIG_RE.match(sig)
    assert sink.verify_with_registry(env, sig, reg) is True


def test_verify_with_registry_wrong_registered_key_returns_false():
    signer_reg = sink.EmitterKeyRegistry()
    verifier_reg = sink.EmitterKeyRegistry()
    env = _envelope(emitter=sink.EMITTER_OPENCODE, emitter_key_id="opencode-hmac-1")
    signer_reg.register(env.emitter, env.emitter_key_id, _KEY)
    verifier_reg.register(env.emitter, env.emitter_key_id, _KEY2)  # different key
    sig = sink.sign_with_registry(env, signer_reg)
    assert sink.verify_with_registry(env, sig, verifier_reg) is False


# ================ Step 1C: append-only EvidenceSink + verify_chain ================

_SINK_ID = "sink-1"
_OPENCODE_KEY_ID = "opencode-hmac-1"
_GATEWAY_KEY_ID = "gateway-hmac-1"


def _registry(emitter=sink.EMITTER_OPENCODE, key_id=_OPENCODE_KEY_ID, key=_KEY):
    reg = sink.EmitterKeyRegistry()
    reg.register(emitter, key_id, key)
    return reg


def _sink(registry=None):
    return sink.EvidenceSink(_SINK_ID, registry if registry is not None else _registry())


def _signed(
    payload=None,
    *,
    key=_KEY,
    nonce="n-1",
    emitter=sink.EMITTER_OPENCODE,
    key_id=_OPENCODE_KEY_ID,
    approval_id="appr-xyz",
    record_type="apply_result",
    run_id="run-abc",
    sink_id=_SINK_ID,
    schema_version=None,
    ts="2026-07-05T00:00:00Z",
    payload_hash=None,
):
    """Build a submittable ``(envelope, payload, emitter_sig)`` triple.

    ``payload_hash`` defaults to the true digest of ``payload`` (so append's binding check
    passes); pass an explicit value to forge a mismatch. The signature is always valid over
    the (possibly forged) envelope, so signature and payload-binding failures are isolable.
    """
    if payload is None:
        payload = {"status": "applied", "changed_files": ["a.py"]}
    env = sink.SigningEnvelope(
        schema_version=sink.SCHEMA_VERSION if schema_version is None else schema_version,
        sink_id=sink_id,
        run_id=run_id,
        emitter=emitter,
        emitter_key_id=key_id,
        record_type=record_type,
        payload_hash=sink.payload_digest(payload) if payload_hash is None else payload_hash,
        ts=ts,
        nonce=nonce,
        approval_id=approval_id,
    )
    return env, payload, sink.sign_envelope(env, key)


def _append_n(s, n):
    """Append ``n`` valid, distinct records; return the (detached) records handed back."""
    out = []
    for i in range(n):
        env, payload, sig = _signed(
            payload={"i": i}, nonce=f"n-{i}", run_id=f"run-{i}", approval_id=f"appr-{i}"
        )
        out.append(s.append(env, payload, sig))
    return out


# --- construction ---
def test_sink_requires_sink_id_and_registry():
    with pytest.raises(sink.EvidenceError):
        sink.EvidenceSink("", _registry())
    with pytest.raises(sink.EvidenceError):
        sink.EvidenceSink(_SINK_ID, object())


# --- append happy path ---
def test_append_first_record_returns_appended_record():
    s = _sink()
    env, payload, sig = _signed()
    rec = s.append(env, payload, sig)
    assert isinstance(rec, sink.AppendedRecord)
    assert rec.seq == 0
    assert len(s) == 1


def test_append_multiple_records_appends_in_order():
    s = _sink()
    recs = _append_n(s, 3)
    assert [r.seq for r in recs] == [0, 1, 2]
    assert len(s) == 3


def test_seq_increments_from_zero():
    s = _sink()
    _append_n(s, 3)
    assert [r.seq for r in s.records] == [0, 1, 2]


def test_first_record_prev_hash_is_genesis():
    s = _sink()
    rec = s.append(*_signed())
    assert rec.prev_hash == sink.GENESIS_PREV_HASH


def test_prev_hash_chains_to_previous_record_hash():
    s = _sink()
    recs = _append_n(s, 3)
    assert recs[1].prev_hash == recs[0].record_hash
    assert recs[2].prev_hash == recs[1].record_hash


def test_append_recomputes_payload_hash_from_payload():
    s = _sink()
    payload = {"status": "applied"}
    env, _, sig = _signed(payload=payload)
    rec = s.append(env, payload, sig)
    assert sink.payload_digest(rec.payload) == env.payload_hash


def test_record_hash_is_sha256_formatted():
    s = _sink()
    rec = s.append(*_signed())
    assert SHA256_RE.match(rec.record_hash)


def test_record_hash_changes_with_seq():
    env, _, sig = _signed()
    a = sink.record_digest(sink._hashable_core(env, sig, 0, sink.GENESIS_PREV_HASH))
    b = sink.record_digest(sink._hashable_core(env, sig, 1, sink.GENESIS_PREV_HASH))
    assert a != b


def test_record_hash_changes_with_prev_hash():
    env, _, sig = _signed()
    a = sink.record_digest(sink._hashable_core(env, sig, 0, sink.GENESIS_PREV_HASH))
    b = sink.record_digest(sink._hashable_core(env, sig, 0, "sha256:" + "a" * 64))
    assert a != b


def test_record_hash_changes_with_payload_hash():
    env, _, sig = _signed()
    tampered = replace(env, payload_hash="sha256:" + "9" * 64)
    a = sink.record_digest(sink._hashable_core(env, sig, 0, sink.GENESIS_PREV_HASH))
    b = sink.record_digest(sink._hashable_core(tampered, sig, 0, sink.GENESIS_PREV_HASH))
    assert a != b


# --- append rejections (fail closed) ---
def test_append_rejects_malformed_envelope_or_signature():
    s = _sink()
    env, payload, sig = _signed()
    with pytest.raises(sink.EvidenceError, match=sink.REASON_MALFORMED):
        s.append("not-an-envelope", payload, sig)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_MALFORMED):
        s.append(env, payload, 12345)  # non-string signature


def test_append_rejects_schema_mismatch():
    s = _sink()
    env, payload, sig = _signed(schema_version=99)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_SCHEMA_UNSUPPORTED):
        s.append(env, payload, sig)


def test_append_rejects_sink_id_mismatch():
    s = _sink()
    env, payload, sig = _signed(sink_id="sink-evil")
    with pytest.raises(sink.EvidenceError, match=sink.REASON_SINK_MISMATCH):
        s.append(env, payload, sig)


def test_append_rejects_empty_nonce():
    s = _sink()
    env, payload, sig = _signed(nonce="")
    with pytest.raises(sink.EvidenceError, match=sink.REASON_MALFORMED):
        s.append(env, payload, sig)


def test_append_rejects_unknown_emitter_or_key():
    s = _sink()
    env, payload, sig = _signed(key_id="opencode-hmac-does-not-exist")
    with pytest.raises(sink.EvidenceError, match=sink.REASON_UNKNOWN_EMITTER):
        s.append(env, payload, sig)


def test_append_rejects_bad_signature():
    s = _sink()
    env, payload, _ = _signed()
    bad_sig = sink.sign_envelope(env, _KEY2)  # signed with a key the registry does not hold
    with pytest.raises(sink.EvidenceError, match=sink.REASON_SIG_INVALID):
        s.append(env, payload, bad_sig)


def test_append_rejects_payload_hash_mismatch():
    s = _sink()
    # Envelope commits to the hash of {"a": 1}, but a different payload is submitted.
    env, _, sig = _signed(payload={"a": 1})
    with pytest.raises(sink.EvidenceError, match=sink.REASON_PAYLOAD_HASH_MISMATCH):
        s.append(env, {"a": 2}, sig)


def test_append_rejects_replayed_nonce():
    s = _sink()
    s.append(*_signed(nonce="n-dup"))
    with pytest.raises(sink.EvidenceError, match=sink.REASON_REPLAY):
        s.append(*_signed(nonce="n-dup", payload={"different": True}))


def test_append_allows_same_nonce_across_different_emitters():
    reg = sink.EmitterKeyRegistry()
    reg.register(sink.EMITTER_OPENCODE, _OPENCODE_KEY_ID, _KEY)
    reg.register(sink.EMITTER_GATEWAY, _GATEWAY_KEY_ID, _KEY2)
    s = sink.EvidenceSink(_SINK_ID, reg)
    s.append(*_signed(emitter=sink.EMITTER_OPENCODE, key_id=_OPENCODE_KEY_ID, key=_KEY,
                      nonce="shared"))
    s.append(*_signed(emitter=sink.EMITTER_GATEWAY, key_id=_GATEWAY_KEY_ID, key=_KEY2,
                      nonce="shared", record_type="approval_decided", approval_id=None))
    assert len(s) == 2
    s.verify_chain()


def test_append_leaves_no_partial_state_on_rejection():
    s = _sink()
    s.append(*_signed(nonce="n-0"))
    head_before, len_before = s.head_hash, len(s)
    # A rejected append (bad signature) must not consume the nonce or touch the chain.
    env, payload, _ = _signed(nonce="n-1")
    with pytest.raises(sink.EvidenceError):
        s.append(env, payload, sink.sign_envelope(env, _KEY2))
    assert len(s) == len_before
    assert s.head_hash == head_before
    # The same nonce is still free -> a valid append with it succeeds.
    s.append(*_signed(nonce="n-1"))
    assert len(s) == len_before + 1


# --- detached payload snapshot (mutability contract) ---
def test_append_stores_detached_payload_snapshot():
    s = _sink()
    payload = {"status": "applied", "files": ["a.py"]}
    env, _, sig = _signed(payload=payload)
    returned = s.append(env, payload, sig)
    payload["files"].append("evil.py")  # mutate the caller's original after append
    assert s.records[0].payload == {"status": "applied", "files": ["a.py"]}
    assert returned.payload == {"status": "applied", "files": ["a.py"]}
    s.verify_chain()


def test_mutating_caller_payload_after_append_does_not_change_stored_record():
    s = _sink()
    payload = {"nested": {"k": ["v"]}}
    env, _, sig = _signed(payload=payload)
    s.append(env, payload, sig)
    payload["nested"]["k"].append("evil")
    assert s.records[0].payload == {"nested": {"k": ["v"]}}
    s.verify_chain()  # stored payload still matches its payload_hash


def test_records_property_does_not_expose_mutable_internal_payload():
    s = _sink()
    s.append(*_signed(payload={"files": ["a.py"]}))
    s.records[0].payload["files"].append("evil.py")  # mutate a handed-out snapshot
    assert s.records[0].payload["files"] == ["a.py"]  # a fresh snapshot is clean
    s.verify_chain()


def test_mutating_records_snapshot_does_not_change_internal_state():
    s = _sink()
    s.append(*_signed())
    snapshot = s.records
    snapshot[0].extra["injected"] = True
    snapshot[0].payload["tampered"] = True
    assert s.records[0].extra == {}
    assert "tampered" not in s.records[0].payload
    s.verify_chain()


# --- sink surface ---
def test_records_property_returns_tuple_snapshot():
    s = _sink()
    _append_n(s, 2)
    recs = s.records
    assert isinstance(recs, tuple)
    assert len(recs) == 2


def test_len_reflects_appended_count():
    s = _sink()
    assert len(s) == 0
    s.append(*_signed(nonce="n-0"))
    s.append(*_signed(nonce="n-1"))
    assert len(s) == 2


def test_head_hash_is_genesis_when_empty_then_tracks_last_record():
    s = _sink()
    assert s.head_hash == sink.GENESIS_PREV_HASH
    rec = s.append(*_signed())
    assert s.head_hash == rec.record_hash


# --- verify_chain: clean ---
def test_verify_chain_passes_for_clean_records():
    s = _sink()
    _append_n(s, 4)
    s.verify_chain()  # does not raise


def test_verify_chain_passes_for_empty_sink():
    _sink().verify_chain()  # does not raise


# --- verify_chain: tamper / reorder / replay / malformed ---
def test_verify_chain_fails_on_reordered_records():
    s = _sink()
    _append_n(s, 3)
    s._records[0], s._records[1] = s._records[1], s._records[0]
    with pytest.raises(sink.EvidenceError):
        s.verify_chain()


def test_verify_chain_fails_on_seq_gap():
    s = _sink()
    _append_n(s, 2)
    s._records[1] = replace(s._records[1], seq=5)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_SEQ_GAP):
        s.verify_chain()


def test_verify_chain_fails_on_prev_hash_tamper():
    s = _sink()
    _append_n(s, 2)
    s._records[1] = replace(s._records[1], prev_hash="sha256:" + "a" * 64)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_CHAIN_BROKEN):
        s.verify_chain()


def test_verify_chain_fails_on_record_hash_tamper():
    s = _sink()
    _append_n(s, 1)
    s._records[0] = replace(s._records[0], record_hash="sha256:" + "b" * 64)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_RECORD_HASH_MISMATCH):
        s.verify_chain()


def test_verify_chain_fails_on_envelope_field_tamper():
    s = _sink()
    _append_n(s, 1)
    tampered_env = replace(s._records[0].envelope, run_id="run-evil")
    s._records[0] = replace(s._records[0], envelope=tampered_env)
    with pytest.raises(sink.EvidenceError):
        s.verify_chain()


def test_verify_chain_fails_on_payload_tamper():
    s = _sink()
    s.append(*_signed(payload={"files": ["a.py"]}))
    s._records[0] = replace(s._records[0], payload={"files": ["evil.py"]})
    with pytest.raises(sink.EvidenceError, match=sink.REASON_PAYLOAD_HASH_MISMATCH):
        s.verify_chain()


def test_verify_chain_detects_internal_payload_tamper():
    s = _sink()
    s.append(*_signed(payload={"files": ["a.py"]}))
    s._records[0].payload["files"].append("evil.py")  # mutate private stored payload
    with pytest.raises(sink.EvidenceError, match=sink.REASON_PAYLOAD_HASH_MISMATCH):
        s.verify_chain()


def test_verify_chain_fails_on_payload_hash_tamper():
    s = _sink()
    s.append(*_signed())
    env = s._records[0].envelope
    s._records[0] = replace(
        s._records[0], envelope=replace(env, payload_hash="sha256:" + "9" * 64)
    )
    with pytest.raises(sink.EvidenceError):
        s.verify_chain()


def test_verify_chain_fails_on_emitter_sig_tamper():
    s = _sink()
    s.append(*_signed())
    sig = s._records[0].emitter_sig
    flipped = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    s._records[0] = replace(s._records[0], emitter_sig=flipped)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_SIG_INVALID):
        s.verify_chain()


def test_verify_chain_surfaces_unknown_emitter_key():
    s = _sink()
    s.append(*_signed())
    s._registry = sink.EmitterKeyRegistry()  # verifier lost the key
    with pytest.raises(sink.EvidenceError, match=sink.REASON_UNKNOWN_EMITTER):
        s.verify_chain()


def test_verify_chain_fails_on_duplicate_nonce_from_scratch():
    s = _sink()
    env, payload, sig = _signed(nonce="n-dup")
    s.append(env, payload, sig)
    # Hand-craft a second, internally-valid record sharing the same envelope (hence nonce):
    # same envelope -> same valid signature; only the sink-assigned position differs.
    seq = 1
    prev = s.head_hash
    rec = sink.AppendedRecord(
        envelope=env,
        payload=json.loads(sink.canonicalize(payload)),
        emitter_sig=sig,
        seq=seq,
        prev_hash=prev,
        record_hash=sink.record_digest(sink._hashable_core(env, sig, seq, prev)),
        extra={},
    )
    s._records.append(rec)
    with pytest.raises(sink.EvidenceError, match=sink.REASON_REPLAY):
        s.verify_chain()


def test_verify_chain_fails_on_malformed_stored_record():
    s = _sink()
    s.append(*_signed())
    s._records.append("not-a-record")
    with pytest.raises(sink.EvidenceError, match=sink.REASON_MALFORMED):
        s.verify_chain()


# --- purity / no wiring ---
def test_sink_append_and_verify_do_not_touch_the_filesystem(monkeypatch):
    def _no_open(*args, **kwargs):  # pragma: no cover - only fires on a violation
        raise AssertionError("append/verify must not open/write any file")

    monkeypatch.setattr("builtins.open", _no_open)
    s = _sink()
    s.append(*_signed())
    s.verify_chain()
    assert len(s) == 1


def test_sink_module_imports_are_stdlib_only():
    import types

    module_globals = {
        v.__name__ for v in vars(sink).values() if isinstance(v, types.ModuleType)
    }
    # No gateway/agent runtime is pulled into the sink's namespace (no wiring).
    assert not any(name.startswith("private_ai_gateway") for name in module_globals)
    assert not any(
        tok in name for name in module_globals for tok in ("worker", "checks", "orchestration")
    )
