"""Evidence sink — Step 1A: canonicalization, digests, and constants only.

These tests pin the deterministic substrate the rest of the sink builds on. They exercise
*no* trust mechanics (no signing, no append, no chain) — those arrive in 1B/1C. A green run
proves: canonical bytes are order-independent and reproducible, the digests are correctly
formatted and change exactly when their inputs change, the pinned constants are what the
design says, and the serializer is pure (no filesystem side effects, fail-closed on junk).
"""

import re

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
