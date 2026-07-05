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
