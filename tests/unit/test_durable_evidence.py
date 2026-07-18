"""Durable evidence store (Step 7A) — contract, restart survival, crashes, integrity.

The SQLite ``SqliteEvidenceSink`` must be behaviorally indistinguishable from the in-memory
``EvidenceSink`` (same append validation, same ``seq``/``prev_hash``/``record_hash`` chaining,
same ``verify_chain``, same replay + portable-identity uniqueness) while *persisting* across
restarts and refusing to open on a tampered/broken chain. Signed contracts are untouched.
"""

from __future__ import annotations

import json
import sqlite3

import pytest
from openclaw import sink as sinkmod
from openclaw.sink import EmitterKeyRegistry, EvidenceError, EvidenceSink, SigningEnvelope
from openclaw.sink_sqlite import (
    EVIDENCE_DB_SCHEMA_VERSION,
    EvidenceStore,
    SqliteEvidenceSink,
)
from openclaw.sqlite_util import DurableStoreError

_SINK_ID = "sink-durable-1"
_KEY = b"0123456789abcdef0123456789abcdef"
_KEY2 = b"ffffffffffffffffffffffffffffffff"
_KEY_ID = "opencode-hmac-1"


def _registry(key=_KEY):
    reg = EmitterKeyRegistry()
    reg.register(sinkmod.EMITTER_OPENCODE, _KEY_ID, key)
    return reg


def _signed(payload=None, *, nonce="n-1", evidence_id=None, run_id="run-abc", key=_KEY):
    if payload is None:
        payload = {"status": "applied", "changed_files": ["a.py"]}
    env = SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id() if evidence_id is None else evidence_id,
        sink_id=_SINK_ID,
        run_id=run_id,
        emitter=sinkmod.EMITTER_OPENCODE,
        emitter_key_id=_KEY_ID,
        record_type="apply_result",
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-07-05T00:00:00Z",
        nonce=nonce,
        approval_id="appr-xyz",
    )
    return env, payload, sinkmod.sign_envelope(env, key)


def _evidence_path(tmp_path) -> str:
    return str(tmp_path / "evidence.sqlite3")


def _append_n(sink, n):
    out = []
    for i in range(n):
        out.append(sink.append(*_signed(payload={"i": i}, nonce=f"n-{i}", run_id=f"run-{i}")))
    return out


# ============================================================ shared behavioral contract
@pytest.fixture(params=["memory", "sqlite"])
def sink(request, tmp_path):
    if request.param == "memory":
        yield EvidenceSink(_SINK_ID, _registry())
    else:
        s = SqliteEvidenceSink(_SINK_ID, _registry(), path=_evidence_path(tmp_path))
        yield s
        s.close()


def test_sink_satisfies_evidence_protocol(sink):
    assert isinstance(sink, EvidenceStore)


def test_append_and_head_and_len(sink):
    assert len(sink) == 0
    assert sink.head_hash == sinkmod.GENESIS_PREV_HASH
    rec = sink.append(*_signed())
    assert len(sink) == 1
    assert rec.seq == 0
    assert rec.prev_hash == sinkmod.GENESIS_PREV_HASH
    assert sink.head_hash == rec.record_hash


def test_chain_grows_and_verifies(sink):
    recs = _append_n(sink, 4)
    assert [r.seq for r in recs] == [0, 1, 2, 3]
    for i in range(1, 4):
        assert recs[i].prev_hash == recs[i - 1].record_hash
    sink.verify_chain()  # no raise


def test_returned_records_are_detached(sink):
    rec = sink.append(*_signed(payload={"k": ["v"]}))
    rec.payload["k"].append("mutated")
    # Mutating the handed-back copy must not change what the sink holds.
    assert sink.records[0].payload == {"k": ["v"]}


def test_replay_refused(sink):
    sink.append(*_signed(nonce="dup"))
    with pytest.raises(EvidenceError) as exc:
        sink.append(*_signed(payload={"other": 1}, nonce="dup"))
    assert sinkmod.REASON_REPLAY in str(exc.value)


def test_duplicate_evidence_id_refused(sink):
    fixed = "ev-" + "a" * 32
    sink.append(*_signed(nonce="n-a", evidence_id=fixed))
    with pytest.raises(EvidenceError) as exc:
        sink.append(*_signed(payload={"z": 2}, nonce="n-b", evidence_id=fixed))
    assert sinkmod.REASON_DUPLICATE_EVIDENCE_ID in str(exc.value)


def test_bad_signature_refused(sink):
    env, payload, _ = _signed()
    bad_sig = sinkmod.sign_envelope(env, _KEY2)  # signed with the wrong key
    with pytest.raises(EvidenceError):
        sink.append(env, payload, bad_sig)
    assert len(sink) == 0


def test_payload_binding_enforced(sink):
    env, payload, sig = _signed()
    with pytest.raises(EvidenceError):
        sink.append(env, {"tampered": True}, sig)
    assert len(sink) == 0


# ============================================================ restart survival (sqlite)
def test_multi_record_chain_survives_reopen(tmp_path):
    path = _evidence_path(tmp_path)
    s1 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    refs = [r.evidence_ref() for r in _append_n(s1, 3)]
    head = s1.head_hash
    s1.close()

    s2 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    assert len(s2) == 3
    assert s2.head_hash == head
    s2.verify_chain()
    # Stable evidence references remain byte-identical after reopen.
    reopened = [r.evidence_ref() for r in s2.records]
    assert reopened == refs
    s2.close()


def test_sequence_and_head_resume_after_reopen(tmp_path):
    path = _evidence_path(tmp_path)
    s1 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    _append_n(s1, 2)
    prev_head = s1.head_hash
    s1.close()

    s2 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    rec = s2.append(*_signed(payload={"i": 99}, nonce="n-99", run_id="run-99"))
    assert rec.seq == 2
    assert rec.prev_hash == prev_head
    s2.verify_chain()
    s2.close()


def test_replay_defence_survives_reopen(tmp_path):
    path = _evidence_path(tmp_path)
    s1 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s1.append(*_signed(nonce="keep"))
    s1.close()
    s2 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    with pytest.raises(EvidenceError) as exc:
        s2.append(*_signed(payload={"x": 1}, nonce="keep"))
    assert sinkmod.REASON_REPLAY in str(exc.value)
    s2.close()


# ============================================================ crash / transaction (sqlite)
class _FailingConn:
    def __init__(self, real, needle):
        self._real = real
        self._needle = needle
        self.armed = True

    def execute(self, sql, *args, **kwargs):
        if self.armed and self._needle in sql:
            self.armed = False
            raise sqlite3.OperationalError(f"injected failure on {self._needle!r}")
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_append_insert_failure_leaves_length_and_head_unchanged(tmp_path):
    path = _evidence_path(tmp_path)
    sink = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    sink.append(*_signed(nonce="ok"))
    head_before, len_before = sink.head_hash, len(sink)
    sink._conn = _FailingConn(sink._conn, "INSERT INTO records")
    with pytest.raises(sqlite3.OperationalError):
        sink.append(*_signed(payload={"x": 1}, nonce="fail"))
    sink._conn = sink._conn._real
    assert len(sink) == len_before
    assert sink.head_hash == head_before
    sink.close()


def test_reopen_after_interrupted_append_returns_committed_chain(tmp_path):
    path = _evidence_path(tmp_path)
    s1 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s1.append(*_signed(nonce="ok"))
    s1._conn = _FailingConn(s1._conn, "INSERT INTO records")
    with pytest.raises(sqlite3.OperationalError):
        s1.append(*_signed(payload={"x": 1}, nonce="fail"))
    s1._conn = s1._conn._real
    s1.close()

    s2 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    assert len(s2) == 1  # only the committed record survived
    s2.verify_chain()
    s2.close()


def test_committed_record_survives_reconstruction(tmp_path):
    path = _evidence_path(tmp_path)
    s1 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    rec = s1.append(*_signed(nonce="only"))
    rh = rec.record_hash
    s1.close()
    s2 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    assert s2.records[0].record_hash == rh
    s2.close()


# ============================================================ integrity (sqlite)
def _corrupt(path, sql, params=()):
    raw = sqlite3.connect(path)
    raw.execute(sql, params)
    raw.commit()
    raw.close()


def test_fresh_evidence_db_is_at_current_schema(tmp_path):
    path = _evidence_path(tmp_path)
    sink = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    row = sink._conn.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    assert int(row[0]) == EVIDENCE_DB_SCHEMA_VERSION
    assert str(sink._conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() == "wal"
    sink.close()


def test_tampered_payload_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    _corrupt(path, "UPDATE records SET payload=? WHERE seq=0", (json.dumps({"evil": 1}),))
    with pytest.raises(EvidenceError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_tampered_signature_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    _corrupt(path, "UPDATE records SET emitter_sig='hmac-sha256:' || ? WHERE seq=0",
             ("0" * 64,))
    with pytest.raises(EvidenceError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_changed_record_hash_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    _corrupt(path, "UPDATE records SET record_hash='sha256:' || ? WHERE seq=0", ("0" * 64,))
    with pytest.raises(EvidenceError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_changed_prev_hash_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    _append_n(s, 2)
    s.close()
    _corrupt(path, "UPDATE records SET prev_hash='sha256:' || ? WHERE seq=1", ("0" * 64,))
    with pytest.raises(EvidenceError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_sequence_gap_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    _append_n(s, 2)
    s.close()
    _corrupt(path, "UPDATE records SET seq=5 WHERE seq=1")
    with pytest.raises(DurableStoreError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_malformed_stored_json_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    _corrupt(path, "UPDATE records SET payload='{not json' WHERE seq=0")
    with pytest.raises(DurableStoreError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_missing_verification_key_fails_closed_on_open(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    # An empty registry cannot verify the stored emitter signature.
    with pytest.raises(EvidenceError):
        SqliteEvidenceSink(_SINK_ID, EmitterKeyRegistry(), path=path)


def test_unsupported_future_evidence_schema_fails_closed(tmp_path):
    path = _evidence_path(tmp_path)
    SqliteEvidenceSink(_SINK_ID, _registry(), path=path).close()
    _corrupt(path, "UPDATE schema_meta SET value='999' WHERE key='schema_version'")
    with pytest.raises(DurableStoreError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)


def test_reopen_healthy_database(tmp_path):
    path = _evidence_path(tmp_path)
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    _append_n(s, 3)
    s.close()
    s2 = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)  # no raise
    assert len(s2) == 3
    s2.close()
