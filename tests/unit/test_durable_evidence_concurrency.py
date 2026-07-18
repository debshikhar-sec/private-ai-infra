"""Evidence-store append synchronization under concurrency (Step 7A.1).

``SqliteEvidenceSink.append`` serializes the whole operation (validate -> position -> commit ->
mirror), so concurrent appends from many threads produce one valid, contiguously ordered chain
whose database and in-memory mirror agree exactly, and an injected mid-append failure leaves
both — and the seen-nonce / seen-evidence-id sets — unchanged. Coordination uses a barrier and a
forwarding proxy; correctness never depends on timing sleeps.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest
from openclaw import sink as sinkmod
from openclaw.sink import EmitterKeyRegistry, SigningEnvelope
from openclaw.sink_sqlite import SqliteEvidenceSink

_SINK_ID = "sink-conc-1"
_KEY = b"0123456789abcdef0123456789abcdef"
_KEY_ID = "opencode-hmac-1"


def _registry():
    reg = EmitterKeyRegistry()
    reg.register(sinkmod.EMITTER_OPENCODE, _KEY_ID, _KEY)
    return reg


def _signed(i: int):
    payload = {"i": i}
    env = SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(),
        sink_id=_SINK_ID,
        run_id=f"run-{i}",
        emitter=sinkmod.EMITTER_OPENCODE,
        emitter_key_id=_KEY_ID,
        record_type="apply_result",
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-07-05T00:00:00Z",
        nonce=f"n-{i}",
        approval_id="appr-xyz",
    )
    return env, payload, sinkmod.sign_envelope(env, _KEY)


def _db_rows(path):
    raw = sqlite3.connect(path)
    raw.row_factory = sqlite3.Row
    try:
        return raw.execute(
            "SELECT seq, evidence_id, nonce, record_hash FROM records ORDER BY seq ASC"
        ).fetchall()
    finally:
        raw.close()


def test_concurrent_appends_produce_one_valid_ordered_chain(tmp_path):
    path = str(tmp_path / "evidence.sqlite3")
    sink = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    n_threads, per = 8, 6
    total = n_threads * per
    barrier = threading.Barrier(n_threads)
    errors: list[Exception] = []

    def worker(base: int):
        barrier.wait()  # release all workers together to maximize interleaving
        try:
            for k in range(per):
                sink.append(*_signed(base + k))
        except Exception as exc:  # pragma: no cover - surfaced via assert below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(t * per,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    # In-memory mirror is a contiguous, correctly chained sequence.
    assert len(sink) == total
    assert [r.seq for r in sink.records] == list(range(total))
    sink.verify_chain()
    # Database agrees with the mirror on order and head.
    rows = _db_rows(path)
    assert [r["seq"] for r in rows] == list(range(total))
    assert [r["record_hash"] for r in rows] == [r.record_hash for r in sink.records]
    assert sink.head_hash == rows[-1]["record_hash"]
    # Every nonce and evidence id is represented exactly once, mirror == database.
    assert len({r["nonce"] for r in rows}) == total
    assert len({r["evidence_id"] for r in rows}) == total
    assert {r.envelope.evidence_id for r in sink.records} == {r["evidence_id"] for r in rows}
    sink.close()


class _FailOnInsert:
    """Forwarding proxy that raises on the first INSERT — deterministic, no sleeps."""

    def __init__(self, real):
        self._real = real
        self.armed = True

    def execute(self, sql, *args, **kwargs):
        if self.armed and "INSERT INTO records" in sql:
            self.armed = False
            raise sqlite3.OperationalError("injected insert failure")
        return self._real.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_injected_append_failure_leaves_db_and_mirror_and_sets_unchanged(tmp_path):
    path = str(tmp_path / "evidence.sqlite3")
    sink = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    sink.append(*_signed(0))
    before = {
        "len": len(sink),
        "head": sink.head_hash,
        "records": list(sink.records),
        "nonces": set(sink._seen_nonces),
        "eids": set(sink._seen_evidence_ids),
        "db": [tuple(r) for r in _db_rows(path)],
    }
    sink._conn = _FailOnInsert(sink._conn)
    with pytest.raises(sqlite3.OperationalError):
        sink.append(*_signed(1))
    sink._conn = sink._conn._real
    assert len(sink) == before["len"]
    assert sink.head_hash == before["head"]
    assert list(sink.records) == before["records"]
    assert set(sink._seen_nonces) == before["nonces"]
    assert set(sink._seen_evidence_ids) == before["eids"]
    assert [tuple(r) for r in _db_rows(path)] == before["db"]
    # Still healthy and appendable afterwards.
    sink.append(*_signed(2))
    sink.verify_chain()
    sink.close()
