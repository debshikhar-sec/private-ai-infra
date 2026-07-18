"""Durable, single-node SQLite evidence store (Step 7A).

A SQLite-backed :class:`~openclaw.sink.EvidenceSink`: the same verifier-owned, append-only,
tamper-evident log — same validation, same ``seq``/``prev_hash``/``record_hash`` chaining,
same ``verify_chain`` — that *persists* across process restarts.

It is a thin durable backing over the in-memory sink, deliberately reusing (never
re-implementing) the frozen 1A–1C substrate:

  * ``append`` reuses the parent's full ``_validate_submission`` precondition sequence, then
    positions and persists the record inside one ``BEGIN IMMEDIATE`` transaction (read the
    authoritative head → assign ``seq``/``prev_hash`` → compute ``record_hash`` with the
    existing functions → insert → commit), and only then updates the in-memory mirror. Any
    validation/constraint/commit failure leaves the chain unchanged.
  * On open it validates the schema version, loads every record in ``seq`` order, rebuilds the
    typed records **without trusting any stored derived value**, and runs the parent's
    ``verify_chain`` — so tampering, gaps, duplicates, or a broken chain fail closed before the
    store is usable.

Nothing about the signed contracts changes: ``SigningEnvelope``, canonicalization,
``evidence_digest``, ``record_hash``, ``EvidenceRef``, payload contracts, and signature
algorithm all come from :mod:`openclaw.sink`. Standard library only; parameterized SQL only;
no pickle. The raw payload and signature are stored as detached JSON/text — never a key.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Protocol, runtime_checkable

from openclaw import sink as _sink
from openclaw.sink import (
    AppendedRecord,
    EmitterKeyRegistry,
    EvidenceError,
    EvidenceSink,
    SigningEnvelope,
    _detach_record,
    _detached_payload,
    _hashable_core,
    record_digest,
)
from openclaw.sqlite_util import DurableStoreError, connect, migrate, transaction


@runtime_checkable
class EvidenceStore(Protocol):
    """The narrow evidence surface both the in-memory and durable sinks implement.

    A structural protocol (Step 7A): a verifier or gateway holds an ``EvidenceStore`` and
    neither knows nor cares whether it is the in-memory :class:`~openclaw.sink.EvidenceSink`
    or the durable :class:`SqliteEvidenceSink`. Signed contracts and validation are identical;
    only persistence differs.
    """

    @property
    def sink_id(self) -> str: ...

    @property
    def head_hash(self) -> str: ...

    @property
    def records(self) -> tuple: ...

    def __len__(self) -> int: ...

    def append(
        self, envelope: SigningEnvelope, payload: Any, emitter_sig: str
    ) -> AppendedRecord: ...

    def verify_chain(self) -> None: ...


# This evidence database's own schema-version domain — separate from the evidence-envelope
# ``SCHEMA_VERSION`` (which versions the signed record shape). Bump only via a forward step.
EVIDENCE_DB_SCHEMA_VERSION = 1

# A single statement, run via ``conn.execute`` (never ``executescript``, which would COMMIT
# our explicit migration transaction).
_CREATE_RECORDS = """
CREATE TABLE records (
    seq          INTEGER PRIMARY KEY,
    evidence_id  TEXT NOT NULL UNIQUE,
    emitter      TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    envelope     TEXT NOT NULL,
    payload      TEXT NOT NULL,
    emitter_sig  TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    record_hash  TEXT NOT NULL,
    extra        TEXT NOT NULL,
    UNIQUE(emitter, nonce)
)
"""


def _migrate_to_v1(conn: sqlite3.Connection) -> None:
    """Forward migration 0 -> 1: create the initial evidence schema."""
    conn.execute(_CREATE_RECORDS)


_MIGRATIONS = [_migrate_to_v1]


def _envelope_from_json(text: str) -> SigningEnvelope:
    """Reconstruct a :class:`SigningEnvelope` from its stored canonical mapping JSON."""
    try:
        m = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise DurableStoreError(f"malformed stored envelope JSON: {exc}") from exc
    if not isinstance(m, dict):
        raise DurableStoreError("stored envelope is not a JSON object")
    try:
        return SigningEnvelope(
            schema_version=m["schema_version"],
            evidence_id=m["evidence_id"],
            sink_id=m["sink_id"],
            run_id=m["run_id"],
            emitter=m["emitter"],
            emitter_key_id=m["emitter_key_id"],
            record_type=m["record_type"],
            payload_hash=m["payload_hash"],
            ts=m["ts"],
            nonce=m["nonce"],
            approval_id=m.get("approval_id"),
        )
    except (KeyError, TypeError) as exc:
        raise DurableStoreError(f"stored envelope is missing a field: {exc}") from exc


class SqliteEvidenceSink(EvidenceSink):
    """Durable evidence sink — the same surface/semantics as ``EvidenceSink``, backed by SQLite.

    Construction opens (and migrates) the database, loads and re-verifies the whole chain, and
    populates the in-memory mirror the parent's read properties (``records``/``head_hash``/
    ``__len__``) and validation (``_seen_nonces``/``_seen_evidence_ids``) use.
    """

    def __init__(self, sink_id: str, registry: EmitterKeyRegistry, *, path: str) -> None:
        super().__init__(sink_id, registry)
        self._path = str(path)
        self._conn = connect(self._path)
        migrate(self._conn, "evidence", EVIDENCE_DB_SCHEMA_VERSION, _MIGRATIONS)
        self._load_and_verify()

    def close(self) -> None:
        self._conn.close()

    # -- load / integrity --------------------------------------------------------------
    def _load_and_verify(self) -> None:
        """Rebuild the in-memory mirror from the database, then full-chain verify it.

        Loads records in ``seq`` order and reconstructs each :class:`AppendedRecord` from its
        stored (non-derived) fields; ``verify_chain`` then recomputes payload hashes, signatures,
        sequence, previous hashes, record hashes, and nonce/evidence-id uniqueness from scratch.
        A load or verification failure leaves the database untouched and fails closed.
        """
        rows = self._conn.execute(
            "SELECT seq, envelope, payload, emitter_sig, prev_hash, record_hash, extra "
            "FROM records ORDER BY seq ASC"
        ).fetchall()
        for i, row in enumerate(rows):
            if row["seq"] != i:
                raise DurableStoreError(
                    f"evidence database has a sequence gap at index {i} (seq {row['seq']!r})"
                )
            envelope = _envelope_from_json(row["envelope"])
            try:
                payload = json.loads(row["payload"])
                extra = json.loads(row["extra"])
            except (ValueError, TypeError) as exc:
                raise DurableStoreError(f"malformed stored JSON at seq {i}: {exc}") from exc
            if not isinstance(extra, dict):
                raise DurableStoreError(f"stored extra at seq {i} is not an object")
            record = AppendedRecord(
                envelope=envelope,
                payload=payload,
                emitter_sig=row["emitter_sig"],
                seq=row["seq"],
                prev_hash=row["prev_hash"],
                record_hash=row["record_hash"],
                extra=extra,
            )
            self._records.append(record)
            self._seen_nonces.add((envelope.emitter, envelope.nonce))
            self._seen_evidence_ids.add(envelope.evidence_id)
        # Trust nothing derived: re-verify the entire chain from scratch (raises on any break).
        self.verify_chain()

    # -- append (durable) --------------------------------------------------------------
    def append(
        self, envelope: SigningEnvelope, payload: Any, emitter_sig: str
    ) -> AppendedRecord:
        """Validate, then durably chain, one evidence record. Fail-closed; returns a detached copy.

        Same preconditions as the in-memory sink (via ``_validate_submission``); the record is
        positioned and inserted in one transaction that reads the authoritative head, so a
        competing writer cannot claim the same ``seq``. The in-memory mirror is updated only
        after the commit succeeds.
        """
        self._validate_submission(envelope, payload, emitter_sig)
        snapshot = _detached_payload(payload)
        try:
            with transaction(self._conn):
                head = self._conn.execute(
                    "SELECT seq, record_hash FROM records ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if head is None:
                    seq = 0
                    prev_hash = _sink.GENESIS_PREV_HASH
                else:
                    seq = head["seq"] + 1
                    prev_hash = head["record_hash"]
                record_hash = record_digest(
                    _hashable_core(envelope, emitter_sig, seq, prev_hash)
                )
                self._conn.execute(
                    "INSERT INTO records (seq, evidence_id, emitter, nonce, envelope, "
                    "payload, emitter_sig, prev_hash, record_hash, extra) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        seq,
                        envelope.evidence_id,
                        envelope.emitter,
                        envelope.nonce,
                        json.dumps(envelope.to_mapping(), separators=(",", ":"),
                                   ensure_ascii=False),
                        json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False),
                        emitter_sig,
                        prev_hash,
                        record_hash,
                        "{}",
                    ),
                )
        except sqlite3.IntegrityError as exc:
            # A UNIQUE(evidence_id) / UNIQUE(emitter, nonce) / PK(seq) violation — the durable
            # backstop for the same identities ``_validate_submission`` guards in memory.
            raise EvidenceError(f"{_sink.REASON_MALFORMED}: durable constraint violated: {exc}") from exc
        # Committed — now update the in-memory mirror to match.
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
        return _detach_record(record)
