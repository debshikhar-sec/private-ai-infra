"""Minimal, safe SQLite substrate for the verifier-owned durable evidence store (Step 7A).

The evidence store is verifier-owned and must not depend on the gateway package, so this
substrate is a small, self-contained sibling of the gateway's equivalent rather than a shared
import. It gives the durable :class:`~openclaw.sink_sqlite.SqliteEvidenceSink` exactly what it
needs and nothing more:

  * :func:`connect` opens a file-backed connection in autocommit mode and applies (then
    *verifies*) the WAL / foreign-key / synchronous / busy-timeout safety settings. Autocommit
    plus explicit ``BEGIN IMMEDIATE`` gives real transactional DDL and a single-writer append.
  * :func:`transaction` is an all-or-nothing write scope that also serializes writers so two
    appends cannot claim the same chain position.
  * :func:`migrate` is a forward-only schema ladder keyed on a per-database ``schema_meta``
    version — distinct from the evidence-envelope ``SCHEMA_VERSION``. It never downgrades,
    never destroys data, and fails closed on a version newer than this build understands.

Standard library only. Parameterized SQL only; no pickle or executable serialization.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager

_BUSY_TIMEOUT_MS = 5000


class DurableStoreError(Exception):
    """A durable store cannot be opened, validated, or mutated safely — fail closed."""


class DatabaseOwnership:
    """Exclusive single-owner advisory lock over one durable database file (Step 7A.1).

    Ownership is expressed by an ``flock`` (``LOCK_EX | LOCK_NB``) held on a sidecar
    ``<db>.lock`` file for the owning store's whole lifetime. Because ``flock`` locks are keyed
    to the *open file description*, a second acquisition — from another thread, another store
    instance in this process, or another process on a supported POSIX platform (both CI legs
    are POSIX) — fails closed while the first owner holds it, and succeeds only once that owner
    releases (on ``close`` or any construction-failure path).

    This is a single-owner contract, not coherent multi-writer support: it exists precisely to
    stop a second instance from operating on a stale in-memory mirror. The lock file is created
    if absent and **never unlinked** (removing an active lock file would invite an
    inode-replacement race); it stores no keys, credentials, tokens, or runtime data.

    Kept package-local (a small sibling of the gateway's copy) so the verifier-owned evidence
    store never imports the gateway package.
    """

    def __init__(self, db_path: str) -> None:
        self._lock_path = db_path + ".lock"
        self._fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._fd)
            self._fd = -1
            raise DurableStoreError(
                f"durable database {db_path!r} is already owned by another store or process; "
                f"refusing a second concurrent owner (fail closed)"
            ) from exc

    def release(self) -> None:
        """Release ownership; idempotent and safe on every cleanup path."""
        if self._fd >= 0:
            fd, self._fd = self._fd, -1
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def check_integrity(conn: sqlite3.Connection, domain: str) -> None:
    """Fail closed unless ``PRAGMA integrity_check`` reports exactly ``ok`` (no repair)."""
    result = [r[0] for r in conn.execute("PRAGMA integrity_check").fetchall()]
    if result != ["ok"]:
        raise DurableStoreError(
            f"{domain} database failed SQLite integrity_check: {result!r}"
        )


def connect(path: str) -> sqlite3.Connection:
    """Open a file-backed SQLite connection with verified single-node safety settings.

    Autocommit (``isolation_level=None``) so :func:`transaction` controls every write
    boundary explicitly (and DDL is transactional). ``check_same_thread=False`` because the
    owning store serializes access with its own lock. Refuses ``:memory:`` — WAL needs a real
    file, and an in-memory "durable" store would be a contradiction.
    """
    if path == ":memory:" or not path:
        raise DurableStoreError("a durable SQLite store requires a real file path")
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    if str(mode).lower() != "wal":
        conn.close()
        raise DurableStoreError(f"WAL journal mode not enabled (got {mode!r})")
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        conn.close()
        raise DurableStoreError("foreign-key enforcement not enabled")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """An all-or-nothing write scope: ``BEGIN IMMEDIATE`` then ``COMMIT``, else ``ROLLBACK``.

    ``BEGIN IMMEDIATE`` takes the write lock up front so a competing writer cannot interleave
    and claim the same chain position; any exception rolls the whole scope back, leaving no
    partial state (DDL included, since the connection is in autocommit mode).
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def migrate(
    conn: sqlite3.Connection,
    domain: str,
    target_version: int,
    migrations: list[Callable[[sqlite3.Connection], None]],
) -> None:
    """Forward-only migrate ``conn`` to ``target_version``; fail closed on anything unexpected.

    ``migrations[i]`` upgrades schema version ``i`` -> ``i+1``. Each step runs in one
    transaction, so a failed step leaves the prior committed version intact. A stored version
    newer than ``target_version`` is unsupported (never downgrade).
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_meta ("
        "key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    try:
        current = int(row[0]) if row is not None else 0
    except (ValueError, TypeError) as exc:
        raise DurableStoreError(
            f"{domain} database has a malformed schema version {row[0]!r}"
        ) from exc
    if current == target_version:
        return
    if current > target_version:
        raise DurableStoreError(
            f"{domain} database schema version {current} is newer than this build "
            f"supports ({target_version}); refusing to open"
        )
    for version in range(current, target_version):
        with transaction(conn):
            migrations[version](conn)
            conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(version + 1),),
            )
