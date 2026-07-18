"""State-backend selection for the gateway's durable stores (Step 7A).

Chooses and opens the authority (and, as a paired durable substrate, evidence) storage from
two environment variables:

  * ``PRIVATE_AI_STATE_BACKEND`` — ``memory`` (default) or ``sqlite``.
  * ``PRIVATE_AI_STATE_DIR`` — the directory holding the two fixed-name databases when the
    backend is ``sqlite``.

``memory`` reproduces today's behavior byte-for-byte: an in-memory
:class:`~private_ai_gateway.approvals.ApprovalStore` and no evidence sink. ``sqlite`` opens a
durable :class:`~private_ai_gateway.approvals_sqlite.SqliteApprovalStore` and manages the two
databases as *separate* stores under one initialization-integrity rule:

  * neither database present  -> initialize both deterministically;
  * both present              -> open and validate each independently;
  * exactly one present       -> fail closed (never silently create the missing peer).

This is an initialization-integrity check, not Step 7B reconciliation: it never infers
authority state from evidence or vice versa. The durable evidence database is initialized and
integrity-checked here but **not** wired to a live emitting sink — that needs verifier key
material, which Step 7A deliberately does not load, so the gateway's ``EVIDENCE_SINK`` stays
``None`` and no key custody is broadened.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from private_ai_gateway.approvals import ApprovalStore

STATE_BACKEND_MEMORY = "memory"
STATE_BACKEND_SQLITE = "sqlite"

AUTHORITY_DB_FILENAME = "authority.sqlite3"
EVIDENCE_DB_FILENAME = "evidence.sqlite3"

# Cosmetic sink identity for the app-managed (empty) durable evidence database. It matters
# only if the database ever holds records; Step 7A never emits into it (no keys).
_EVIDENCE_SINK_ID = "gateway-evidence"


class StateError(Exception):
    """The configured state backend cannot be opened safely — fail closed at startup."""


@dataclass(frozen=True)
class StateConfig:
    """Parsed, validated state-backend configuration."""

    backend: str
    state_dir: str | None

    @classmethod
    def from_env(cls, environ: Any) -> StateConfig:
        """Parse and validate ``PRIVATE_AI_STATE_BACKEND`` / ``PRIVATE_AI_STATE_DIR``."""
        backend = (environ.get("PRIVATE_AI_STATE_BACKEND", "") or "").strip().lower()
        backend = backend or STATE_BACKEND_MEMORY
        if backend not in (STATE_BACKEND_MEMORY, STATE_BACKEND_SQLITE):
            raise StateError(
                f"PRIVATE_AI_STATE_BACKEND must be {STATE_BACKEND_MEMORY!r} or "
                f"{STATE_BACKEND_SQLITE!r}, got {backend!r}"
            )
        state_dir = (environ.get("PRIVATE_AI_STATE_DIR", "") or "").strip() or None
        return cls(backend=backend, state_dir=state_dir)


@dataclass
class OpenedBackend:
    """The opened stores plus their on-disk locations (paths are ``None`` for memory)."""

    authority_store: Any
    evidence_sink: Any | None
    authority_path: str | None
    evidence_path: str | None


def _resolve_state_dir(state_dir: str | None) -> str:
    """Return an absolute, usable state directory or fail closed."""
    if not state_dir:
        raise StateError(
            "PRIVATE_AI_STATE_DIR must be set when PRIVATE_AI_STATE_BACKEND=sqlite"
        )
    path = os.path.abspath(os.path.expanduser(state_dir))
    if not os.path.isdir(path):
        raise StateError(f"state directory {path!r} does not exist or is not a directory")
    if not os.access(path, os.W_OK):
        raise StateError(f"state directory {path!r} is not writable")
    return path


def _check_paired_existence(authority_path: str, evidence_path: str) -> None:
    """Enforce the both-or-neither rule between the two databases; fail closed otherwise."""
    authority_exists = os.path.exists(authority_path)
    evidence_exists = os.path.exists(evidence_path)
    if authority_exists != evidence_exists:
        present, missing = (
            (AUTHORITY_DB_FILENAME, EVIDENCE_DB_FILENAME)
            if authority_exists
            else (EVIDENCE_DB_FILENAME, AUTHORITY_DB_FILENAME)
        )
        raise StateError(
            f"state directory is inconsistent: {present} exists but {missing} does not; "
            f"refusing to silently create the missing peer (fail closed)"
        )


def _init_evidence_db(evidence_path: str) -> None:
    """Initialize/validate the durable evidence database as an empty substrate, then close it.

    Opens the durable evidence store with an empty key registry: for a fresh or empty database
    this creates/validates the schema and trivially passes chain verification (no records, no
    keys needed). If the database already holds records that need verifier keys to check, that
    verification fails closed here — the gateway does not hold those keys in Step 7A.
    """
    from openclaw.sink import EmitterKeyRegistry
    from openclaw.sink_sqlite import SqliteEvidenceSink

    sink = SqliteEvidenceSink(_EVIDENCE_SINK_ID, EmitterKeyRegistry(), path=evidence_path)
    sink.close()


def open_backend(config: StateConfig) -> OpenedBackend:
    """Open the configured state backend, failing closed on any unsafe condition.

    ``memory`` yields a fresh in-memory store and no evidence sink (today's behavior). ``sqlite``
    resolves the state directory, enforces the paired-existence rule, opens the durable authority
    store, and initializes/validates the durable evidence database (kept unwired: ``evidence_sink``
    is ``None`` because Step 7A loads no verifier keys).
    """
    if config.backend == STATE_BACKEND_MEMORY:
        return OpenedBackend(
            authority_store=ApprovalStore(),
            evidence_sink=None,
            authority_path=None,
            evidence_path=None,
        )

    # sqlite
    from private_ai_gateway.approvals_sqlite import SqliteApprovalStore

    state_dir = _resolve_state_dir(config.state_dir)
    authority_path = os.path.join(state_dir, AUTHORITY_DB_FILENAME)
    evidence_path = os.path.join(state_dir, EVIDENCE_DB_FILENAME)
    _check_paired_existence(authority_path, evidence_path)
    authority_store = SqliteApprovalStore(authority_path)
    _init_evidence_db(evidence_path)
    return OpenedBackend(
        authority_store=authority_store,
        evidence_sink=None,
        authority_path=authority_path,
        evidence_path=evidence_path,
    )
