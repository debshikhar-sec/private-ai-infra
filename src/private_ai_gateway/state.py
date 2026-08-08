"""State-backend selection for the gateway's durable stores (Steps 7A / 7B.0).

Chooses and opens the authority (and, as a paired durable substrate, evidence) storage from
three environment variables:

  * ``PRIVATE_AI_STATE_BACKEND`` — ``memory`` (default) or ``sqlite``.
  * ``PRIVATE_AI_STATE_DIR`` — the directory holding the two fixed-name databases when the
    backend is ``sqlite``.
  * ``PRIVATE_AI_EVIDENCE_MODE`` — ``off`` (default) or ``durable`` (Step 7B.0). ``durable``
    requires the ``sqlite`` backend and per-emitter HMAC keys in the environment (see
    :mod:`openclaw.assurance`); it opens the durable evidence store as a *live* sink whose
    ownership is held for the runtime lifetime.

``memory`` reproduces the pre-7A behavior byte-for-byte: an in-memory
:class:`~private_ai_gateway.approvals.ApprovalStore` and no evidence sink. ``sqlite`` opens a
durable :class:`~private_ai_gateway.approvals_sqlite.SqliteApprovalStore` and manages the two
databases as *separate* stores under one initialization-integrity rule:

  * neither database present  -> initialize both deterministically;
  * both present              -> open and validate each independently;
  * exactly one present       -> fail closed (never silently create the missing peer).

This is an initialization-integrity check, not Step 7B.2 reconciliation: it never infers
authority state from evidence or vice versa. With ``PRIVATE_AI_EVIDENCE_MODE=off`` the
durable evidence database is initialized/validated as an **empty substrate** only and the
gateway's ``EVIDENCE_SINK`` stays ``None`` (no key custody is broadened); a database that
already holds records then fails closed with an explicit remediation message, because
records cannot be verified without the configured registry. With ``durable``, construction
of the sink and its verification registry is **assurance-owned**
(:func:`openclaw.assurance.open_durable_sink`) — the gateway receives a handle, never the
registry.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from private_ai_gateway.approvals import ApprovalStore

STATE_BACKEND_MEMORY = "memory"
STATE_BACKEND_SQLITE = "sqlite"

EVIDENCE_MODE_OFF = "off"
EVIDENCE_MODE_DURABLE = "durable"

AUTHORITY_DB_FILENAME = "authority.sqlite3"
EVIDENCE_DB_FILENAME = "evidence.sqlite3"

# Sink identity for the durable evidence database. Must stay equal to
# ``openclaw.assurance.DURABLE_SINK_ID`` so records written in durable mode reopen under
# the same identity in every mode; in ``off`` mode the database stays empty.
_EVIDENCE_SINK_ID = "gateway-evidence"


class StateError(Exception):
    """The configured state backend cannot be opened safely — fail closed at startup."""


@dataclass(frozen=True)
class StateConfig:
    """Parsed, validated state-backend configuration."""

    backend: str
    state_dir: str | None
    evidence_mode: str = EVIDENCE_MODE_OFF

    @classmethod
    def from_env(cls, environ: Any) -> StateConfig:
        """Parse and validate the state/evidence configuration; fail closed on any mismatch."""
        backend = (environ.get("PRIVATE_AI_STATE_BACKEND", "") or "").strip().lower()
        backend = backend or STATE_BACKEND_MEMORY
        if backend not in (STATE_BACKEND_MEMORY, STATE_BACKEND_SQLITE):
            raise StateError(
                f"PRIVATE_AI_STATE_BACKEND must be {STATE_BACKEND_MEMORY!r} or "
                f"{STATE_BACKEND_SQLITE!r}, got {backend!r}"
            )
        state_dir = (environ.get("PRIVATE_AI_STATE_DIR", "") or "").strip() or None
        evidence_mode = (environ.get("PRIVATE_AI_EVIDENCE_MODE", "") or "").strip().lower()
        evidence_mode = evidence_mode or EVIDENCE_MODE_OFF
        if evidence_mode not in (EVIDENCE_MODE_OFF, EVIDENCE_MODE_DURABLE):
            raise StateError(
                f"PRIVATE_AI_EVIDENCE_MODE must be {EVIDENCE_MODE_OFF!r} or "
                f"{EVIDENCE_MODE_DURABLE!r}, got {evidence_mode!r}"
            )
        if evidence_mode == EVIDENCE_MODE_DURABLE and backend != STATE_BACKEND_SQLITE:
            # Durable evidence with a restart-forgetting authority store would be a
            # misleading half-configuration — refuse it outright.
            raise StateError(
                "PRIVATE_AI_EVIDENCE_MODE=durable requires PRIVATE_AI_STATE_BACKEND=sqlite"
            )
        return cls(backend=backend, state_dir=state_dir, evidence_mode=evidence_mode)


@dataclass
class OpenedBackend:
    """The opened stores plus their on-disk locations (paths are ``None`` for memory)."""

    authority_store: Any
    evidence_sink: Any | None
    authority_path: str | None
    evidence_path: str | None

    def close(self) -> None:
        """Release both stores (connections and ownership locks); safe to call once at shutdown.

        The evidence sink closes first, then the authority store — the reverse of open
        order. Stores without a ``close`` (the in-memory backend) are skipped.
        """
        try:
            if self.evidence_sink is not None and hasattr(self.evidence_sink, "close"):
                self.evidence_sink.close()
        finally:
            if hasattr(self.authority_store, "close"):
                self.authority_store.close()


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
    keys needed). A database that already holds records cannot be verified without the
    configured registry, so it fails closed here with an explicit remediation message — the
    ``off`` evidence mode never silently ignores unverifiable evidence.
    """
    from openclaw.sink import EmitterKeyRegistry, EvidenceError
    from openclaw.sink_sqlite import SqliteEvidenceSink

    try:
        sink = SqliteEvidenceSink(
            _EVIDENCE_SINK_ID, EmitterKeyRegistry(), path=evidence_path
        )
    except EvidenceError as exc:
        raise StateError(
            f"evidence database {evidence_path!r} holds records that cannot be verified "
            f"without keys; set PRIVATE_AI_EVIDENCE_MODE=durable with the configured "
            f"emitter keys to open it (fail closed): {exc}"
        ) from exc
    sink.close()


def _open_durable_evidence(environ: Any, evidence_path: str):
    """Open the live durable evidence sink via assurance-owned construction (Step 7B.0).

    Construction of the sink and its verification registry belongs to the assurance plane
    (:mod:`openclaw.assurance`); this function only resolves the environment and translates
    a configuration failure into a :class:`StateError`. Error messages never carry key
    material — the assurance loader names variables, not values.
    """
    from openclaw.assurance import AssuranceConfigError, open_durable_sink

    try:
        return open_durable_sink(environ, evidence_path)
    except AssuranceConfigError as exc:
        raise StateError(f"durable evidence configuration is invalid: {exc}") from exc


def open_backend(config: StateConfig, environ: Any | None = None) -> OpenedBackend:
    """Open the configured state backend, failing closed on any unsafe condition.

    ``memory`` yields a fresh in-memory store and no evidence sink (the pre-7A behavior).
    ``sqlite`` resolves the state directory, enforces the paired-existence rule, opens the
    durable authority store, then handles evidence per ``evidence_mode``:

      * ``off`` — initialize/validate the evidence database as an empty substrate and close
        it (``evidence_sink`` stays ``None``; no keys are loaded);
      * ``durable`` — assurance-owned construction opens a **live** durable sink whose
        ownership lock is held for the runtime lifetime (Step 7B.0). ``environ`` (default
        ``os.environ``) supplies the per-emitter key material to the assurance loader; keys
        are never stored on this config or the returned backend.
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

    environ = os.environ if environ is None else environ
    state_dir = _resolve_state_dir(config.state_dir)
    authority_path = os.path.join(state_dir, AUTHORITY_DB_FILENAME)
    evidence_path = os.path.join(state_dir, EVIDENCE_DB_FILENAME)
    _check_paired_existence(authority_path, evidence_path)
    authority_store = SqliteApprovalStore(authority_path)
    # If the evidence database fails to open/initialize, close the already-open authority
    # store (releasing its connection and ownership lock) before propagating — no partial
    # backend is left holding resources, and a subsequent clean open can succeed.
    evidence_sink = None
    try:
        if config.evidence_mode == EVIDENCE_MODE_DURABLE:
            evidence_sink = _open_durable_evidence(environ, evidence_path)
        else:
            _init_evidence_db(evidence_path)
    except BaseException:
        authority_store.close()
        raise
    return OpenedBackend(
        authority_store=authority_store,
        evidence_sink=evidence_sink,
        authority_path=authority_path,
        evidence_path=evidence_path,
    )
