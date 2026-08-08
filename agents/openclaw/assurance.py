"""Assurance-owned durable evidence construction (Step 7B.0).

The verifier — not the gateway — owns the construction of the durable evidence store and
the verification-key registry it needs. The gateway (and any other emitter) receives only
a handle to the constructed :class:`~openclaw.sink_sqlite.SqliteEvidenceSink` plus its *own*
emitter signing material; the complete registry is assembled here, by assurance-plane code.
In today's single-process runtime this is a custody-direction boundary, not process
isolation — but it is exactly the shape a later process split preserves.

Key custody (symmetric-HMAC MVP — tamper-evident, not non-repudiable):

  * each emitter's signing key comes from its own environment variable
    (``PRIVATE_AI_EVIDENCE_KEY_GATEWAY`` / ``PRIVATE_AI_EVIDENCE_KEY_OPENCODE``),
    hex-encoded, at least :data:`MIN_KEY_BYTES` bytes;
  * :func:`emitter_signing_key` hands one emitter its own key and key id — nothing else;
  * :func:`load_registry` assembles the full verification registry (with symmetric HMAC the
    verification key *is* the signing key) — only assurance construction calls this;
  * keys are never persisted to SQLite, never logged, and never placed in evidence payloads —
    error messages name the variable, never its value.

Fail closed: a missing, non-hex, or too-short key raises :class:`AssuranceConfigError`
before any store is opened. Standard library only.
"""

from __future__ import annotations

from typing import Any

from openclaw.sink import EMITTER_GATEWAY, EMITTER_OPENCODE, EmitterKeyRegistry
from openclaw.sink_sqlite import SqliteEvidenceSink

# The durable runtime chain's sink identity. Matches the identity the gateway's state
# layer has used for the (previously empty) durable evidence database since Step 7A.
DURABLE_SINK_ID = "gateway-evidence"

# One environment variable per emitter: each emitter reads only its own.
EMITTER_KEY_ENV = {
    EMITTER_GATEWAY: "PRIVATE_AI_EVIDENCE_KEY_GATEWAY",
    EMITTER_OPENCODE: "PRIVATE_AI_EVIDENCE_KEY_OPENCODE",
}

# Stable key identities for the HMAC MVP (rotation is a later, production step).
EMITTER_KEY_IDS = {
    EMITTER_GATEWAY: "gateway-hmac-1",
    EMITTER_OPENCODE: "opencode-hmac-1",
}

# Minimum decoded key length. 16 bytes (32 hex chars) is the floor; 32 bytes recommended.
MIN_KEY_BYTES = 16


class AssuranceConfigError(Exception):
    """The durable-evidence configuration is missing or invalid — fail closed.

    Messages name the offending environment variable but never echo its value.
    """


def _decode_key(env_name: str, raw: str | None) -> bytes:
    """Decode one hex-encoded key from its environment value; fail closed, leak nothing."""
    if raw is None or not raw.strip():
        raise AssuranceConfigError(
            f"{env_name} is required for durable evidence: set it to a hex-encoded "
            f"HMAC key of at least {MIN_KEY_BYTES} bytes"
        )
    try:
        key = bytes.fromhex(raw.strip())
    except ValueError as exc:
        raise AssuranceConfigError(
            f"{env_name} is not valid hex-encoded key material"
        ) from exc
    if len(key) < MIN_KEY_BYTES:
        raise AssuranceConfigError(
            f"{env_name} decodes to fewer than {MIN_KEY_BYTES} bytes; refusing a weak key"
        )
    return key


def emitter_signing_key(environ: Any, emitter: str) -> tuple[bytes, str]:
    """One emitter's own signing key and key id — the only material that emitter receives.

    ``environ`` is any mapping (``os.environ`` or a test dict). Unknown emitters fail
    closed rather than defaulting.
    """
    env_name = EMITTER_KEY_ENV.get(emitter)
    if env_name is None:
        raise AssuranceConfigError(f"unknown evidence emitter {emitter!r}")
    return _decode_key(env_name, environ.get(env_name)), EMITTER_KEY_IDS[emitter]


def load_registry(environ: Any) -> EmitterKeyRegistry:
    """Assemble the full verification registry — assurance-owned construction only.

    Every known emitter's key must be present and valid: a partial registry could not
    verify the whole chain on a later reopen, so a missing key fails closed here rather
    than surfacing as an unverifiable record after a restart.
    """
    registry = EmitterKeyRegistry()
    for emitter in EMITTER_KEY_ENV:
        key, key_id = emitter_signing_key(environ, emitter)
        registry.register(emitter, key_id, key)
    return registry


def open_durable_sink(environ: Any, path: str) -> SqliteEvidenceSink:
    """Construct the durable evidence store under assurance-owned key custody.

    Builds the verification registry from the environment, then opens (or creates) the
    durable database at ``path`` — which takes exclusive ownership, runs the startup
    integrity checks, and re-verifies any existing chain against the registry. A populated
    database therefore reopens and verifies correctly across restarts, and any corruption,
    unverifiable record, or configuration error fails closed before the store is usable.
    The caller holds the returned sink (and its ownership lock) for the runtime lifetime
    and must ``close()`` it on shutdown.
    """
    registry = load_registry(environ)
    return SqliteEvidenceSink(DURABLE_SINK_ID, registry, path=path)
