"""State-backend selection (Step 7A) — config parsing and paired initialization safety.

``PRIVATE_AI_STATE_BACKEND`` chooses memory (default, today's behavior) or sqlite (durable).
The sqlite path enforces the both-or-neither database rule and fails closed on a missing or
unusable state directory. It initializes the durable evidence database but never wires a live
sink (no keys are loaded in Step 7A).
"""

from __future__ import annotations

import os

import pytest

from private_ai_gateway.approvals import ApprovalStore
from private_ai_gateway.approvals_sqlite import SqliteApprovalStore
from private_ai_gateway.state import (
    AUTHORITY_DB_FILENAME,
    EVIDENCE_DB_FILENAME,
    StateConfig,
    StateError,
    open_backend,
)


def _cfg(**env):
    return StateConfig.from_env(env)


# --- config parsing -----------------------------------------------------------------
def test_default_backend_is_memory():
    cfg = _cfg()
    assert cfg.backend == "memory"
    assert cfg.state_dir is None


def test_explicit_sqlite_backend_parsed():
    cfg = _cfg(PRIVATE_AI_STATE_BACKEND="sqlite", PRIVATE_AI_STATE_DIR="/tmp/x")
    assert cfg.backend == "sqlite"
    assert cfg.state_dir == "/tmp/x"


def test_unknown_backend_fails_closed():
    with pytest.raises(StateError):
        _cfg(PRIVATE_AI_STATE_BACKEND="postgres")


# --- memory backend -----------------------------------------------------------------
def test_memory_backend_yields_in_memory_store_and_no_sink():
    opened = open_backend(_cfg())
    assert isinstance(opened.authority_store, ApprovalStore)
    assert opened.evidence_sink is None
    assert opened.authority_path is None


# --- sqlite backend -----------------------------------------------------------------
def test_sqlite_backend_initializes_both_databases(tmp_path):
    opened = open_backend(
        _cfg(PRIVATE_AI_STATE_BACKEND="sqlite", PRIVATE_AI_STATE_DIR=str(tmp_path))
    )
    assert isinstance(opened.authority_store, SqliteApprovalStore)
    assert opened.evidence_sink is None  # unwired: no keys loaded in Step 7A
    assert os.path.exists(os.path.join(tmp_path, AUTHORITY_DB_FILENAME))
    assert os.path.exists(os.path.join(tmp_path, EVIDENCE_DB_FILENAME))
    opened.authority_store.close()


def test_sqlite_backend_reopens_healthy_pair(tmp_path):
    cfg = _cfg(PRIVATE_AI_STATE_BACKEND="sqlite", PRIVATE_AI_STATE_DIR=str(tmp_path))
    o1 = open_backend(cfg)
    o1.authority_store.create_run(
        run_id="run-1", principal_id="p", canonical_plan_hash="sha256:" + "a" * 64,
        effective_autonomy=1, policy_ceiling=3,
    )
    o1.authority_store.close()
    o2 = open_backend(cfg)  # both present -> open + validate each
    assert o2.authority_store.get_run("run-1") is not None
    o2.authority_store.close()


def test_sqlite_requires_state_dir():
    with pytest.raises(StateError):
        open_backend(_cfg(PRIVATE_AI_STATE_BACKEND="sqlite"))


def test_sqlite_missing_state_dir_fails_closed(tmp_path):
    missing = str(tmp_path / "does-not-exist")
    with pytest.raises(StateError):
        open_backend(_cfg(PRIVATE_AI_STATE_BACKEND="sqlite", PRIVATE_AI_STATE_DIR=missing))


def test_exactly_one_database_present_fails_closed(tmp_path):
    # Create only the authority database, leaving evidence absent.
    SqliteApprovalStore(str(tmp_path / AUTHORITY_DB_FILENAME)).close()
    assert not os.path.exists(os.path.join(tmp_path, EVIDENCE_DB_FILENAME))
    with pytest.raises(StateError):
        open_backend(_cfg(PRIVATE_AI_STATE_BACKEND="sqlite", PRIVATE_AI_STATE_DIR=str(tmp_path)))
