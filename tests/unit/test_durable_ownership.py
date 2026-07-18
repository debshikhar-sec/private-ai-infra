"""Exclusive single-owner model for the durable stores (Step 7A.1).

Each durable database has its own advisory ownership lock. A second live owner — another store
instance in this process, or a separate process — fails closed; ownership is released on normal
close and on every construction-failure path, so a clean owner can open afterward. The authority
and evidence databases lock independently, so both can be owned at once from one state directory.
No sleeps: ownership is enforced synchronously at construction.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from openclaw.sink import EmitterKeyRegistry
from openclaw.sink_sqlite import SqliteEvidenceSink
from openclaw.sqlite_util import DatabaseOwnership as EvidenceOwnership
from openclaw.sqlite_util import DurableStoreError as EvidenceDurableError

from private_ai_gateway.approvals_sqlite import SqliteApprovalStore
from private_ai_gateway.sqlite_util import DatabaseOwnership, DurableStoreError

_REPO = Path(__file__).resolve().parents[2]
_ENVPATH = f"{_REPO / 'src'}:{_REPO / 'agents'}"
# Matches the sink_id baked into tests.unit.test_durable_evidence._signed envelopes.
_SINK_ID = "sink-durable-1"
_KEY = b"0123456789abcdef0123456789abcdef"
_KEY_ID = "opencode-hmac-1"


def _registry():
    from openclaw import sink as sinkmod

    reg = EmitterKeyRegistry()
    reg.register(sinkmod.EMITTER_OPENCODE, _KEY_ID, _KEY)
    return reg


# --- second-instance-in-process fails closed -----------------------------------------
def test_second_authority_instance_fails_while_first_open(tmp_path):
    path = str(tmp_path / "authority.sqlite3")
    first = SqliteApprovalStore(path)
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)
    first.close()


def test_authority_reopens_after_first_closes(tmp_path):
    path = str(tmp_path / "authority.sqlite3")
    SqliteApprovalStore(path).close()
    second = SqliteApprovalStore(path)  # no raise once the first owner released
    second.close()


def test_second_evidence_instance_fails_while_first_open(tmp_path):
    path = str(tmp_path / "evidence.sqlite3")
    first = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    with pytest.raises(EvidenceDurableError):
        SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    first.close()


def test_evidence_reopens_after_first_closes(tmp_path):
    path = str(tmp_path / "evidence.sqlite3")
    SqliteEvidenceSink(_SINK_ID, _registry(), path=path).close()
    second = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    second.close()


# --- authority and evidence own independently ----------------------------------------
def test_authority_and_evidence_owned_simultaneously(tmp_path):
    auth = SqliteApprovalStore(str(tmp_path / "authority.sqlite3"))
    ev = SqliteEvidenceSink(_SINK_ID, _registry(), path=str(tmp_path / "evidence.sqlite3"))
    # Both live at once from one state dir — separate lock files, no cross-blocking.
    auth.create_run(
        run_id="r1", principal_id="p", canonical_plan_hash="sha256:" + "a" * 64,
        effective_autonomy=1, policy_ceiling=3,
    )
    assert auth.get_run("r1") is not None
    assert len(ev) == 0
    auth.close()
    ev.close()


# --- ownership released after construction failure -----------------------------------
def test_authority_ownership_released_after_constructor_failure(tmp_path):
    import sqlite3

    path = str(tmp_path / "authority.sqlite3")
    s = SqliteApprovalStore(path)
    s.create_run(
        run_id="r1", principal_id="p", canonical_plan_hash="sha256:" + "a" * 64,
        effective_autonomy=1, policy_ceiling=3,
    )
    s.close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE runs SET status='bogus' WHERE run_id='r1'")
    raw.commit()
    raw.close()
    with pytest.raises(DurableStoreError):
        SqliteApprovalStore(path)
    # The failed constructor must have released ownership: a fresh acquisition succeeds.
    own = DatabaseOwnership(path)
    own.release()


def test_evidence_ownership_released_after_constructor_failure(tmp_path):
    from openclaw.sink import EvidenceError
    from tests.unit.test_durable_evidence import _signed

    path = str(tmp_path / "evidence.sqlite3")
    s = SqliteEvidenceSink(_SINK_ID, _registry(), path=path)
    s.append(*_signed(nonce="n"))
    s.close()
    # An empty registry cannot verify the stored signature -> construction fails after the
    # ownership lock was taken; the lock must be released on that path.
    with pytest.raises(EvidenceError):
        SqliteEvidenceSink(_SINK_ID, EmitterKeyRegistry(), path=path)
    own = EvidenceOwnership(path)
    own.release()


# --- cross-process ownership ---------------------------------------------------------
_CHILD = (
    "import sys\n"
    "from private_ai_gateway.approvals_sqlite import SqliteApprovalStore\n"
    "from private_ai_gateway.sqlite_util import DurableStoreError\n"
    "try:\n"
    "    s = SqliteApprovalStore(sys.argv[1]); s.close(); sys.exit(0)\n"
    "except DurableStoreError:\n"
    "    sys.exit(3)\n"
)


def _child_open(path: str) -> int:
    return subprocess.run(
        [sys.executable, "-c", _CHILD, path],
        env={"PYTHONPATH": _ENVPATH, "PATH": ""},
        capture_output=True,
    ).returncode


def test_separate_process_cannot_acquire_owned_database(tmp_path):
    path = str(tmp_path / "authority.sqlite3")
    owner = SqliteApprovalStore(path)
    try:
        assert _child_open(path) == 3  # ownership denied in the child process
    finally:
        owner.close()
    assert _child_open(path) == 0  # succeeds once the owner has closed
