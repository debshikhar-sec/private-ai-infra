"""Unit tests for Hermes persistent memory (store.py)."""

import json

import pytest
from hermes.store import MemoryStore, NextGate, RunEntry


def test_load_state_absent_returns_empty(tmp_path):
    assert MemoryStore(tmp_path).load_state() == {}


def test_save_then_load_roundtrip_and_stamps_updated_at(tmp_path):
    store = MemoryStore(tmp_path)
    store.save_state({"current_gate": "g1"})
    loaded = store.load_state()
    assert loaded["current_gate"] == "g1"
    assert loaded["updated_at"] != "1970-01-01T00:00:00Z"  # stamped on save


def test_save_state_backs_up_prior_copy(tmp_path):
    store = MemoryStore(tmp_path)
    store.save_state({"current_gate": "first"})
    store.save_state({"current_gate": "second"})
    backups = list((tmp_path / "backups").glob("*/PROJECT_STATE.json"))
    assert len(backups) == 1
    # The backup holds the PRIOR state, not the new one.
    assert json.loads(backups[0].read_text())["current_gate"] == "first"


def test_first_save_makes_no_backup(tmp_path):
    store = MemoryStore(tmp_path)
    store.save_state({"current_gate": "first"})
    assert not (tmp_path / "backups").exists()


def test_load_corrupt_state_raises(tmp_path):
    store = MemoryStore(tmp_path)
    store.state_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        store.load_state()


def test_load_non_object_state_raises(tmp_path):
    store = MemoryStore(tmp_path)
    store.state_path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError):
        store.load_state()


def test_append_run_creates_then_appends(tmp_path):
    store = MemoryStore(tmp_path)
    store.append_run(RunEntry(goal="first cycle", results=["did a thing"], next_action="step 2"))
    store.append_run(RunEntry(goal="second cycle"))
    text = store.history_path.read_text()
    assert text.startswith("# Run History")
    assert "first cycle" in text and "second cycle" in text
    assert "did a thing" in text
    # Two dated sections.
    assert text.count("\n## ") == 2


def test_run_entry_markdown_includes_autonomy_and_approval():
    md = RunEntry(goal="g", autonomy_level="L3", approval_required="edit gateway").to_markdown()
    assert "Autonomy level: L3" in md
    assert "Approval required: edit gateway" in md


def test_set_next_gate_writes_sections(tmp_path):
    store = MemoryStore(tmp_path)
    store.set_next_gate(
        NextGate(
            current_gate="phase_x",
            allowed_next_action="run the thing",
            not_allowed=["publish"],
            approval_needed=["git push"],
        )
    )
    text = store.next_actions_path.read_text()
    assert "Current gate — phase_x" in text
    assert "run the thing" in text
    assert "publish" in text
    assert "git push" in text


def test_atomic_write_leaves_no_tmp_file(tmp_path):
    store = MemoryStore(tmp_path)
    store.save_state({"a": 1})
    assert not list(tmp_path.glob("*.tmp"))
