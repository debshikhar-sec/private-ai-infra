"""Unit tests for the Hermes runner (run.py) with an injected fake client."""

from hermes import run as hermes_run
from hermes.store import MemoryStore

SAMPLE_REPLY = """\
PHASE: Phase 4 — sandbox refresh
CURRENT READ: state looks good
SAFE NEXT ACTION: refresh the copied sandbox
AUTONOMY LEVEL: L2
DO NOT DO YET: do not enable OpenClaw
COMMANDS OR SCRIPT: bash run_review.sh
VALIDATION: ISOLATION_RESULT=PASS
EXPECTED RESULT: clean report
IF IT FAILS: inspect manifests
APPROVAL REQUIRED: none
NEXT OWNER ACTION: review report
"""


class _FakeClient:
    def __init__(self, *a, **k):
        self.calls = []

    def complete(self, messages, *, max_tokens=None):
        self.calls.append(messages)
        return SAMPLE_REPLY


def test_show_prompt_is_offline(tmp_path, monkeypatch, capsys):
    # No token set, but --show-prompt must never call the gateway.
    monkeypatch.delenv("PRIVATE_AI_HERMES_TOKEN", raising=False)
    monkeypatch.delenv("PRIVATE_AI_AUTH_TOKEN", raising=False)
    rc = hermes_run.main(
        ["--objective", "plan it", "--memory-dir", str(tmp_path), "--show-prompt"]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "SYSTEM" in out and "USER" in out and "plan it" in out


def test_missing_token_errors(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVATE_AI_HERMES_TOKEN", raising=False)
    monkeypatch.delenv("PRIVATE_AI_AUTH_TOKEN", raising=False)
    rc = hermes_run.main(["--objective", "x", "--memory-dir", str(tmp_path)])
    assert rc == 2


def test_full_cycle_records_memory(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVATE_AI_HERMES_TOKEN", "hermes-key")
    rc = hermes_run.main(
        ["--objective", "plan the next step", "--memory-dir", str(tmp_path)],
        client_factory=_FakeClient,
    )
    assert rc == 0
    store = MemoryStore(tmp_path)

    # State persisted.
    state = store.load_state()
    assert state["last_objective"] == "plan the next step"
    assert state["last_autonomy_level"] == "L2"

    # Run history appended.
    history = store.history_path.read_text()
    assert "plan the next step" in history

    # Next gate written from the plan.
    nxt = store.next_actions_path.read_text()
    assert "refresh the copied sandbox" in nxt
    assert "do not enable OpenClaw" in nxt


def test_cycle_surfaces_approval_required(tmp_path, monkeypatch, capsys):
    gated = SAMPLE_REPLY.replace(
        "APPROVAL REQUIRED: none", "APPROVAL REQUIRED: edit gateway/app.py"
    )

    class _GatedClient(_FakeClient):
        def complete(self, messages, *, max_tokens=None):
            return gated

    monkeypatch.setenv("PRIVATE_AI_HERMES_TOKEN", "hermes-key")
    hermes_run.main(
        ["--objective", "x", "--memory-dir", str(tmp_path)],
        client_factory=_GatedClient,
    )
    err = capsys.readouterr().err
    assert "APPROVAL REQUIRED" in err

    nxt = MemoryStore(tmp_path).next_actions_path.read_text()
    assert "edit gateway/app.py" in nxt
