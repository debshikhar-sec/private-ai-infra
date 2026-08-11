"""Track C — the shadow-engineering harness.

The harness exists to answer "could the local model have written this?" — never "may it be
applied?". These tests are mostly about what it *cannot* do, because that is the whole
claim: zero additional operational authority.

Every model response is a literal string supplied by a stub. **CI never downloads, loads,
or executes an MLX model**, and there is no network dependency anywhere in this file.
"""

from __future__ import annotations

import json

import pytest
from hermes import shadow_engineering as se
from opencode_sandbox import candidate as cand

_OBJ = "Bump the value in src/thing.py from 1 to 2"


@pytest.fixture
def repo(tmp_path):
    """The tree under evaluation. Deliberately *outside* the trace dir, so the
    "mutates nothing" assertion cannot be satisfied by writing traces elsewhere."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "thing.py").write_text("value = 1\n", encoding="utf-8")
    (root / "README.md").write_text("# demo\n", encoding="utf-8")
    return root


def _stub(text, model="mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit"):
    """A deterministic stand-in for a governed model call. No model is ever loaded."""
    def call(messages):
        assert isinstance(messages, list) and messages, "messages must be a real prompt"
        return text, model
    return call


_GOOD = json.dumps({
    "edits": [{"path": "src/thing.py", "kind": "modify", "new_content": "value = 2\n"}],
    "rationale": "bump the value",
})


def _engineer(tmp_path, engineering_text=_GOOD, **over):
    kwargs = dict(
        strategy_call=_stub("Edit src/thing.py.", "mlx-community/Qwen3.6-27B-OptiQ-4bit"),
        engineering_call=_stub(engineering_text),
        strategy_identity=se.ModelIdentity(
            alias="strategy", principal="shadow-engineer", declared_autonomy="L1"),
        engineering_identity=se.ModelIdentity(
            alias="engineering", principal="shadow-engineer", declared_autonomy="L1"),
        trace_dir=tmp_path / "traces",
    )
    kwargs.update(over)
    return se.ShadowEngineer(**kwargs)


# --- the flow --------------------------------------------------------------------------

def test_a_valid_candidate_produces_a_usable_evaluation(tmp_path, repo):
    engineer = _engineer(tmp_path)
    trace = engineer.run(_OBJ, root=repo, allowed_paths=["src/thing.py"],
                         reference_files=["src/thing.py"], policy_hash="sha256:deadbeef",
                         source_commit="abc1234")
    assert trace.candidate_parse_status == "ok"
    assert trace.deterministic_validation_result == "clean"
    assert trace.teacher_verdict == se.V_MATCHES_REFERENCE
    assert trace.candidate_declared_files == ["src/thing.py"]
    assert trace.applied is False


def test_a_refused_candidate_is_a_normal_recorded_outcome(tmp_path, repo):
    engineer = _engineer(tmp_path, engineering_text="Sure! " + _GOOD)
    trace = engineer.run(_OBJ, root=repo, reference_files=["src/thing.py"])
    assert trace.candidate_parse_status == "refused"
    assert trace.candidate_reason_code == cand.R_NOT_JSON
    assert trace.teacher_verdict == se.V_REFUSED
    assert cand.R_NOT_JSON in trace.teacher_reason_codes


def test_scope_overreach_is_reported_not_silently_accepted(tmp_path, repo):
    wide = json.dumps({"edits": [
        {"path": "src/thing.py", "kind": "modify", "new_content": "value = 2\n"},
        {"path": "README.md", "kind": "modify", "new_content": "# rewritten\n"},
    ], "rationale": "also touched the readme"})
    trace = _engineer(tmp_path, engineering_text=wide).run(
        _OBJ, root=repo, reference_files=["src/thing.py"])
    assert trace.teacher_verdict == se.V_DIFFERS_FROM_REFERENCE
    assert "scope_exceeds_reference" in trace.teacher_reason_codes


def test_without_a_reference_the_teacher_says_so_rather_than_guessing(tmp_path, repo):
    trace = _engineer(tmp_path).run(_OBJ, root=repo)
    assert trace.teacher_verdict == se.V_NO_REFERENCE
    assert "no_reference" in trace.teacher_reason_codes


def test_repeated_generation_yields_a_stable_verdict(tmp_path, repo):
    engineer = _engineer(tmp_path)
    traces = [engineer.run(_OBJ, root=repo, reference_files=["src/thing.py"],
                           write_trace=False) for _ in range(4)]
    assert {t.teacher_verdict for t in traces} == {se.V_MATCHES_REFERENCE}
    assert len({t.trace_id for t in traces}) == 4       # ids are still unique


# --- the authority proof: the local model cannot mutate anything -----------------------

def test_the_harness_refuses_to_hold_an_owner_token(tmp_path):
    with pytest.raises(se.ShadowEngineeringError) as exc:
        _engineer(tmp_path, owner_token="test-owner-break-glass-token")
    assert "owner token" in str(exc.value)


def test_the_module_imports_no_execution_path():
    """Structural: the harness's *code* must not reference an apply/execute entry point.

    The module docstring names these paths in order to say it never uses them, so the scan
    runs over the source with that docstring removed — otherwise the prose describing the
    guarantee would be mistaken for a violation of it.
    """
    import inspect

    src = inspect.getsource(se).replace(se.__doc__ or "", "", 1)
    for forbidden in (
        "apply_proposal", "CodeActWorker", "GovernedSession", "session.execute",
        "v1/approvals", "decide_approval", "mark_used", "subprocess", "os.system",
    ):
        assert forbidden not in src, f"shadow harness must not reference {forbidden!r}"


def test_a_full_shadow_run_leaves_the_tree_byte_identical(tmp_path, repo):
    """Behavioural: generation + validation + evaluation mutate nothing under root."""
    before = sorted(
        (str(p.relative_to(repo)), p.read_bytes()) for p in repo.rglob("*") if p.is_file()
    )
    _engineer(tmp_path).run(_OBJ, root=repo, allowed_paths=["src/thing.py"],
                            reference_files=["src/thing.py"])
    after = sorted(
        (str(p.relative_to(repo)), p.read_bytes()) for p in repo.rglob("*") if p.is_file()
    )
    assert after == before


def test_the_harness_never_acquires_an_approval(tmp_path, repo, monkeypatch):
    """No approval is created or decided anywhere in a shadow run."""
    from private_ai_gateway import approvals

    touched: list[str] = []
    for name in ("create_pending_approval", "decide_approval", "mark_used"):
        monkeypatch.setattr(
            approvals.ApprovalStore, name,
            lambda *a, _n=name, **k: touched.append(_n), raising=True,
        )
    _engineer(tmp_path).run(_OBJ, root=repo, reference_files=["src/thing.py"])
    assert touched == []


def test_the_shadow_principal_is_capped_and_holds_no_skills_or_tools():
    """Policy proof: even if it tried, the principal cannot route or execute work."""
    from private_ai_gateway import app as gw
    from private_ai_gateway.demo import install_demo_plane

    install_demo_plane(gw)
    principal = gw.POLICY.find_principal("shadow-engineer")
    assert principal is not None, "the shadow principal must exist in the demo policy"
    assert gw.autonomy_ceiling_for(principal) <= 1        # L1: suggest-only
    assert sorted(principal.allowed_models) == ["engineering", "strategy"]
    assert not principal.allowed_skills                   # cannot route work
    assert not principal.allowed_tools                    # cannot call a tool


# --- the evaluation trace --------------------------------------------------------------

def test_the_trace_records_model_identity_so_a_build_swap_is_visible(tmp_path, repo):
    trace = _engineer(tmp_path).run(_OBJ, root=repo, policy_hash="sha256:abc",
                                    source_commit="c0ffee")
    assert trace.engineering_model.alias == "engineering"
    assert trace.engineering_model.resolved_model.endswith("Qwen3-Coder-30B-A3B-Instruct-8bit")
    assert trace.engineering_model.principal == "shadow-engineer"
    assert trace.engineering_model.declared_autonomy == "L1"
    assert trace.strategy_model.resolved_model.endswith("Qwen3.6-27B-OptiQ-4bit")
    assert trace.policy_hash == "sha256:abc" and trace.source_commit == "c0ffee"


def test_a_route_change_is_visible_in_the_trace(tmp_path, repo):
    """The same alias served by a different build produces a different recorded identity."""
    swapped = _engineer(tmp_path, engineering_call=_stub(_GOOD, "some-other-model-build"))
    trace = swapped.run(_OBJ, root=repo)
    assert trace.engineering_model.alias == "engineering"
    assert trace.engineering_model.resolved_model == "some-other-model-build"


def test_the_trace_stores_no_raw_model_text_or_secret_material(tmp_path, repo):
    leaky = json.dumps({
        "edits": [{"path": "src/thing.py", "kind": "modify",
                   "new_content": "TOKEN = 'AKIAIOSFODNN7EXAMPLE'\n"}],
        "rationale": "embeds a credential-shaped string",
    })
    trace = _engineer(tmp_path, engineering_text=leaky).run(
        _OBJ, root=repo, allowed_paths=["src/thing.py"])
    rendered = trace.to_json()
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered   # file contents are never stored
    assert "demo-shadow-engineer" not in rendered   # nor is any bearer token
    assert trace.candidate_declared_files == ["src/thing.py"]   # identifiers only


def test_the_trace_is_written_to_the_runtime_path_and_is_not_evidence(tmp_path, repo):
    engineer = _engineer(tmp_path)
    trace = engineer.run(_OBJ, root=repo)
    written = list((tmp_path / "traces").glob("*.json"))
    assert len(written) == 1
    on_disk = json.loads(written[0].read_text(encoding="utf-8"))
    assert on_disk["trace_id"] == trace.trace_id
    # It is plain local JSON — no signing envelope, no evidence identity, no chain fields.
    for evidence_field in ("envelope", "evidence_id", "emitter_sig", "record_hash", "seq"):
        assert evidence_field not in on_disk


def test_the_trace_is_never_written_to_the_evidence_sink(tmp_path, repo, monkeypatch):
    from openclaw.sink import EvidenceSink

    appended: list = []
    monkeypatch.setattr(EvidenceSink, "append",
                        lambda *a, **k: appended.append(a), raising=True)
    _engineer(tmp_path).run(_OBJ, root=repo)
    assert appended == [], "an evaluation trace is not governance evidence"


def test_the_engineering_prompt_carries_the_current_file_contents(tmp_path, repo):
    """Without this the model rewrites a file it never saw, silently dropping what was there.

    The first real local trial did exactly that: structurally perfect, scope exact, and yet
    it removed two public parameters and the module docstring.
    """
    seen: list[list[dict]] = []

    def capture(messages):
        seen.append(messages)
        return _GOOD, "stub-model"

    _engineer(tmp_path, engineering_call=capture).run(
        _OBJ, root=repo, allowed_paths=["src/thing.py"])
    prompt = "\n".join(m["content"] for m in seen[0])
    assert "value = 1" in prompt, "the model was not shown the current file"
    assert "src/thing.py (current contents)" in prompt
    assert "must survive unless the objective says otherwise" in prompt


def test_reading_scope_is_bounded_and_never_fails_on_a_missing_file(repo):
    assert se.read_scope(repo, ["src/thing.py"]) == {"src/thing.py": "value = 1\n"}
    assert se.read_scope(repo, ["does/not/exist.py"]) == {}
    assert se.read_scope(repo, ["src/thing.py"], max_bytes=1) == {}   # over the bound
    assert se.read_scope(repo, None) == {}


def test_the_objective_is_hashed_not_stored_verbatim(tmp_path, repo):
    trace = _engineer(tmp_path).run("something quite sensitive and specific", root=repo)
    assert trace.objective_hash.startswith("sha256:")
    assert "something quite sensitive" not in trace.to_json()


# --- CLI -------------------------------------------------------------------------------

def test_the_cli_refuses_to_run_without_a_shadow_token(monkeypatch, capsys):
    monkeypatch.delenv("PRIVATE_AI_SHADOW_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        se.main([_OBJ])
    assert "PRIVATE_AI_SHADOW_TOKEN" in capsys.readouterr().err
