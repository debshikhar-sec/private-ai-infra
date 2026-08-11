"""Track D — the strict candidate-proposal adapter.

A local model's response is data, and this is the deterministic boundary that decides
whether that data is even a candidate. These tests hold it to the rule that every tolerance
is an attack surface: prose around JSON is refused rather than salvaged, unknown fields are
refused rather than ignored, and scope is enforced against what the objective declared.

Fully offline and deterministic: every "model response" is a literal string. No model is
downloaded, loaded, or executed.
"""

from __future__ import annotations

import json

import pytest
from opencode_sandbox import apply as act
from opencode_sandbox import candidate as cand


@pytest.fixture
def repo(tmp_path):
    """A tiny tree the candidate is validated against. Never written by the adapter."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "thing.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# demo\n", encoding="utf-8")
    return tmp_path


def _candidate(**over):
    body = {
        "edits": [{"path": "src/thing.py", "kind": "modify", "new_content": "value = 2\n"}],
        "rationale": "bump the value",
    }
    body.update(over)
    return json.dumps(body)


# --- the accepting case ----------------------------------------------------------------

def test_a_well_formed_candidate_parses_into_the_existing_proposal_schema(repo):
    result = cand.parse_candidate(_candidate(), root=repo)
    assert result.ok and result.reason_code == ""
    assert isinstance(result.proposal, act.ChangeProposal)
    assert result.declared_files == ("src/thing.py",)
    # It reuses the sandbox's own schema rather than inventing a second patch format.
    assert result.proposal.edits[0].kind == act.KIND_MODIFY
    assert result.proposal.source == "local-engineering-candidate"


def test_a_valid_candidate_is_still_only_a_candidate(repo):
    """Parsing grants nothing: no approval, and the tree is untouched."""
    before = {p.name: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    result = cand.parse_candidate(_candidate(), root=repo)
    assert result.ok
    after = {p.name: p.read_bytes() for p in repo.rglob("*") if p.is_file()}
    assert after == before
    # The proposal carries no approval field of any kind.
    assert not hasattr(result.proposal, "approval")


# --- refusals -------------------------------------------------------------------------

def test_malformed_json_is_refused(repo):
    result = cand.parse_candidate("{not json at all", root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_NOT_JSON)


def test_prose_around_json_is_refused_not_salvaged(repo):
    """Extracting a JSON island out of model prose is how unintended objects get applied."""
    noisy = "Sure! Here is the change you asked for:\n\n" + _candidate() + "\n\nHope that helps!"
    result = cand.parse_candidate(noisy, root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_NOT_JSON)


def test_a_python_triple_quoted_string_is_refused(repo):
    """An observed real failure mode: the local model emitted Python string syntax.

    Seen in the first live trial — the *content* was correct, but ``new_content`` was a
    Python triple-quoted literal rather than an escaped JSON string. Refused, never
    salvaged: a parser willing to guess at almost-JSON is a parser that will eventually
    guess wrong about what a change contains.
    """
    almost = (
        '{"edits": [{"path": "src/thing.py", "kind": "modify", "new_content": """"""value = 2\n"""}], '
        '"rationale": "bump"}'
    )
    result = cand.parse_candidate(almost, root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_NOT_JSON)


def test_a_json_array_is_refused(repo):
    result = cand.parse_candidate('[{"path": "x"}]', root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_NOT_OBJECT)


def test_an_arbitrary_executable_field_is_refused(repo):
    """The model produces data; it never gets to name an operation."""
    for field_name in ("command", "run", "exec", "shell", "script"):
        body = json.loads(_candidate())
        body[field_name] = "rm -rf /"
        result = cand.parse_candidate(json.dumps(body), root=repo)
        assert result.refused, f"{field_name!r} was not refused"
        assert result.reason_code == cand.R_UNKNOWN_FIELD
        assert field_name in result.detail


def test_an_unknown_edit_level_field_is_refused(repo):
    result = cand.parse_candidate(_candidate(edits=[
        {"path": "src/thing.py", "kind": "modify", "new_content": "x\n", "mode": "0777"},
    ]), root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_UNKNOWN_FIELD)


def test_absolute_paths_are_refused(repo):
    for bad in ("/etc/passwd", "~/.ssh/id_rsa", "C:\\Windows\\system32"):
        result = cand.parse_candidate(_candidate(edits=[
            {"path": bad, "kind": "create", "new_content": "x"},
        ]), root=repo)
        assert (result.refused, result.reason_code) == (True, cand.R_ABSOLUTE_PATH), bad


def test_path_traversal_is_refused(repo):
    for bad in ("../outside.py", "src/../../escape.py", "a/../../b.py"):
        result = cand.parse_candidate(_candidate(edits=[
            {"path": bad, "kind": "create", "new_content": "x"},
        ]), root=repo)
        assert (result.refused, result.reason_code) == (True, cand.R_PATH_TRAVERSAL), bad


def test_an_undeclared_file_is_refused(repo):
    result = cand.parse_candidate(
        _candidate(edits=[
            {"path": "README.md", "kind": "modify", "new_content": "# hacked\n"},
        ]),
        root=repo, allowed_paths=["src/thing.py"],
    )
    assert (result.refused, result.reason_code) == (True, cand.R_UNDECLARED_FILE)
    assert "README.md" in result.detail


def test_a_malformed_operation_is_refused(repo):
    result = cand.parse_candidate(_candidate(edits=[
        {"path": "src/thing.py", "kind": "chmod", "new_content": "x"},
    ]), root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_UNKNOWN_KIND)


def test_an_edit_missing_required_fields_is_refused(repo):
    for bad in ({"kind": "modify"}, {"path": "src/thing.py"}, {}, "not-a-dict"):
        result = cand.parse_candidate(_candidate(edits=[bad]), root=repo)
        assert result.refused, bad
        assert result.reason_code in (cand.R_MALFORMED_EDIT, cand.R_UNKNOWN_KIND)


def test_an_empty_patch_is_refused(repo):
    result = cand.parse_candidate(_candidate(edits=[]), root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_EMPTY_PATCH)


def test_missing_edits_is_refused(repo):
    result = cand.parse_candidate(json.dumps({"rationale": "nothing"}), root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_MISSING_EDITS)


def test_an_oversized_candidate_is_refused_before_parsing(repo):
    huge = json.dumps({"edits": [
        {"path": "src/thing.py", "kind": "modify", "new_content": "x" * 5000},
    ], "rationale": "big"})
    result = cand.parse_candidate(huge, root=repo, max_bytes=1024)
    assert (result.refused, result.reason_code) == (True, cand.R_OVERSIZE)


def test_confinement_violations_come_from_the_sandbox_rules_not_a_parallel_check(repo):
    """A create over an existing file is caught by opencode_sandbox.apply.validate."""
    result = cand.parse_candidate(_candidate(edits=[
        {"path": "README.md", "kind": "create", "new_content": "dup"},
    ]), root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_CONFINEMENT)
    assert any("already exists" in v for v in result.violations)


def test_a_modify_of_a_missing_file_is_refused(repo):
    result = cand.parse_candidate(_candidate(edits=[
        {"path": "src/nope.py", "kind": "modify", "new_content": "x"},
    ]), root=repo)
    assert (result.refused, result.reason_code) == (True, cand.R_CONFINEMENT)


def test_repeated_generation_of_the_same_response_is_deterministic(repo):
    """Same input, same verdict — the adapter has no hidden state."""
    verdicts = [cand.parse_candidate(_candidate(), root=repo) for _ in range(5)]
    assert all(v.ok for v in verdicts)
    assert len({v.declared_files for v in verdicts}) == 1


def test_the_adapter_never_writes_to_the_tree(repo):
    """Every refusal path, and the accepting path, leave the tree byte-identical."""
    snapshot = sorted(
        (str(p.relative_to(repo)), p.read_bytes()) for p in repo.rglob("*") if p.is_file()
    )
    for text in (
        _candidate(), "{bad", "[]", _candidate(edits=[]),
        _candidate(edits=[{"path": "/etc/passwd", "kind": "create", "new_content": "x"}]),
        json.dumps({"edits": [], "command": "rm -rf /"}),
    ):
        cand.parse_candidate(text, root=repo)
    after = sorted(
        (str(p.relative_to(repo)), p.read_bytes()) for p in repo.rglob("*") if p.is_file()
    )
    assert after == snapshot
