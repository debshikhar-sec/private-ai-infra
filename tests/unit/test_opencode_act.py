"""Tests for the OpenCode act step — the approval-gated, confined, verified apply path.

Pure-stdlib and offline (no opencode binary, no gateway): everything operates on temp
trees, so these run on CI alongside the Hermes/OpenClaw/eval suites.
"""

from __future__ import annotations

import json

from opencode_sandbox import act as cli
from opencode_sandbox import apply as act


def _target(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / "handler.py").write_text("x = 1\n", encoding="utf-8")
    return root


def _proposal(edits, *, level="L3", rationale="r"):
    return act.ChangeProposal(
        edits=[act.FileEdit(**e) for e in edits],
        autonomy_level=act.autonomy.parse_level(level, act.REQUIRED_APPROVAL_LEVEL),
        rationale=rationale,
    )


_GRANT = act.Approval(approver="alice", reason="reviewed", granted=True)


# ------------------------------------------------------------------ parse / model
def test_parse_proposal_reads_edits_not_approval():
    text = json.dumps(
        {
            "rationale": "fix",
            "autonomy_level": "L3",
            "edits": [{"path": "a.py", "kind": "modify", "new_content": "y\n"}],
            "approval": {"approver": "self", "granted": True},  # must be ignored
        }
    )
    p = act.parse_proposal(text, source="p.json")
    assert p.declared_files == ["a.py"]
    assert p.autonomy_level == 3
    assert not hasattr(p, "approval")


# --------------------------------------------------------------------- validation
def test_validate_rejects_path_escape(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "../escape.py", "kind": "create", "new_content": "x"}])
    v = act.validate(p, root)
    assert v and "escapes" in v[0]


def test_validate_rejects_absolute_path(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "/etc/passwd", "kind": "create", "new_content": "x"}])
    assert act.validate(p, root)


def test_validate_rejects_modify_of_missing_file(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "nope.py", "kind": "modify", "new_content": "x"}])
    assert any("does not exist" in s for s in act.validate(p, root))


def test_validate_rejects_create_over_existing(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "create", "new_content": "x"}])
    assert any("already exists" in s for s in act.validate(p, root))


def test_validate_rejects_unknown_kind(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "chmod", "new_content": "x"}])
    assert any("unknown edit kind" in s for s in act.validate(p, root))


def test_validate_clean_proposal_has_no_violations(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}])
    assert act.validate(p, root) == []


# ------------------------------------------------------------------------ gating
def test_apply_refused_without_approval(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}])
    rep = act.apply_proposal(p, root, tmp_path / "sb")
    assert rep.status == act.REFUSED
    assert rep.exit_code() == 1
    # fail closed: the real target was not touched
    assert (root / "handler.py").read_text(encoding="utf-8") == "x = 1\n"
    assert not (tmp_path / "sb").exists()


def test_apply_rejected_on_confinement_violation_without_writing(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "../evil", "kind": "create", "new_content": "x"}])
    rep = act.apply_proposal(p, root, tmp_path / "sb", approval=_GRANT)
    assert rep.status == act.REJECTED
    assert rep.violations
    assert not (tmp_path / "sb").exists()


def test_under_declared_level_still_requires_approval(tmp_path):
    # A proposal that carries edits but declares L2 (dry_run) cannot dodge the gate.
    root = _target(tmp_path)
    p = _proposal(
        [{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}], level="L2"
    )
    rep = act.apply_proposal(p, root, tmp_path / "sb")
    assert rep.status == act.REFUSED
    assert rep.autonomy_level == act.REQUIRED_APPROVAL_LEVEL  # escalated to the real level
    assert "under-declared" in rep.detail


# ------------------------------------------------------------------- apply/verify
def test_apply_with_approval_writes_sandbox_only(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}])
    rep = act.apply_proposal(p, root, tmp_path / "sb", approval=_GRANT)
    assert rep.status == act.APPLIED
    assert rep.changed_files == ["handler.py"]
    assert rep.approver == "alice"
    assert not rep.committed
    # sandbox has the change; the real target does not
    assert (tmp_path / "sb" / "handler.py").read_text(encoding="utf-8") == "x = 2\n"
    assert (root / "handler.py").read_text(encoding="utf-8") == "x = 1\n"


def test_commit_mirrors_verified_change_onto_target(tmp_path):
    root = _target(tmp_path)
    p = _proposal(
        [
            {"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"},
            {"path": "NEW.md", "kind": "create", "new_content": "hi\n"},
        ]
    )
    rep = act.apply_proposal(p, root, tmp_path / "sb", approval=_GRANT, commit_to=root)
    assert rep.status == act.APPLIED and rep.committed
    assert sorted(rep.changed_files) == ["NEW.md", "handler.py"]
    assert (root / "handler.py").read_text(encoding="utf-8") == "x = 2\n"
    assert (root / "NEW.md").read_text(encoding="utf-8") == "hi\n"


def test_delete_edit_is_applied_and_verified(tmp_path):
    root = _target(tmp_path)
    (root / "old.py").write_text("gone soon\n", encoding="utf-8")
    p = _proposal([{"path": "old.py", "kind": "delete"}])
    rep = act.apply_proposal(p, root, tmp_path / "sb", approval=_GRANT)
    assert rep.status == act.APPLIED
    assert rep.changed_files == ["old.py"]
    assert not (tmp_path / "sb" / "old.py").exists()


def test_noop_modify_is_applied_but_flagged(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "modify", "new_content": "x = 1\n"}])
    rep = act.apply_proposal(p, root, tmp_path / "sb", approval=_GRANT)
    assert rep.status == act.APPLIED
    assert "no-op" in rep.detail


def test_verification_helper_flags_undeclared_change(tmp_path):
    # Directly exercise the verifier: an edit whose path is NOT in the declared set
    # must surface as an unexpected (undeclared) change.
    root = _target(tmp_path)
    changed, unexpected, noops = act._apply_and_verify(
        root, [act.FileEdit("handler.py", "modify", "x = 9\n")], declared=set()
    )
    assert changed == ["handler.py"]
    assert unexpected == ["handler.py"]


# --------------------------------------------------------------------- rendering
def test_render_diff_shows_unified_diff(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}])
    diff = act.render_diff(p, root)
    assert "-x = 1" in diff and "+x = 2" in diff


def test_report_record_is_json_serializable(tmp_path):
    root = _target(tmp_path)
    p = _proposal([{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}])
    rep = act.apply_proposal(p, root, tmp_path / "sb", approval=_GRANT)
    rec = rep.to_record()
    json.dumps(rec)  # must not raise
    assert rec["component"] == "opencode-act"
    assert rec["status"] == "applied"
    assert rec["autonomy_name"] == "owner_run"


# --------------------------------------------------------------------------- CLI
def _write_proposal(tmp_path, edits, *, level="L3"):
    p = tmp_path / "proposal.json"
    p.write_text(
        json.dumps({"autonomy_level": level, "rationale": "r", "edits": edits}),
        encoding="utf-8",
    )
    return str(p)


def test_cli_refuses_without_approval(tmp_path, capsys):
    root = _target(tmp_path)
    prop = _write_proposal(
        tmp_path, [{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}]
    )
    code = cli.main([prop, "--target", str(root), "--runtime-dir", str(tmp_path / "rt")])
    assert code == 1
    out = capsys.readouterr()
    assert "REFUSED" in out.out
    assert "--approve" in out.err
    assert (root / "handler.py").read_text(encoding="utf-8") == "x = 1\n"


def test_cli_approve_and_commit_writes_target(tmp_path, capsys):
    root = _target(tmp_path)
    prop = _write_proposal(
        tmp_path, [{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}]
    )
    code = cli.main(
        [
            prop,
            "--target", str(root),
            "--runtime-dir", str(tmp_path / "rt"),
            "--approve", "alice:reviewed",
            "--commit",
            "--format", "json",
        ]
    )
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "applied" and data["committed"] is True
    assert (root / "handler.py").read_text(encoding="utf-8") == "x = 2\n"


def test_cli_rejects_empty_approver(tmp_path, capsys):
    root = _target(tmp_path)
    prop = _write_proposal(
        tmp_path, [{"path": "handler.py", "kind": "modify", "new_content": "x = 2\n"}]
    )
    code = cli.main(
        [prop, "--target", str(root), "--runtime-dir", str(tmp_path / "rt"), "--approve", ":no name"]
    )
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()
