"""Step 7C.3B — governed rollback and containment.

7C.3A proved a future sandbox apply *could* be reversed and deliberately wired the primitive
to nothing. These tests hold the thing that now calls it to the properties that make undoing
safe rather than convenient:

  * **A rollback is a mutation, not a repair.** Its own governed run, its own owner approval
    bound to its own canonical plan hash, its own single-use reservation appended *before*
    the approval is consumed, its own signed outcome. No agent can grant itself an undo, and
    reconciliation cannot trigger one.
  * **A failure is never a success.** A refusal *before* the reservation spends nothing and
    touches nothing; a failure *after* it signs a `failed` outcome, contains the workspace,
    and invalidates the rollback run. Either way there is no partial success and no silent
    retry.
  * **The executor reports; OpenClaw judges.** The verifier re-reads the tree rather than
    reading the executor's claim, and signs its own verdict with its own key.
  * **No pre-image, no rollback.** A historical apply is refused, not fabricated for.
  * **Confined.** A workspace outside the configured sandbox runtime root is refused before
    anything is read.

Deterministic: real durable stores, real signing, real files, real crash injection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from openclaw import assurance, verification
from openclaw.report import VERDICT_FAIL, VERDICT_PASS
from openclaw.sink import EMITTER_GATEWAY, EMITTER_OPENCLAW, EMITTER_OPENCODE
from opencode_sandbox import preimage
from opencode_sandbox import rollback as executor
from opencode_sandbox.apply import Approval, ChangeProposal, FileEdit, apply_proposal

from private_ai_gateway import app as gw
from private_ai_gateway import rollback as rb
from private_ai_gateway.approvals import ApprovalStatus, RunStatus
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.state import StateConfig, open_backend

_GW_HEX = "aa" * 32
_OC_HEX = "bb" * 32
_CLAW_HEX = "cc" * 32
_OWNER_TOKEN = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER_TOKEN}"}
HERMES = {"Authorization": f"Bearer {TOKENS['hermes']}"}


def _env(tmp_path):
    return {
        "PRIVATE_AI_EVIDENCE_KEY_GATEWAY": _GW_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCODE": _OC_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCLAW": _CLAW_HEX,
        "PRIVATE_AI_STATE_BACKEND": "sqlite",
        "PRIVATE_AI_STATE_DIR": str(tmp_path / "state"),
        "PRIVATE_AI_EVIDENCE_MODE": "durable",
    }


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """A gateway wired to durable stores plus a real sandbox runtime root."""
    install_demo_plane(gw)
    for name, value in _env(tmp_path).items():
        monkeypatch.setenv(name, value)
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    env = _env(tmp_path)
    opened = open_backend(StateConfig.from_env(env), environ=env)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "APPROVAL_STORE", opened.authority_store)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", bytes.fromhex(_GW_HEX))
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", True, raising=False)
    monkeypatch.setattr(gw, "SANDBOX_RUNTIME_ROOT", str(runtime))
    yield gw.app.test_client(), opened, runtime
    try:
        opened.close()
    except Exception:  # noqa: BLE001
        pass


# --- building a reversible apply ---------------------------------------------------------

def _source_tree(base: Path) -> Path:
    src = base / "src_tree"
    src.mkdir(parents=True)
    (src / "keep.py").write_text("UNTOUCHED\n", encoding="utf-8")
    (src / "edit.py").write_text("original\n", encoding="utf-8")
    (src / "gone.py").write_text("doomed\n", encoding="utf-8")
    return src


def _proposal():
    return ChangeProposal(
        edits=[
            FileEdit("edit.py", "modify", "rewritten\n"),
            FileEdit("gone.py", "delete", None),
            FileEdit("added.py", "create", "new\n"),
        ],
        autonomy_level=3,
    )


def _reversible_apply(opened, runtime, tmp_path, *, with_preimage=True, name="ws1"):
    """A run whose apply landed in a real sandbox workspace, with a real signed record."""
    from opencode_sandbox.evidence_emit import emit_apply_result

    store = opened.authority_store
    run_id = "run-" + name.ljust(28, "0")[:28]
    plan_hash = "sha256:" + "1" * 64
    store.create_run(run_id=run_id, principal_id="hermes", canonical_plan_hash=plan_hash,
                     effective_autonomy=3, policy_ceiling=6)
    approval_id = store.create_pending_approval(run_id).approval_id
    store.decide_approval(approval_id, decision="approve", approver="owner")

    src = _source_tree(tmp_path / name)
    workspace = runtime / name
    workspace.mkdir()
    report = apply_proposal(
        _proposal(), src, workspace / "sandbox", approval=Approval("owner", "reviewed"),
        preimage_store=(workspace / "preimage") if with_preimage else None,
        run_id=run_id, approval_id=approval_id,
    )
    assert report.status == "applied"
    store.mark_used(approval_id)
    emit_apply_result(
        opened.evidence_sink, bytes.fromhex(_OC_HEX),
        sink_id=opened.evidence_sink.sink_id, run_id=run_id, approval_id=approval_id,
        emitter_key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCODE], report=report,
    )
    return run_id, approval_id, workspace, src


def _plan(client, run_id, approval_id, workspace_name, headers=None):
    return client.post("/v1/rollbacks", headers=headers or OWNER,
                       json={"run_id": run_id, "approval_id": approval_id,
                             "workspace": workspace_name})


def _approve_plan(client, plan_body):
    return client.post(
        "/v1/approvals", headers=OWNER,
        json={"run_id": plan_body["rollback_run_id"],
              "canonical_plan_hash": plan_body["canonical_plan_hash"],
              "decision": "approve", "reason": "reviewed the restoration"},
    ).get_json()["approval_id"]


def _execute(client, plan_body, rb_approval, run_id, approval_id, workspace_name,
             headers=None):
    return client.post("/v1/rollbacks/execute", headers=headers or OWNER,
                       json={"rollback_run_id": plan_body["rollback_run_id"],
                             "approval_id": rb_approval, "run_id": run_id,
                             "approval_id_origin": approval_id,
                             "workspace": workspace_name})


def _types(sink):
    return [r.envelope.record_type for r in sink.records]


def _contents(root: Path) -> dict:
    return {str(p.relative_to(root)): p.read_text(encoding="utf-8")
            for p in sorted(root.rglob("*")) if p.is_file()}


# --- the happy path, end to end -----------------------------------------------------------

def test_a_governed_rollback_restores_the_sandbox_and_records_every_step(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, workspace, src = _reversible_apply(opened, runtime, tmp_path)
    sandbox = workspace / "sandbox"
    assert (sandbox / "edit.py").read_text() == "rewritten\n"

    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    assert plan["snapshot_id"].startswith("pre-")
    assert sorted(plan["restores"]) == ["added.py", "edit.py", "gone.py"]

    rb_approval = _approve_plan(client, plan)
    result = _execute(client, plan, rb_approval, run_id, approval_id, "ws1").get_json()

    assert result["restored"] is True
    assert result["contained"] is False
    assert result["human_action_required"] is False
    assert _contents(sandbox) == _contents(src)           # byte-exact
    assert not (sandbox / "added.py").exists()

    kinds = _types(opened.evidence_sink)
    assert kinds.count("rollback_validated") == 1
    assert kinds.count("rollback_result") == 1
    opened.evidence_sink.verify_chain()


def test_a_successful_rollback_claims_only_the_sandbox(wired, tmp_path):
    """It restored a tree. It did not undo the world, and does not say it did."""
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    result = _execute(client, plan, _approve_plan(client, plan), run_id, approval_id,
                      "ws1").get_json()
    assert "no external effect" in result["scope"]

    record = next(r for r in opened.evidence_sink.records
                  if r.envelope.record_type == "rollback_result")
    assert "no external effect is claimed to be undone" in record.payload["detail"]
    assert record.envelope.emitter == EMITTER_OPENCODE


def test_the_reservation_is_appended_before_the_approval_is_consumed(wired, tmp_path):
    """Step 7B.1's ordering, unchanged: spent authority always leaves a durable trace."""
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    rb_approval = _approve_plan(client, plan)

    seen = []
    real_mark = opened.authority_store.mark_used

    def watching(aid, **kw):
        seen.append(_types(opened.evidence_sink))
        return real_mark(aid, **kw)

    opened.authority_store.mark_used = watching
    try:
        _execute(client, plan, rb_approval, run_id, approval_id, "ws1")
    finally:
        opened.authority_store.mark_used = real_mark

    at_consume = seen[-1]
    assert "rollback_validated" in at_consume        # reserved first
    assert "rollback_result" not in at_consume       # mutated after


def test_the_rollback_approval_is_single_use(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    rb_approval = _approve_plan(client, plan)
    assert _execute(client, plan, rb_approval, run_id, approval_id, "ws1").status_code == 200

    again = _execute(client, plan, rb_approval, run_id, approval_id, "ws1")
    assert again.status_code == 409
    assert again.get_json()["error"]["code"] == rb.CODE_NOT_AUTHORIZED
    assert _types(opened.evidence_sink).count("rollback_result") == 1


def test_a_second_rollback_of_the_same_run_is_refused(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")

    second = _plan(client, run_id, approval_id, "ws1")
    assert second.status_code == 409
    assert second.get_json()["error"]["code"] == rb.CODE_ALREADY_ROLLED_BACK


# --- authority ------------------------------------------------------------------------------

@pytest.mark.parametrize("who", ["hermes", "opencode", "openclaw"])
def test_no_agent_principal_may_plan_or_execute_a_rollback(wired, tmp_path, who):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    headers = {"Authorization": f"Bearer {TOKENS[who]}"}
    assert _plan(client, run_id, approval_id, "ws1", headers=headers).status_code == 403
    assert client.post("/v1/rollbacks/execute", headers=headers, json={}).status_code == 403
    assert "rollback_result" not in _types(opened.evidence_sink)


def test_an_unapproved_rollback_never_executes(wired, tmp_path):
    """A plan is capability; only the approval is authority."""
    client, opened, runtime = wired
    run_id, approval_id, workspace, src = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()

    resp = _execute(client, plan, "appr-" + "0" * 32, run_id, approval_id, "ws1")
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == rb.CODE_NOT_AUTHORIZED
    assert (workspace / "sandbox" / "edit.py").read_text() == "rewritten\n"   # unrestored
    assert "rollback_validated" not in _types(opened.evidence_sink)


def test_an_approval_for_a_different_plan_hash_is_refused(wired, tmp_path):
    """Approving *a* rollback is not approving *this* restoration."""
    client, opened, runtime = wired
    run_a, appr_a, _, _ = _reversible_apply(opened, runtime, tmp_path, name="wsa")
    run_b, appr_b, _, _ = _reversible_apply(opened, runtime, tmp_path, name="wsb")
    plan_a = _plan(client, run_a, appr_a, "wsa").get_json()
    plan_b = _plan(client, run_b, appr_b, "wsb").get_json()
    assert plan_a["canonical_plan_hash"] != plan_b["canonical_plan_hash"]

    foreign = _approve_plan(client, plan_b)
    resp = _execute(client, plan_a, foreign, run_a, appr_a, "wsa")
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == rb.CODE_NOT_AUTHORIZED


def test_reconciliation_never_triggers_a_rollback(wired, tmp_path):
    """Structural: the reconciler holds no executor and reaches no rollback entry point."""
    repo = Path(__file__).resolve().parents[2]
    source = (repo / "src" / "private_ai_gateway" / "reconciliation.py").read_text()
    for forbidden in ("rollback", "restore_into", "perform_rollback", "execute_rollback"):
        assert forbidden not in source


# --- what cannot be rolled back ---------------------------------------------------------------

def test_an_apply_with_no_pre_image_is_refused_not_fabricated_for(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(
        opened, runtime, tmp_path, with_preimage=False, name="old"
    )
    resp = _plan(client, run_id, approval_id, "old")
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == rb.CODE_NOT_REVERSIBLE


def test_a_run_with_no_apply_evidence_is_refused(wired, tmp_path):
    client, opened, runtime = wired
    store = opened.authority_store
    store.create_run(run_id="run-empty", principal_id="hermes",
                     canonical_plan_hash="sha256:" + "2" * 64,
                     effective_autonomy=3, policy_ceiling=6)
    appr = store.create_pending_approval("run-empty").approval_id
    resp = _plan(client, "run-empty", appr, "ws1")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == rb.CODE_APPLY_NOT_FOUND


def test_a_terminally_disposed_run_is_not_reopened_to_be_undone(wired, tmp_path):
    from private_ai_gateway import disposition as disp

    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    opened.authority_store.invalidate_run(run_id)
    apply_ref = next(r for r in opened.evidence_sink.records
                     if r.envelope.record_type == "apply_result").evidence_ref()
    verdict = verification.emit_verification_result(
        opened.evidence_sink, _fail_report(), run_id=run_id, approval_id=approval_id,
        signing_key=bytes.fromhex(_CLAW_HEX),
        key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCLAW],
    )
    assert apply_ref is not None
    client.post("/v1/dispositions", headers=OWNER, json={
        "run_id": run_id, "approval_id": approval_id,
        "disposition": disp.DISPOSITION_CLOSED_UNKNOWN,
        "basis_type": disp.BASIS_VERIFICATION_RESULT,
        "basis_ref": verdict.evidence_ref.to_mapping(),
    })

    resp = _plan(client, run_id, approval_id, "ws1")
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == rb.CODE_RUN_DISPOSED


def _fail_report():
    from openclaw.checks import FAIL, Finding
    from openclaw.report import build_report

    return build_report([Finding("AC-1", "control", FAIL, "high", "broke")])


@pytest.mark.parametrize("bad", ["../outside", "/etc", "ws1/../../escape", "~/elsewhere"])
def test_a_workspace_outside_the_runtime_root_is_refused(wired, tmp_path, bad):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    resp = _plan(client, run_id, approval_id, bad)
    assert resp.status_code in (400, 404)
    assert resp.get_json()["error"]["code"] in (
        rb.CODE_WORKSPACE_UNCONFINED, rb.CODE_WORKSPACE_MISSING
    )


def test_a_symlinked_workspace_pointing_outside_the_root_is_refused(wired, tmp_path):
    """Selection is by name among real child directories, so a symlink is simply not one."""
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    outside = tmp_path / "outside_ws"
    outside.mkdir()
    (runtime / "sneaky").symlink_to(outside, target_is_directory=True)

    resp = _plan(client, run_id, approval_id, "sneaky")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == rb.CODE_WORKSPACE_MISSING


def test_a_nested_workspace_path_is_refused(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    (runtime / "ws1" / "nested").mkdir()
    resp = _plan(client, run_id, approval_id, "ws1/nested")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == rb.CODE_WORKSPACE_UNCONFINED


def test_rollback_is_unavailable_with_no_configured_runtime_root(wired, tmp_path,
                                                                 monkeypatch):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    monkeypatch.setattr(gw, "SANDBOX_RUNTIME_ROOT", "")
    resp = _plan(client, run_id, approval_id, "ws1")
    assert resp.get_json()["error"]["code"] == rb.CODE_WORKSPACE_UNCONFINED


def test_a_workspace_whose_snapshot_does_not_match_the_evidence_is_refused(wired, tmp_path):
    """Naming a real workspace is not enough: its snapshot must be the one evidence names."""
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    snap = next((workspace / "preimage").iterdir())
    blob = next((snap / preimage.BLOBS_DIR).iterdir())
    blob.write_text("tampered\n", encoding="utf-8")

    resp = _plan(client, run_id, approval_id, "ws1")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == rb.CODE_SNAPSHOT_UNUSABLE


def test_a_missing_snapshot_is_refused(wired, tmp_path):
    import shutil

    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    shutil.rmtree(workspace / "preimage")
    resp = _plan(client, run_id, approval_id, "ws1")
    assert resp.get_json()["error"]["code"] == rb.CODE_SNAPSHOT_UNUSABLE


# --- failure is never success, and containment --------------------------------------------

def test_a_snapshot_that_breaks_after_approval_is_refused_before_anything_is_spent(
    wired, tmp_path
):
    """Refused *before* the reservation: no authority spent, nothing written, no containment.

    Containment exists for an unknown state. A rollback that never started leaves a known
    one, so treating it as contained would be over-reacting to a clean refusal.
    """
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    rb_approval = _approve_plan(client, plan)

    # The snapshot is corrupted between approval and execution.
    snap = next((workspace / "preimage").iterdir())
    next((snap / preimage.BLOBS_DIR).iterdir()).unlink()

    resp = _execute(client, plan, rb_approval, run_id, approval_id, "ws1")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == rb.CODE_SNAPSHOT_UNUSABLE
    assert "rollback_validated" not in _types(opened.evidence_sink)
    assert "rollback_result" not in _types(opened.evidence_sink)
    assert opened.authority_store.get_approval(rb_approval).approval_status is (
        ApprovalStatus.APPROVED                      # never consumed
    )
    assert executor.containment_reason(workspace) == ""
    assert (workspace / "sandbox" / "edit.py").read_text() == "rewritten\n"


def test_a_post_restore_mismatch_is_a_failure_and_contains_the_workspace(wired, tmp_path,
                                                                         monkeypatch):
    """If the tree does not match afterwards, the rollback failed — however it looked."""
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    rb_approval = _approve_plan(client, plan)

    monkeypatch.setattr(executor, "restore_into", lambda snapshot, root: ["edit.py"])
    result = _execute(client, plan, rb_approval, run_id, approval_id, "ws1").get_json()

    assert result["restored"] is False
    assert result["status"] == executor.FAILED
    assert result["contained"] is True
    assert result["human_action_required"] is True
    assert executor.containment_reason(workspace).startswith(
        executor.R_POST_RESTORE_MISMATCH
    )
    record = next(r for r in opened.evidence_sink.records
                  if r.envelope.record_type == "rollback_result")
    assert record.payload["status"] == executor.FAILED
    assert record.payload["restored_files"] == []
    assert opened.authority_store.get_run(plan["rollback_run_id"]).status is (
        RunStatus.INVALIDATED
    )


def test_a_restore_that_raises_mid_write_is_contained_not_retried(wired, tmp_path,
                                                                  monkeypatch):
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    rb_approval = _approve_plan(client, plan)

    def exploding(snapshot, root):
        (Path(root) / "edit.py").write_text("half\n", encoding="utf-8")
        raise OSError("disk full mid-restore")

    monkeypatch.setattr(executor, "restore_into", exploding)
    result = _execute(client, plan, rb_approval, run_id, approval_id, "ws1").get_json()

    assert result["status"] == executor.FAILED
    assert result["contained"] is True
    assert executor.R_RESTORE_FAILED in executor.containment_reason(workspace)
    assert _types(opened.evidence_sink).count("rollback_result") == 1   # not retried


def test_a_contained_workspace_refuses_a_further_rollback(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    executor.contain_workspace(workspace, reason="prior failure", run_id=run_id)

    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    result = _execute(client, plan, _approve_plan(client, plan), run_id, approval_id,
                      "ws1").get_json()
    assert result["restored"] is False
    assert result["contained"] is True
    assert executor.R_WORKSPACE_CONTAINED in result["reason"]


def test_containment_records_why_and_asks_for_a_human(wired, tmp_path):
    _, _, runtime = wired
    workspace = runtime / "ws"
    workspace.mkdir()
    marker = executor.contain_workspace(workspace, reason="snapshot gone", run_id="run-x")
    body = json.loads(marker.read_text(encoding="utf-8"))
    assert body["human_action_required"] is True
    assert body["reason"] == "snapshot gone"
    assert body["run_id"] == "run-x"
    # Idempotent: a second containment does not overwrite the first explanation.
    executor.contain_workspace(workspace, reason="something else")
    assert json.loads(marker.read_text())["reason"] == "snapshot gone"


def test_containment_deletes_nothing(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    before = _contents(workspace / "sandbox")
    executor.contain_workspace(workspace, reason="inspect me")
    assert _contents(workspace / "sandbox") == before


def test_an_unrecordable_outcome_is_loud_and_contains(wired, tmp_path, monkeypatch):
    """The sandbox may be half-restored with no durable trace. That must never be quiet."""
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    rb_approval = _approve_plan(client, plan)

    real_append = opened.evidence_sink.append

    def refuse_outcomes(envelope, payload, sig):
        # Only the executor's outcome fails, so the reservation still lands and the failure
        # is exactly the one being tested: a mutation with no durable record of what it did.
        if envelope.record_type == executor.ROLLBACK_RESULT_RECORD_TYPE:
            raise RuntimeError("sink is gone")
        return real_append(envelope, payload, sig)

    monkeypatch.setattr(opened.evidence_sink, "append", refuse_outcomes)
    resp = _execute(client, plan, rb_approval, run_id, approval_id, "ws1")
    assert resp.status_code == 503
    assert resp.get_json()["error"]["code"] == rb.CODE_EVIDENCE_UNAVAILABLE
    assert executor.containment_reason(workspace)
    assert opened.authority_store.get_run(plan["rollback_run_id"]).status is (
        RunStatus.INVALIDATED
    )


def test_the_executor_refuses_to_write_without_a_reservation(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    snap = next((workspace / "preimage").iterdir())
    with pytest.raises(executor.RollbackExecutionError) as exc:
        executor.perform_rollback(
            workspace=workspace, sandbox=workspace / "sandbox",
            snapshot_id=snap.name, snapshot_digest="sha256:" + "0" * 64,
            reservation_ref=None, apply_ref=None, run_id="x", origin_run_id=run_id,
            approval_id="y", evidence_sink=opened.evidence_sink,
            evidence_key=bytes.fromhex(_OC_HEX),
            emitter_key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCODE],
        )
    assert executor.R_NO_RESERVATION in str(exc.value)
    assert (workspace / "sandbox" / "edit.py").read_text() == "rewritten\n"


# --- independent verification --------------------------------------------------------------

def test_openclaw_signs_its_own_verdict_on_a_successful_rollback(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")

    outcome = next(r for r in opened.evidence_sink.records
                   if r.envelope.record_type == "rollback_result")
    emit = verification.verify_rollback(
        opened.evidence_sink, outcome, sandbox=workspace / "sandbox",
        signing_key=bytes.fromhex(_CLAW_HEX),
        key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCLAW],
    )
    assert emit.advertised_verdict == VERDICT_PASS

    record = next(r for r in opened.evidence_sink.records
                  if r.envelope.record_type == "verification_result")
    assert record.envelope.emitter == EMITTER_OPENCLAW
    assert record.payload["rollback_ref"]["evidence_id"] == outcome.envelope.evidence_id
    opened.evidence_sink.verify_chain()


def test_the_verifier_re_reads_the_tree_rather_than_trusting_the_claim(wired, tmp_path):
    """A `restored` claim over a tree that does not match is a FAIL, not a PASS."""
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")

    # The tree drifts after the executor signed its (then-true) outcome.
    (workspace / "sandbox" / "edit.py").write_text("drifted\n", encoding="utf-8")

    outcome = next(r for r in opened.evidence_sink.records
                   if r.envelope.record_type == "rollback_result")
    emit = verification.verify_rollback(
        opened.evidence_sink, outcome, sandbox=workspace / "sandbox",
        signing_key=bytes.fromhex(_CLAW_HEX),
        key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCLAW],
    )
    assert emit.advertised_verdict == VERDICT_FAIL
    assert "does not match the recorded pre-image" in emit.reason


def test_a_failed_rollback_can_never_be_verified_as_a_pass(wired, tmp_path, monkeypatch):
    client, opened, runtime = wired
    run_id, approval_id, workspace, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    monkeypatch.setattr(executor, "restore_into", lambda s, r: [])
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")

    outcome = next(r for r in opened.evidence_sink.records
                   if r.envelope.record_type == "rollback_result")
    emit = verification.verify_rollback(
        opened.evidence_sink, outcome, sandbox=workspace / "sandbox",
        signing_key=bytes.fromhex(_CLAW_HEX),
        key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCLAW],
    )
    assert emit.advertised_verdict == VERDICT_FAIL


def test_the_executor_never_emits_the_verifier_conclusion(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")
    payload = next(r for r in opened.evidence_sink.records
                   if r.envelope.record_type == "rollback_result").payload
    assert "verdict" not in payload
    assert "verification" not in json.dumps(payload)


# --- restart ---------------------------------------------------------------------------------

def test_the_whole_rollback_chain_survives_a_restart(wired, tmp_path):
    client, opened, runtime = wired
    run_id, approval_id, workspace, src = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")
    opened.close()

    env = _env(tmp_path)
    reopened = open_backend(StateConfig.from_env(env), environ=env)
    try:
        reopened.evidence_sink.verify_chain()
        outcomes = rb.rollback_results_for(
            reopened.evidence_sink, run_id=plan["rollback_run_id"]
        )
        assert len(outcomes) == 1
        assert outcomes[0].payload["status"] == executor.RESTORED
        assert outcomes[0].payload["origin_run_id"] == run_id
        assert reopened.authority_store.get_approval(
            plan["rollback_run_id"] and outcomes[0].envelope.approval_id
        ).approval_status is ApprovalStatus.USED
        assert _contents(workspace / "sandbox") == _contents(src)
    finally:
        reopened.close()


def test_the_rollback_run_is_a_distinct_governed_run(wired, tmp_path):
    """The envelope's run_id is the rollback's own run, never the run it reverses."""
    client, opened, runtime = wired
    run_id, approval_id, _, _ = _reversible_apply(opened, runtime, tmp_path)
    plan = _plan(client, run_id, approval_id, "ws1").get_json()
    assert plan["rollback_run_id"] != run_id
    _execute(client, plan, _approve_plan(client, plan), run_id, approval_id, "ws1")

    outcome = next(r for r in opened.evidence_sink.records
                   if r.envelope.record_type == "rollback_result")
    assert outcome.envelope.run_id == plan["rollback_run_id"]
    assert outcome.payload["origin_run_id"] == run_id
    # The original run's spent authority is untouched by the rollback.
    assert opened.authority_store.get_approval(approval_id).approval_status is (
        ApprovalStatus.USED
    )
