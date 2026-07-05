"""Governed Chat Console: the phased session and the /v1/orchestrate endpoint.

Runs the real enforcement plane in-process (packaged demo policy + demo backend). A green
run proves the chat drives the *actual* governed loop — Hermes plans and proposes but does
not execute, the apply refuses unless a human approves, and the boundary probes are refused
with their exact audit codes.
"""

import re

import pytest
from hermes.session import GovernedSession
from interop import AgentPeer

from private_ai_gateway import app as gw
from private_ai_gateway.demo import TOKENS, install_demo_plane

HERMES = f"Bearer {TOKENS['hermes']}"


@pytest.fixture
def client():
    install_demo_plane(gw)
    return gw.app.test_client()


@pytest.fixture
def peers(client):
    def make(token):
        def send(method, path, body=None):
            resp = getattr(client, method.lower())(
                path, headers={"Authorization": f"Bearer {token}"}, json=body
            )
            payload = resp.get_json(silent=True)
            if payload is None:
                payload = resp.get_data(as_text=True)
            return resp.status_code, payload

        return AgentPeer(send=send)

    return {name: make(token) for name, token in TOKENS.items()}


# ---- the phased session -----------------------------------------------------

def test_plan_proposes_but_does_not_execute(peers):
    out = GovernedSession(peers, "Apply the reviewed fix and verify it").plan()
    assert out["phase"] == "plan"
    assert out["needs_approval"] is True
    # The executor is discovered from the enforced directory, never named up front.
    assert out["proposal"]["executor"] == "opencode"
    assert out["proposal"]["skill"] == "code.apply"
    assert out["proposal"]["level"] == 3
    # Hermes plans at L1 and nothing above L1 appears as an executed step.
    assert any(s["actor"] == "hermes" and s.get("level") == 1 for s in out["steps"])


def test_execute_with_approval_applies_and_verifies(peers):
    out = GovernedSession(peers, "Apply the reviewed fix and verify it").execute(
        "owner", "reviewed the diff; approved"
    )
    assert out["applied"] is True
    assert out["verdict"] == "PASS"
    # Full attenuating chain: hermes -> opencode (L3) -> openclaw (L2), depth 2.
    depths = {d["depth"] for d in out["chain"]}
    assert depths == {1, 2}
    sub = next(d for d in out["chain"] if d["depth"] == 2)
    assert sub["delegatee"] == "openclaw" and sub["level"] <= 2


def test_execute_without_approval_refuses(peers):
    """The keystone: no human approval, no apply — authority stays with the person."""
    out = GovernedSession(peers, "Apply the reviewed fix and verify it").execute("", "")
    assert out["applied"] is False
    assert out["verdict"] == "REFUSED"
    apply_step = next(s for s in out["steps"] if s["actor"] == "opencode")
    assert apply_step["decision"] == "deny"


def test_probe_refuses_amplification_and_ungranted_skill(peers):
    out = GovernedSession(peers, "x").probe()
    codes = {s["code"] for s in out["steps"]}
    assert "autonomy_amplification" in codes
    assert "skill_not_delegable" in codes
    assert all(s["decision"] == "deny" for s in out["steps"])
    assert "boundary_hole" not in codes  # nothing slipped through


# ---- the HTTP endpoint ------------------------------------------------------

def test_endpoint_plan_phase(client):
    r = client.post("/v1/orchestrate", headers={"Authorization": HERMES},
                    json={"objective": "Apply the reviewed fix and verify it", "phase": "plan"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["needs_approval"] is True
    assert body["proposal"]["executor"] == "opencode"


def test_endpoint_execute_requires_approval(client):
    # After D2b an inline-approver body no longer applies; execute needs an approval_id.
    refused = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": "Apply the reviewed fix and verify it", "phase": "execute",
              "approver": "owner", "reason": "reviewed"},
    ).get_json()
    assert refused["applied"] is False and refused["verdict"] == "REFUSED"
    assert refused["refusal_reason"] == "approval_missing"


def test_endpoint_rejects_unknown_phase_and_empty_objective(client):
    bad_phase = client.post("/v1/orchestrate", headers={"Authorization": HERMES},
                            json={"objective": "x", "phase": "delete-everything"})
    assert bad_phase.status_code == 400
    assert bad_phase.get_json()["error"]["code"] == "invalid_request"

    empty = client.post("/v1/orchestrate", headers={"Authorization": HERMES},
                        json={"objective": "  ", "phase": "plan"})
    assert empty.status_code == 400


def test_endpoint_requires_authentication(client):
    r = client.post("/v1/orchestrate", json={"objective": "x", "phase": "plan"})
    assert r.status_code == 401


# ---- run_id lifecycle (Step C1: threading only, no enforcement) --------------

RUN_ID_RE = re.compile(r"^run-[0-9a-f]+$")
_OBJ = "Apply the reviewed fix and verify it"


def _post(client, **body):
    return client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES}, json=body
    ).get_json()


def test_plan_response_includes_minted_run_id(client):
    body = _post(client, objective=_OBJ, phase="plan")
    assert RUN_ID_RE.match(body["run_id"])


def test_plan_ignores_client_supplied_run_id(client):
    body = _post(client, objective=_OBJ, phase="plan", run_id="run-attacker-supplied")
    assert body["run_id"] != "run-attacker-supplied"
    assert RUN_ID_RE.match(body["run_id"])


def test_execute_echoes_supplied_run_id(client):
    # An unregistered run + a stray approval_id is a governed refusal, but the run_id is
    # still echoed for correlation (the transcript carries it even when nothing applies).
    body = _post(
        client, objective=_OBJ, phase="execute",
        run_id="run-corr-execute", approval_id="appr-none",
    )
    assert body["run_id"] == "run-corr-execute"
    assert body["applied"] is False and body["verdict"] == "REFUSED"
    assert body["refusal_reason"] == "run_not_found"


def test_probe_echoes_supplied_run_id(client):
    body = _post(client, objective=_OBJ, phase="probe", run_id="run-corr-probe")
    assert body["run_id"] == "run-corr-probe"
    assert body["phase"] == "probe"


def test_execute_without_approval_refuses_and_probe_is_backward_compatible(client):
    # Execute with no run_id/approval_id is a governed refusal (echoed run_id stays empty).
    ex = _post(client, objective=_OBJ, phase="execute", approver="owner", reason="ok")
    assert ex["applied"] is False and ex["verdict"] == "REFUSED"
    assert ex["refusal_reason"] == "approval_missing"
    assert ex.get("run_id", "") == ""  # echoed empty, never minted outside plan

    # Probe is unchanged by D2b.
    pr = _post(client, objective=_OBJ, phase="probe")
    assert pr["phase"] == "probe"
    assert pr.get("run_id", "") == ""


def test_plan_still_proposes_alongside_run_id(client):
    body = _post(client, objective=_OBJ, phase="plan")
    assert body["needs_approval"] is True
    assert body["proposal"]["executor"] == "opencode"
    assert body["proposal"]["skill"] == "code.apply"
    assert "run_id" in body


# ---- C2: run_id audit tagging (orchestration sub-requests only) --------------

def test_orchestration_subrequest_audit_carries_run_id(client):
    body = _post(client, objective=_OBJ, phase="plan")
    run_id = body["run_id"]
    assert RUN_ID_RE.match(run_id)
    # At least one governed sub-request hop (e.g. the L1 plan model call) is tagged.
    tagged = [e for e in gw.DECISION_LOG.tail(limit=200) if e.get("run_id") == run_id]
    assert tagged, "expected an orchestration audit record tagged with the run_id"


def test_plain_request_without_x_run_id_has_no_run_id_key(client):
    # /v1/decisions is an untagged, recording handler (hermes lacks can_read_audit -> 403,
    # which is itself audited). A plain request must keep the exact historical shape.
    client.get("/v1/decisions", headers={"Authorization": HERMES})
    recs = [e for e in gw.DECISION_LOG.tail(limit=50) if e.get("path") == "/v1/decisions"]
    assert recs, "expected a /v1/decisions audit record"
    assert all("run_id" not in e for e in recs)


def test_untagged_handler_ignores_x_run_id(client):
    # Option B proof: an untagged handler does NOT tag its record even if a client sets
    # X-Run-Id — only the explicitly tagged orchestration-path handlers emit run_id.
    client.get(
        "/v1/decisions",
        headers={"Authorization": HERMES, "X-Run-Id": "run-should-be-ignored"},
    )
    recs = [e for e in gw.DECISION_LOG.tail(limit=50) if e.get("path") == "/v1/decisions"]
    assert recs
    assert all("run_id" not in e for e in recs)


# ---- D1: canonical plan hash on plan (metadata only; no enforcement) ---------

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def test_plan_returns_run_id_and_canonical_plan_hash(client):
    body = _post(client, objective=_OBJ, phase="plan")
    assert RUN_ID_RE.match(body["run_id"])
    assert SHA256_RE.match(body["canonical_plan_hash"])


def test_plan_hash_is_stable_across_runs_with_same_inputs(client):
    a = _post(client, objective=_OBJ, phase="plan")
    b = _post(client, objective=_OBJ, phase="plan")
    assert a["run_id"] != b["run_id"]                        # fresh run each time
    assert a["canonical_plan_hash"] == b["canonical_plan_hash"]  # same authority-bearing plan


def test_plan_registers_run_in_approval_store(client):
    body = _post(client, objective=_OBJ, phase="plan")
    run = gw.APPROVAL_STORE.get_run(body["run_id"])
    assert run is not None
    assert run.canonical_plan_hash == body["canonical_plan_hash"]
    assert run.principal_id == "hermes"


def test_execute_inline_approver_no_longer_authorizes(client):
    # D2b closes the loop: a request-body approver grants nothing, even on a real run.
    plan = _post(client, objective=_OBJ, phase="plan")
    ex = _post(client, objective=_OBJ, phase="execute",
               approver="owner", reason="reviewed", run_id=plan["run_id"])
    assert ex["applied"] is False and ex["verdict"] == "REFUSED"
    assert ex["refusal_reason"] == "approval_missing"


def test_plan_fails_closed_when_policy_unreadable(client, monkeypatch):
    # policy_hash is authority-bearing: an unreadable policy file must fail closed, never
    # hash a fallback and return a misleading canonical_plan_hash.
    monkeypatch.setattr(gw, "POLICY_PATH", "/nonexistent/policy/does-not-exist.toml")
    r = client.post("/v1/orchestrate", headers={"Authorization": HERMES},
                    json={"objective": _OBJ, "phase": "plan"})
    assert r.status_code == 503
    assert r.get_json()["error"]["code"] == "orchestration_unavailable"


def test_demo_plane_repoints_policy_path_to_packaged_policy(monkeypatch, tmp_path):
    # Regression for the CI false-green: the module default POLICY_PATH is the *untracked*
    # config/policy.toml, absent in a fresh checkout. install_demo_plane must repoint
    # POLICY_PATH at the packaged demo policy it actually loaded, so the authority-bearing
    # canonical hash reads a file that ships with the package — never config/policy.toml.
    from pathlib import Path

    # Simulate CI: POLICY_PATH points at a nonexistent file *before* the demo plane installs.
    missing = tmp_path / "config" / "policy.toml"
    monkeypatch.setattr(gw, "POLICY_PATH", str(missing))
    assert not missing.exists()

    install_demo_plane(gw)

    # POLICY_PATH now resolves to the packaged, existing demo policy.
    assert Path(gw.POLICY_PATH).is_file()
    assert Path(gw.POLICY_PATH).name == "demo_policy.toml"

    # A plan succeeds end to end without relying on config/policy.toml.
    c = gw.app.test_client()
    body = _post(c, objective=_OBJ, phase="plan")
    assert RUN_ID_RE.match(body["run_id"])
    assert SHA256_RE.match(body["canonical_plan_hash"])
    # The plan's policy_hash is sha256-formatted (hashed from the packaged demo policy).
    assert SHA256_RE.match(body["canonical_plan"]["policy_hash"])


# ---- D2a: owner-gated POST /v1/approvals (decision only; no execute enforcement) ----

_OWNER_TOKEN = "test-owner-break-glass-token"


@pytest.fixture
def owner_token(monkeypatch):
    # install_demo_plane does not configure AUTH_TOKEN; set a known owner (break-glass)
    # token so the bearer resolves to OWNER_PRINCIPAL (via _identify_principal's fallback).
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    return _OWNER_TOKEN


def _owner_hdr():
    return {"Authorization": f"Bearer {_OWNER_TOKEN}"}


def _plan_and_hash(client):
    body = _post(client, objective=_OBJ, phase="plan")
    return body["run_id"], body["canonical_plan_hash"]


def _approve(client, run_id, plan_hash, reason="reviewed the diff"):
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "approve", "reason": reason})
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def _reject(client, run_id, plan_hash, reason="scope too broad"):
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "reject", "reason": reason})
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def test_owner_can_approve_registered_run(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "approve", "reason": "reviewed the diff"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["approval_id"].startswith("appr-")
    assert body["run_id"] == run_id
    assert body["approval_status"] == "approved"
    assert body["canonical_plan_hash"] == plan_hash
    assert body["expires_at"] is not None
    assert body["single_use"] is True


def test_owner_can_reject_registered_run(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "reject", "reason": "scope too broad"})
    assert r.status_code == 200                       # rejection is a governed success
    body = r.get_json()
    assert body["approval_status"] == "rejected"
    assert body["rejection_reason"] == "scope too broad"


def test_non_owner_cannot_approve(client):
    run_id, plan_hash = _plan_and_hash(client)
    r = client.post("/v1/approvals", headers={"Authorization": HERMES},
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "approve"})
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "owner_required"


def test_approvals_requires_authentication(client):
    r = client.post("/v1/approvals",
                    json={"run_id": "x", "canonical_plan_hash": "y", "decision": "approve"})
    assert r.status_code == 401


def test_approve_unknown_run_refuses(client, owner_token):
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": "run-does-not-exist",
                          "canonical_plan_hash": "sha256:" + "0" * 64, "decision": "approve"})
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "run_not_found"


def test_approve_wrong_hash_refuses(client, owner_token):
    run_id, _ = _plan_and_hash(client)
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": "sha256:" + "0" * 64,
                          "decision": "approve"})
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "hash_mismatch"


def test_invalid_decision_refuses(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "delete-everything"})
    assert r.status_code == 400
    assert r.get_json()["error"]["code"] == "invalid_decision"


def test_body_approver_field_is_ignored(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "approve", "approver": "attacker"})
    assert r.status_code == 200
    rec = gw.APPROVAL_STORE.get_approval(r.get_json()["approval_id"])
    assert rec.approver == "owner"          # authenticated principal, not the body field


def test_approvals_store_is_in_memory_only(client, owner_token):
    # No persistence: the store exposes no path, and a fresh store (restart) forgets the run.
    from private_ai_gateway.approvals import ApprovalStore

    assert not hasattr(gw.APPROVAL_STORE, "_path")
    run_id, plan_hash = _plan_and_hash(client)
    client.post("/v1/approvals", headers=_owner_hdr(),
                json={"run_id": run_id, "canonical_plan_hash": plan_hash, "decision": "approve"})
    assert ApprovalStore().get_run(run_id) is None


# ---- D2b: execute enforcement (approval-bound; inline approver no longer authorizes) ----
# The full loop on the wire: plan -> owner approve -> execute {run_id, approval_id}. Execute
# recomputes the canonical hash server-side and applies only under a matching, unused,
# non-expired approval. Every failure mode is a governed 200 refusal, not a 4xx/5xx.

def _execute(client, run_id, approval_id, objective=_OBJ):
    return _post(client, objective=objective, phase="execute",
                 run_id=run_id, approval_id=approval_id)


def test_plan_approve_execute_applies_and_verifies(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is True and ex["verdict"] == "PASS"
    assert ex["run_id"] == run_id
    # The full attenuating chain still runs under the durable approval.
    assert {d["depth"] for d in ex["chain"]} == {1, 2}


def test_execute_missing_approval_id_refuses(client):
    run_id, _ = _plan_and_hash(client)
    ex = _execute(client, run_id, "")
    assert ex["applied"] is False and ex["verdict"] == "REFUSED"
    assert ex["refusal_reason"] == "approval_missing"


def test_execute_unknown_approval_id_refuses(client):
    run_id, _ = _plan_and_hash(client)
    ex = _execute(client, run_id, "appr-does-not-exist")
    assert ex["applied"] is False
    assert ex["refusal_reason"] == "approval_missing"


def test_execute_approval_from_a_different_run_refuses(client, owner_token):
    run_a, hash_a = _plan_and_hash(client)
    approval_a = _approve(client, run_a, hash_a)
    run_b, _ = _plan_and_hash(client)          # a second, distinct run
    ex = _execute(client, run_b, approval_a)   # b's run, a's approval
    assert ex["applied"] is False
    assert ex["refusal_reason"] == "run_mismatch"


def test_execute_objective_drift_hash_mismatch_refuses(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    # The objective the browser sends at execute drifts from the approved plan -> the
    # server-recomputed hash no longer matches the run/approval binding.
    ex = _execute(client, run_id, approval_id, objective="a different objective entirely")
    assert ex["applied"] is False
    assert ex["refusal_reason"] == "hash_mismatch"


def test_execute_replay_refuses_on_second_execute(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    first = _execute(client, run_id, approval_id)
    assert first["applied"] is True                      # single-use is consumed here
    second = _execute(client, run_id, approval_id)
    assert second["applied"] is False
    assert second["refusal_reason"] == "replay"


def test_execute_after_rejection_refuses(client, owner_token):
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _reject(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False
    assert ex["refusal_reason"] == "rejected"


def test_execute_expired_approval_refuses(client, owner_token):
    # Expire the approval by rewinding its expiry on the stored record (no approvals.py
    # change): validate_for_execute lazily transitions an approved-but-expired approval.
    from datetime import datetime, timedelta, timezone

    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    rec = gw.APPROVAL_STORE.get_approval(approval_id)
    rec.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False
    assert ex["refusal_reason"] == "expired"


def test_execute_refusal_is_audited_with_run_id(client, owner_token):
    # An approval-gate refusal happens before any sub-request; the handler still records it
    # (deny) tagged with the run_id, through the existing DecisionLog.
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _reject(client, run_id, plan_hash)
    _execute(client, run_id, approval_id)
    recs = [e for e in gw.DECISION_LOG.tail(limit=200)
            if e.get("run_id") == run_id and str(e.get("reason", "")).startswith("execute_refused:")]
    assert recs, "expected an execute-refusal audit record tagged with the run_id"
    assert recs[0]["reason"] == "execute_refused:rejected"


# ---- error-exposure hardening: internal exception text must not reach clients (CWE-209) ----
# CodeQL py/stack-trace-exposure flagged the /v1/orchestrate and /v1/approvals error paths for
# returning str(exc) to the client. These prove the message is now static (codes/status kept)
# and the internal detail is not echoed. The detail still goes to the server log.

_SECRET_DETAIL = "INTERNAL-DETAIL-/etc/secret/path-xyz-42"


def test_orchestrate_unavailable_does_not_echo_exception_text(client, monkeypatch):
    from private_ai_gateway import orchestration

    def _boom(*args, **kwargs):
        raise orchestration.OrchestrationUnavailable(_SECRET_DETAIL)

    monkeypatch.setattr(orchestration, "run_phase", _boom)
    r = client.post("/v1/orchestrate", headers={"Authorization": HERMES},
                    json={"objective": "x", "phase": "plan"})
    assert r.status_code == 503
    body = r.get_json()
    assert body["error"]["code"] == "orchestration_unavailable"           # code preserved
    assert body["error"]["message"] == "Orchestration is temporarily unavailable"  # static
    assert _SECRET_DETAIL not in r.get_data(as_text=True)                  # not echoed


def test_orchestrate_valueerror_does_not_echo_exception_text(client, monkeypatch):
    from private_ai_gateway import orchestration

    def _boom(*args, **kwargs):
        raise ValueError(_SECRET_DETAIL)

    monkeypatch.setattr(orchestration, "run_phase", _boom)
    r = client.post("/v1/orchestrate", headers={"Authorization": HERMES},
                    json={"objective": "x", "phase": "plan"})
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"]["code"] == "invalid_request"                     # code preserved
    assert body["error"]["message"] == "Invalid orchestration request"    # static
    assert _SECRET_DETAIL not in r.get_data(as_text=True)                 # not echoed


def test_approvals_error_does_not_echo_exception_text(client, owner_token, monkeypatch):
    from private_ai_gateway.approvals import ApprovalError

    run_id, plan_hash = _plan_and_hash(client)

    def _boom(*args, **kwargs):
        raise ApprovalError(_SECRET_DETAIL)

    # Reach the ApprovalError handler through the real owner/run/hash checks, then fail the
    # decision step with an internal detail that must not surface to the client.
    monkeypatch.setattr(gw.APPROVAL_STORE, "decide_approval", _boom)
    r = client.post("/v1/approvals", headers=_owner_hdr(),
                    json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                          "decision": "approve", "reason": "reviewed"})
    assert r.status_code == 409
    body = r.get_json()
    assert body["error"]["code"] == "approval_error"                      # code preserved
    assert body["error"]["message"] == "Approval could not be recorded"   # static
    assert _SECRET_DETAIL not in r.get_data(as_text=True)                 # not echoed
