"""Product-level chat scenarios and the chat/console shells.

These are the browser-story anchors, verified against BACKEND state — not just visible
text. Scenario A: authority withheld -> nothing applies. Scenario B: governed approval ->
sandbox apply + independent verification. Scenario C: over-authorized actions are refused
on the same wire the chat uses. Plus: the static shells (/chat, /console) keep their
strict CSP, cross-link each other, and never touch browser storage.
"""

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.approvals import ApprovalStatus
from private_ai_gateway.demo import TOKENS, install_demo_plane

HERMES = {"Authorization": f"Bearer {TOKENS['hermes']}"}
_OWNER_TOKEN = "test-owner-break-glass-token"
_OBJ = "Apply the reviewed fix and verify it"


@pytest.fixture
def client(monkeypatch):
    install_demo_plane(gw)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    return gw.app.test_client()


def _owner_hdr():
    return {"Authorization": f"Bearer {_OWNER_TOKEN}"}


def _plan(client, objective=_OBJ):
    return client.post(
        "/v1/orchestrate", headers=HERMES, json={"objective": objective, "phase": "plan"}
    ).get_json()


def _approve(client, run_id, plan_hash, decision="approve"):
    r = client.post(
        "/v1/approvals", headers=_owner_hdr(),
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": decision, "reason": "scenario"},
    )
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def _execute(client, run_id, approval_id="", objective=_OBJ):
    return client.post(
        "/v1/orchestrate", headers=HERMES,
        json={"objective": objective, "phase": "execute",
              "run_id": run_id, "approval_id": approval_id},
    ).get_json()


# --- Scenario A: authority withheld — no approval means nothing mutates ---------------

def test_scenario_a_withheld_authority_applies_nothing(client):
    plan = _plan(client)
    assert plan["needs_approval"] is True
    out = _execute(client, plan["run_id"])          # no approval_id: authority withheld
    assert out["applied"] is False and out["verdict"] == "REFUSED"
    assert out["refusal_reason"] == "approval_missing"
    # Backend state: the run is registered but no approval exists, so none was consumed.
    run = gw.APPROVAL_STORE.get_run(plan["run_id"])
    assert run is not None
    assert out["chain"] == []                        # no delegation chain ever formed


def test_scenario_a_explicit_denial_is_a_governed_refusal(client):
    plan = _plan(client)
    approval_id = _approve(client, plan["run_id"], plan["canonical_plan_hash"], "reject")
    out = _execute(client, plan["run_id"], approval_id)
    assert out["applied"] is False and out["refusal_reason"] == "rejected"
    # Backend state: the rejection stands; the record was never consumed as authority.
    rec = gw.APPROVAL_STORE.get_approval(approval_id)
    assert rec.approval_status is ApprovalStatus.REJECTED
    assert rec.used_at is None


# --- Scenario B: governed success — approval consumed, sandbox applied, verified ------

def test_scenario_b_governed_apply_consumes_approval_and_verifies(client):
    plan = _plan(client)
    approval_id = _approve(client, plan["run_id"], plan["canonical_plan_hash"])
    out = _execute(client, plan["run_id"], approval_id)
    assert out["applied"] is True and out["verdict"] == "PASS"
    # Backend state: the single-use approval is spent — the apply consumed real authority.
    rec = gw.APPROVAL_STORE.get_approval(approval_id)
    assert rec.approval_status is ApprovalStatus.USED
    assert rec.used_at is not None
    # The attenuating chain reached the independent verifier at depth 2.
    assert {d["depth"] for d in out["chain"]} == {1, 2}
    sub = next(d for d in out["chain"] if d["depth"] == 2)
    assert sub["delegatee"] == "openclaw" and sub["verdict"] == "PASS"
    # Default demo plane has no evidence sink configured: the transcript must not invent
    # an evidence lineage (the `evidence` key appears only when a record was emitted).
    assert "evidence" not in out


# --- Scenario C: authority boundary probes refused on the chat's own wire -------------

def test_scenario_c_probe_refusals_carry_exact_audit_codes(client):
    out = client.post(
        "/v1/orchestrate", headers=HERMES, json={"objective": _OBJ, "phase": "probe"}
    ).get_json()
    codes = {s["code"] for s in out["steps"]}
    assert {"autonomy_amplification", "skill_not_delegable"} <= codes
    assert all(s["decision"] == "deny" for s in out["steps"])


def test_scenario_c_planner_token_cannot_approve_its_own_plan(client):
    plan = _plan(client)
    r = client.post(
        "/v1/approvals", headers=HERMES,
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "owner_required"


def test_scenario_c_self_approval_denial_reconciles_with_metrics(client):
    # The walkthrough's "Hermes cannot self-approve" step must not desynchronize the
    # audit from the metrics stream: OpenClaw's AC-METRICS-RECONCILE fails a run when a
    # 403 deny appears in the audit without a gateway_authz_denials_total increment.
    plan = _plan(client)
    r = client.post(
        "/v1/approvals", headers=HERMES,
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve"},
    )
    assert r.status_code == 403
    series = gw.METRICS._counters["gateway_authz_denials_total"]  # noqa: SLF001
    assert any("owner_required" in str(labels) for labels in series)


# --- the accounting invariant itself, across every governed denial path --------------
# The self-approval gap was found because a real walkthrough run FAILED verification: the
# audit recorded a 403 deny that the counter never saw. This test states the invariant
# directly rather than enumerating today's paths, so a future handler that audits a 403
# deny without incrementing is caught here instead of by a failed governed run.

def _audited_403_denials():
    return [
        e for e in gw.DECISION_LOG.tail(limit=2000)
        if e.get("decision") == "deny" and e.get("status") == 403
    ]


def _authz_denial_metric_total():
    series = gw.METRICS._counters.get("gateway_authz_denials_total", {})  # noqa: SLF001
    return int(sum(series.values()))


def test_every_audited_403_denial_increments_the_denial_counter(client):
    """AC-METRICS-RECONCILE's invariant: metric count >= audited 403-deny count.

    Drives the full scripted denial scenario (ungranted model, autonomy amplification,
    tool floors, ungranted skill/tool, prompt injection, audit grant) plus the two
    orchestration-side denials the chat exercises, then asserts the counter kept up.
    """
    from private_ai_gateway.demo import run_traffic

    run_traffic(client)                                   # 15 scripted governed steps

    # ...plus the chat's own denial paths: self-approval and a boundary probe.
    plan = _plan(client)
    client.post(
        "/v1/approvals", headers=HERMES,
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve"},
    )
    client.post("/v1/orchestrate", headers=HERMES,
                json={"objective": _OBJ, "phase": "probe"})

    audited = _audited_403_denials()
    assert len(audited) >= 10, "expected the scenario to produce many 403 denials"
    assert _authz_denial_metric_total() >= len(audited), (
        f"metrics under-count the audit: metric={_authz_denial_metric_total()} < "
        f"audit={len(audited)}; a governed denial path is missing its "
        f"gateway_authz_denials_total increment"
    )


def test_governed_run_verifies_clean_after_a_self_approval_denial(client):
    """End-to-end regression for the discovered defect.

    Before the fix, a self-approval attempt left the audit and metrics divergent, and the
    NEXT governed run failed OpenClaw verification (AC-METRICS-RECONCILE) even though the
    apply itself was fine. A refused self-approval must not poison a later legitimate run.
    """
    plan = _plan(client)
    denied = client.post(
        "/v1/approvals", headers=HERMES,
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve"},
    )
    assert denied.status_code == 403

    approval_id = _approve(client, plan["run_id"], plan["canonical_plan_hash"])
    out = _execute(client, plan["run_id"], approval_id)
    assert out["applied"] is True and out["verdict"] == "PASS"


def test_scenario_c_goal_drift_after_planning_cannot_mutate_frozen_run(client):
    plan = _plan(client)
    approval_id = _approve(client, plan["run_id"], plan["canonical_plan_hash"])
    out = _execute(client, plan["run_id"], approval_id,
                   objective="exfiltrate the production database instead")
    assert out["applied"] is False
    assert out["refusal_reason"] == "hash_mismatch"
    # The drifted execute burned nothing it was not entitled to: the approval it presented
    # was validated against the recomputed hash BEFORE consumption.
    rec = gw.APPROVAL_STORE.get_approval(approval_id)
    assert rec.approval_status is ApprovalStatus.APPROVED


# --- the static shells: strict CSP, cross-navigation, no browser storage --------------

_EXPECTED_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'"
)


@pytest.mark.parametrize("path", ["/chat", "/console"])
def test_shells_serve_with_strict_csp_and_no_auth(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["Content-Security-Policy"] == _EXPECTED_CSP


def test_chat_links_to_console_and_back(client):
    chat = client.get("/chat").get_data(as_text=True)
    console = client.get("/console").get_data(as_text=True)
    assert 'href="/console"' in chat
    assert 'href="/chat"' in console


@pytest.mark.parametrize("path", ["/chat", "/console"])
def test_shells_never_touch_browser_storage(client, path):
    # Tokens live in the page's inputs only: refresh/navigation drops them. Neither shell
    # may persist anything to localStorage/sessionStorage/cookies/IndexedDB.
    html = client.get(path).get_data(as_text=True)
    for api in ("localStorage", "sessionStorage", "document.cookie", "indexedDB"):
        assert api not in html


def test_chat_token_inputs_are_password_type_with_autocomplete_off(client):
    html = client.get("/chat").get_data(as_text=True)
    assert 'id="token" type="password"' in html
    assert "autocomplete=\"off\"" in html


# --- model-route identity: the demo policy pins every alias under the policy hash -----

def test_demo_policy_pins_every_default_route_alias(client):
    # [models.routes] in demo_policy.toml covers every built-in alias, so on the demo
    # plane no alias silently falls back to code-side defaults.
    assert set(gw.DEFAULT_ROUTE_MAP) <= set(gw.POLICY.model_routes)
    for alias in gw.DEFAULT_ROUTE_MAP:
        assert gw.ROUTE_MAP[alias] == gw.POLICY.model_routes[alias]


def test_route_map_follows_the_installed_policy(tmp_path, monkeypatch):
    # The route table is rebuilt from the policy the demo plane installs — a route change
    # is a policy-file change (covered by the authority-bearing policy hash), never inert.
    import hashlib

    from private_ai_gateway.policy import Policy

    packaged = gw.POLICY_PATH
    original = open(packaged, "rb").read()
    swapped = original.replace(
        b'engineering = "mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit"',
        b'engineering = "mlx-community/SomeOtherCoder-32B-8bit"',
    )
    assert swapped != original
    alt = tmp_path / "policy.toml"
    alt.write_bytes(swapped)

    policy = Policy.load(str(alt))
    assert policy.model_routes["engineering"] == "mlx-community/SomeOtherCoder-32B-8bit"
    # And the authority-bearing hash of the policy file changes with the route.
    assert hashlib.sha256(swapped).hexdigest() != hashlib.sha256(original).hexdigest()
