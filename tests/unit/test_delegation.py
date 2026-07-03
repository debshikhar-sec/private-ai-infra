"""Delegation governance: attenuation, custody, depth, and lifecycle.

Two layers under test. The ledger unit tests pin the *semantics* (chains narrow, only
holders sub-delegate, only delegatees report). The endpoint tests pin the *wire
behaviour*: what a cooperating — or misbehaving — agent actually sees.
"""

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.delegation import (
    COMPLETED,
    SUBMITTED,
    DelegationError,
    DelegationLedger,
)
from private_ai_gateway.policy import Policy, Principal, hash_token
from private_ai_gateway.ratelimit import RateLimiter

# The orchestration cast, as plain principals: a planner that can only route (L1),
# an executor (L3), and a verifier (L2).
PLANNER = Principal(
    "planner", frozenset({"strategy"}), max_autonomy_level=1,
    allowed_skills=frozenset({"plan.compose", "code.apply", "assurance.verify"}),
)
EXECUTOR = Principal(
    "executor", frozenset({"strategy"}), max_autonomy_level=3,
    allowed_skills=frozenset({"code.apply", "assurance.verify"}),
)
VERIFIER = Principal(
    "verifier", frozenset(), max_autonomy_level=2,
    allowed_skills=frozenset({"assurance.verify"}), can_read_audit=True,
)
OUTSIDER = Principal(
    "outsider", frozenset(), max_autonomy_level=1,
    allowed_skills=frozenset({"trade.draft"}),
)


# --------------------------------------------------------------------------- ledger
def _create(ledger, **kw):
    defaults = dict(
        delegator=PLANNER, delegatee=EXECUTOR, skill="code.apply",
        requested_level=3, delegatee_ceiling=3,
    )
    defaults.update(kw)
    return ledger.create(**defaults)


def test_create_records_grant_and_depth():
    d = _create(DelegationLedger(), task="apply the reviewed fix")
    assert d.delegator == "planner" and d.delegatee == "executor"
    assert d.granted_level == 3 and d.depth == 1 and d.status == SUBMITTED
    assert d.task == "apply the reviewed fix"


def test_low_autonomy_planner_may_route_higher_level_work():
    # The heart of the two-axis model: an L1 planner routes an L3 task because the
    # *executor's own policy* grants L3 — the planner never held that authority.
    d = _create(DelegationLedger())
    assert d.granted_level == 3


def test_self_delegation_refused():
    with pytest.raises(DelegationError) as e:
        _create(DelegationLedger(), delegatee=PLANNER)
    assert e.value.code == "self_delegation" and e.value.status == 400


def test_delegator_cannot_route_a_skill_it_does_not_hold():
    with pytest.raises(DelegationError) as e:
        _create(DelegationLedger(), delegator=OUTSIDER)
    assert e.value.code == "skill_not_delegable"


def test_delegatee_must_hold_the_skill():
    with pytest.raises(DelegationError) as e:
        _create(DelegationLedger(), delegatee=OUTSIDER, delegatee_ceiling=1)
    assert e.value.code == "skill_not_allowed"


def test_request_above_delegatee_ceiling_is_amplification():
    with pytest.raises(DelegationError) as e:
        _create(DelegationLedger(), requested_level=5)
    assert e.value.code == "autonomy_amplification"


def test_only_the_task_holder_may_sub_delegate():
    ledger = DelegationLedger()
    root = _create(ledger)
    with pytest.raises(DelegationError) as e:
        ledger.create(
            delegator=PLANNER, delegatee=VERIFIER, skill="assurance.verify",
            requested_level=2, delegatee_ceiling=2, parent_id=root.id,
        )
    assert e.value.code == "not_task_holder"


def test_sub_delegation_cannot_widen_the_parent_grant():
    ledger = DelegationLedger()
    root = _create(ledger, requested_level=2)  # parent grant is L2
    with pytest.raises(DelegationError) as e:
        ledger.create(
            delegator=EXECUTOR, delegatee=VERIFIER, skill="assurance.verify",
            requested_level=3, delegatee_ceiling=3, parent_id=root.id,
        )
    assert e.value.code == "delegation_widening"


def test_depth_limit_enforced():
    ledger = DelegationLedger()
    root = _create(ledger)
    with pytest.raises(DelegationError) as e:
        ledger.create(
            delegator=EXECUTOR, delegatee=VERIFIER, skill="assurance.verify",
            requested_level=2, delegatee_ceiling=2, parent_id=root.id, max_depth=1,
        )
    assert e.value.code == "delegation_too_deep"


def test_completed_parent_cannot_be_sub_delegated():
    ledger = DelegationLedger()
    root = _create(ledger)
    ledger.report(root.id, reporter="executor", status=COMPLETED, result="done")
    with pytest.raises(DelegationError) as e:
        ledger.create(
            delegator=EXECUTOR, delegatee=VERIFIER, skill="assurance.verify",
            requested_level=2, delegatee_ceiling=2, parent_id=root.id,
        )
    assert e.value.code == "parent_not_active" and e.value.status == 409


def test_unknown_parent_404():
    with pytest.raises(DelegationError) as e:
        _create(DelegationLedger(), parent_id="dg-missing")
    assert e.value.code == "unknown_parent_task" and e.value.status == 404


def test_only_the_delegatee_reports_and_only_once():
    ledger = DelegationLedger()
    d = _create(ledger)
    with pytest.raises(DelegationError) as e:
        ledger.report(d.id, reporter="planner", status=COMPLETED)
    assert e.value.code == "not_task_holder"

    done = ledger.report(d.id, reporter="executor", status=COMPLETED, verdict="PASS")
    assert done.status == COMPLETED and done.verdict == "PASS"

    with pytest.raises(DelegationError) as e:
        ledger.report(d.id, reporter="executor", status=COMPLETED)
    assert e.value.code == "already_reported" and e.value.status == 409


def test_report_status_must_be_terminal():
    ledger = DelegationLedger()
    d = _create(ledger)
    with pytest.raises(DelegationError) as e:
        ledger.report(d.id, reporter="executor", status="in_progress")
    assert e.value.code == "invalid_status" and e.value.status == 400


def test_chain_runs_root_to_leaf():
    ledger = DelegationLedger()
    root = _create(ledger)
    sub = ledger.create(
        delegator=EXECUTOR, delegatee=VERIFIER, skill="assurance.verify",
        requested_level=2, delegatee_ceiling=2, parent_id=root.id,
    )
    assert [d.id for d in ledger.chain(sub.id)] == [root.id, sub.id]
    assert sub.depth == 2


def test_inbox_and_outbox_views():
    ledger = DelegationLedger()
    d = _create(ledger)
    assert [x.id for x in ledger.for_principal("executor")] == [d.id]
    assert [x.id for x in ledger.for_principal("planner", role="delegator")] == [d.id]
    assert ledger.for_principal("executor", status=COMPLETED) == []


# ------------------------------------------------------------------------- endpoints
KEYS = {"planner": "key-planner", "executor": "key-executor",
        "verifier": "key-verifier", "outsider": "key-outsider"}


@pytest.fixture
def client(monkeypatch):
    pol = Policy(
        {hash_token(KEYS[p.name]): p for p in (PLANNER, EXECUTOR, VERIFIER, OUTSIDER)},
        max_delegation_depth=2,
    )
    monkeypatch.setattr(gw, "POLICY", pol)
    monkeypatch.setattr(gw, "AUTH_TOKEN", "")
    monkeypatch.setattr(gw, "RATE_LIMITER", RateLimiter(0))
    monkeypatch.setattr(gw, "DELEGATIONS", gw.delegation.DelegationLedger())
    return gw.app.test_client()


def _hdr(name):
    return {"Authorization": f"Bearer {KEYS[name]}"}


def _delegate(client, who, **body):
    return client.post("/a2a/tasks", json=body, headers=_hdr(who))


def test_agent_directory_lists_policy_cards(client):
    r = client.get("/a2a/agents", headers=_hdr("planner"))
    assert r.status_code == 200
    body = r.get_json()
    names = [a["name"] for a in body["agents"]]
    assert names == sorted(names) and "executor" in names and "verifier" in names
    executor = next(a for a in body["agents"] if a["name"] == "executor")
    assert executor["x-governance"]["autonomy_ceiling"] == 3
    assert {s["id"] for s in executor["skills"]} == {"assurance.verify", "code.apply"}
    assert body["max_delegation_depth"] == 2


def test_delegation_endpoint_grants_and_audits(client):
    r = _delegate(client, "planner", skill="code.apply", delegatee="executor",
                  autonomy_level="L3", task="apply the fix")
    assert r.status_code == 202
    body = r.get_json()
    assert body["delegator"] == "planner" and body["delegatee"] == "executor"
    assert body["granted_level"] == 3 and body["depth"] == 1
    assert body["granted_autonomy_name"] == "owner_run"


def test_unknown_delegatee_404(client):
    r = _delegate(client, "planner", skill="code.apply", delegatee="ghost")
    assert r.status_code == 404
    assert r.get_json()["error"]["code"] == "unknown_delegatee"


def test_amplification_denied_on_the_wire(client):
    r = _delegate(client, "planner", skill="code.apply", delegatee="executor",
                  autonomy_level="L5")
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "autonomy_amplification"


def test_full_chain_with_sub_delegation_and_results(client):
    root = _delegate(client, "planner", skill="code.apply", delegatee="executor",
                     autonomy_level="L3").get_json()

    # Executor sees the task in its inbox …
    inbox = client.get("/a2a/tasks", headers=_hdr("executor")).get_json()["tasks"]
    assert [t["id"] for t in inbox] == [root["id"]]

    # … sub-delegates verification to the verifier (narrower level, depth 2) …
    sub = _delegate(client, "executor", skill="assurance.verify", delegatee="verifier",
                    autonomy_level="L2", parent_task=root["id"])
    assert sub.status_code == 202
    sub = sub.get_json()
    assert sub["depth"] == 2

    # … a third link would exceed the policy depth of 2.
    deeper = _delegate(client, "verifier", skill="assurance.verify",
                       delegatee="executor", autonomy_level="L2",
                       parent_task=sub["id"])
    assert deeper.status_code == 403
    assert deeper.get_json()["error"]["code"] == "delegation_too_deep"

    # Verifier reports; executor reports; the chain is inspectable by participants.
    r = client.post(f"/a2a/tasks/{sub['id']}/result",
                    json={"status": "completed", "verdict": "PASS"},
                    headers=_hdr("verifier"))
    assert r.status_code == 200 and r.get_json()["verdict"] == "PASS"

    r = client.post(f"/a2a/tasks/{root['id']}/result",
                    json={"status": "completed", "result": "applied + verified"},
                    headers=_hdr("executor"))
    assert r.status_code == 200

    chain = client.get(f"/a2a/tasks/{sub['id']}", headers=_hdr("planner")).get_json()
    assert [d["id"] for d in chain["chain"]] == [root["id"], sub["id"]]


def test_only_delegatee_may_report_on_the_wire(client):
    root = _delegate(client, "planner", skill="code.apply",
                     delegatee="executor", autonomy_level="L3").get_json()
    r = client.post(f"/a2a/tasks/{root['id']}/result",
                    json={"status": "completed"}, headers=_hdr("planner"))
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "not_task_holder"


def test_outsider_cannot_view_or_list_others_tasks(client):
    root = _delegate(client, "planner", skill="code.apply",
                     delegatee="executor", autonomy_level="L3").get_json()

    r = client.get(f"/a2a/tasks/{root['id']}", headers=_hdr("outsider"))
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "not_task_participant"

    r = client.get("/a2a/tasks?all=true", headers=_hdr("outsider"))
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "audit_not_allowed"

    # The verifier holds can_read_audit, so the governance-wide view is granted.
    r = client.get("/a2a/tasks?all=true", headers=_hdr("verifier"))
    assert r.status_code == 200
    assert [t["id"] for t in r.get_json()["tasks"]] == [root["id"]]


def test_unknown_task_404(client):
    assert client.get("/a2a/tasks/dg-nope", headers=_hdr("planner")).status_code == 404


# ---------------------------------------------------------------- expiry (GAD/1.1)
def _expire(monkeypatch, offset: float):
    """Shift the ledger's clock forward so lazily-checked expiries fire."""
    import time as _time

    real = _time.time()
    monkeypatch.setattr(
        "private_ai_gateway.delegation.time.time", lambda: real + offset
    )


def test_expired_task_loses_authority_lazily(monkeypatch):
    ledger = DelegationLedger()
    d = _create(ledger, ttl_seconds=60)
    assert d.expires_at is not None and ledger.get(d.id).status == SUBMITTED
    _expire(monkeypatch, 61)
    assert ledger.get(d.id).status == "expired"


def test_expired_task_cannot_be_reported(monkeypatch):
    ledger = DelegationLedger()
    d = _create(ledger, ttl_seconds=60)
    _expire(monkeypatch, 61)
    with pytest.raises(DelegationError) as err:
        ledger.report(d.id, reporter="executor", status=COMPLETED)
    assert err.value.code == "task_expired" and err.value.status == 409


def test_expired_parent_cannot_be_subdelegated(monkeypatch):
    ledger = DelegationLedger()
    root = _create(ledger, ttl_seconds=60)
    _expire(monkeypatch, 61)
    with pytest.raises(DelegationError) as err:
        _create(
            ledger, delegator=EXECUTOR, delegatee=VERIFIER,
            skill="assurance.verify", requested_level=2, delegatee_ceiling=2,
            parent_id=root.id,
        )
    assert err.value.code == "parent_not_active"


def test_subdelegation_cannot_outlive_parent_grant():
    # Time narrows like authority: the child inherits the tighter bound.
    ledger = DelegationLedger()
    root = _create(ledger, ttl_seconds=60)
    child = _create(
        ledger, delegator=EXECUTOR, delegatee=VERIFIER,
        skill="assurance.verify", requested_level=2, delegatee_ceiling=2,
        parent_id=root.id, ttl_seconds=3600,
    )
    assert child.expires_at <= root.expires_at


def test_no_ttl_means_no_time_bound():
    d = _create(DelegationLedger())
    assert d.expires_at is None and d.to_dict()["expires_at"] is None


def test_expiry_enforced_on_the_wire(client, monkeypatch):
    monkeypatch.setattr(gw.POLICY, "delegation_ttl_seconds", 60, raising=False)
    root = _delegate(client, "planner", skill="code.apply",
                     delegatee="executor", autonomy_level="L3").get_json()
    assert root["expires_at"] is not None
    _expire(monkeypatch, 61)
    r = client.post(f"/a2a/tasks/{root['id']}/result",
                    json={"status": "completed"}, headers=_hdr("executor"))
    assert r.status_code == 409
    assert r.get_json()["error"]["code"] == "task_expired"
    r = client.get(f"/a2a/tasks/{root['id']}", headers=_hdr("planner"))
    assert r.get_json()["task"]["status"] == "expired"
