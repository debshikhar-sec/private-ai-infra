"""Governed Chat Console: the phased session and the /v1/orchestrate endpoint.

Runs the real enforcement plane in-process (packaged demo policy + demo backend). A green
run proves the chat drives the *actual* governed loop — Hermes plans and proposes but does
not execute, the apply refuses unless a human approves, and the boundary probes are refused
with their exact audit codes.
"""

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


def test_endpoint_execute_approved_vs_refused(client):
    approved = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": "Apply the reviewed fix and verify it", "phase": "execute",
              "approver": "owner", "reason": "reviewed"},
    ).get_json()
    assert approved["applied"] is True and approved["verdict"] == "PASS"

    refused = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": "Apply the reviewed fix and verify it", "phase": "execute"},
    ).get_json()
    assert refused["applied"] is False and refused["verdict"] == "REFUSED"


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
