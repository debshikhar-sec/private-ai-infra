"""End-to-end interop: the AgentPeer client, the workers, and the full orchestration.

These run the *real* enforcement plane in-process (the packaged demo policy + demo
backend) via a Flask test client, so a green run proves the governed delegation loop
actually holds — discovery, attenuated hand-off, sub-delegation, verification, and the
refusal of every amplification attempt — not just that the modules import.
"""

import pytest
from hermes import orchestrate
from interop import AgentPeer, PeerError

from private_ai_gateway import app as gw
from private_ai_gateway.demo import TOKENS, install_demo_plane


@pytest.fixture
def peers():
    install_demo_plane(gw)
    client = gw.app.test_client()

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


# ------------------------------------------------------------------ discovery
def test_discovery_is_policy_derived(peers):
    directory = peers["hermes"].discover()
    cards = {c["name"]: c for c in directory["agents"]}
    # Ceilings come from policy, not self-description.
    assert cards["opencode"]["x-governance"]["autonomy_ceiling"] == 3
    assert cards["openclaw"]["x-governance"]["autonomy_ceiling"] == 2
    assert directory["max_delegation_depth"] == 2


def test_find_peer_prefers_least_privilege(peers):
    # Both opencode (L3) and openclaw (L2) advertise assurance.verify; at min L2 the
    # lower-ceiling peer wins — discovery itself follows least-privilege.
    card = peers["hermes"].find_peer("assurance.verify", min_level=2)
    assert card["name"] == "openclaw"
    # Raising the floor past openclaw's ceiling forces the more-privileged executor.
    card = peers["hermes"].find_peer("assurance.verify", min_level=3)
    assert card["name"] == "opencode"


def test_find_peer_none_when_nobody_qualifies(peers):
    assert peers["hermes"].find_peer("no.such.skill") is None


# ------------------------------------------------------------------ worker loop
def test_code_worker_applies_and_sub_delegates(peers):
    from openclaw.worker import AssuranceWorker
    from opencode_sandbox import apply as act
    from opencode_sandbox.worker import CodeActWorker

    root = peers["hermes"].delegate(
        "code.apply", "opencode", level=3, task="apply the reviewed fix"
    )
    worker = CodeActWorker(
        peers["opencode"],
        approval=act.Approval(approver="owner", reason="reviewed", granted=True),
    )
    verifier = AssuranceWorker(peers["openclaw"])

    # Round 1: opencode applies + sub-delegates; nothing to report yet.
    assert worker.poll() == []
    # openclaw verifies its sub-task.
    assert verifier.poll()
    # Round 2: opencode sees the verdict and reports up.
    reported = worker.poll()
    assert reported and reported[0]["status"] == "completed"

    final = peers["hermes"].get_task(root["id"])
    assert final["task"]["status"] == "completed"
    assert final["task"]["verdict"] == "PASS"

    # The sub-task attenuates: querying it shows the full custody chain root->leaf,
    # with authority narrowing L3 (apply) -> L2 (verify).
    sub = peers["opencode"].outbox()[0]
    chain = peers["opencode"].get_task(sub["id"])["chain"]
    assert [d["granted_level"] for d in chain] == [3, 2]
    assert [d["delegatee"] for d in chain] == ["opencode", "openclaw"]


def test_code_worker_reports_failed_without_approval(peers):
    from opencode_sandbox.worker import CodeActWorker

    root = peers["hermes"].delegate("code.apply", "opencode", level=3, task="apply")
    # No approval: the gated engine REFUSES the authority-bearing apply, so the task
    # fails rather than the delegation silently manufacturing authority.
    CodeActWorker(peers["opencode"], approval=None).poll()
    final = peers["hermes"].get_task(root["id"])["task"]
    assert final["status"] == "failed" and final["verdict"] == "REFUSED"


# ------------------------------------------------------------------ refusals on the wire
def test_amplification_refused(peers):
    with pytest.raises(PeerError) as e:
        peers["hermes"].delegate("code.apply", "opencode", level=5)
    assert e.value.code == "autonomy_amplification"


def test_routing_unheld_skill_refused(peers):
    with pytest.raises(PeerError) as e:
        peers["hermes"].delegate("kyc.screening", "kyc-screening-agent", level=1)
    assert e.value.code == "skill_not_delegable"


def test_reporting_on_anothers_task_refused(peers):
    root = peers["hermes"].delegate("code.apply", "opencode", level=3)
    with pytest.raises(PeerError) as e:
        peers["hermes"].report(root["id"], "completed", verdict="FORGED")
    assert e.value.code == "not_task_holder"


# ------------------------------------------------------------------ full driver
def test_orchestrate_run_is_all_green():
    # The whole story — cooperative loop plus every boundary probe — must pass.
    assert orchestrate.run([]) == 0
