"""Autonomous governed orchestration: Hermes plans, delegates, and verifies via peers.

One command runs the whole loop offline, through the *real* enforcement plane:

  1. **Understand** — Hermes reads the A2A agent directory (policy-derived cards, not
     self-descriptions) and learns who exists, what skills they hold, and the autonomy
     ceiling policy actually enforces on each.
  2. **Plan** — a governed model call under Hermes' own principal (L1: it may suggest
     and route, never execute).
  3. **Delegate** — the ``code.apply`` step goes to whichever peer's card offers it at
     the lowest sufficient ceiling. No agent name is hardcoded anywhere in the loop.
  4. **Execute & sub-delegate** — OpenCode applies the change in a confined sandbox
     (still approval-gated) and sub-delegates ``assurance.verify`` inside its own
     grant; OpenClaw verifies from gateway evidence and reports PASS/FAIL.
  5. **Probe** — the same wire is then abused on purpose: amplification, routing an
     unheld skill, over-deep chains, and reporting on someone else's task must all be
     refused with the exact audit codes.

Usage (offline, deterministic, in-process demo plane):
    PYTHONPATH=src:agents python -m hermes.orchestrate

Against a running gateway loaded with the demo policy (``private-ai-gateway demo``):
    PYTHONPATH=src:agents python -m hermes.orchestrate --base-url http://127.0.0.1:8080

Exit code 0 only if every cooperative step *and* every expected refusal behaved
exactly as policy demands.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from interop import AgentPeer, PeerError

from hermes import planner

PLAN_MODEL = "strategy"
EXEC_SKILL = "code.apply"
EXEC_LEVEL = 3  # sandbox apply is owner-initiated execution (L3)
MAX_ROUNDS = 10


@dataclass
class Expectation:
    """One step of the story and whether reality matched it."""

    actor: str
    story: str
    outcome: str
    ok: bool


def _in_process_senders():
    """Spin the packaged demo plane in-process; return (send_factory, tokens)."""
    from private_ai_gateway import app as gw
    from private_ai_gateway.demo import TOKENS, install_demo_plane

    install_demo_plane(gw)
    client = gw.app.test_client()

    def factory(token: str):
        def send(method: str, path: str, body: dict | None = None):
            resp = getattr(client, method.lower())(
                path, headers={"Authorization": f"Bearer {token}"}, json=body
            )
            payload = resp.get_json(silent=True)
            if payload is None:
                payload = resp.get_data(as_text=True)
            return resp.status_code, payload

        return send

    return factory, TOKENS


def _http_peers(base_url: str):
    from private_ai_gateway.demo import TOKENS

    return {name: AgentPeer(base_url, token) for name, token in TOKENS.items()}


def _expect_refusal(fn, *, code: str) -> tuple[str, bool]:
    """Run a delegation that MUST be refused; return (outcome text, matched)."""
    try:
        record = fn()
    except PeerError as exc:
        return f"{exc.status} {exc.code}", exc.code == code
    return f"{record.get('id', 'accepted')} (NOT refused)", False


def run(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="hermes.orchestrate",
        description="Governed autonomous delegation across Hermes/OpenCode/OpenClaw",
    )
    p.add_argument(
        "--objective",
        default="Apply the reviewed fix under governed delegation and verify it",
    )
    p.add_argument("--base-url", help="Run against a live gateway instead of in-process")
    p.add_argument(
        "--approve",
        default="owner:reviewed the proposal diff; approved for sandbox apply",
        help="APPROVER:REASON for the act step ('' to demonstrate the refused path)",
    )
    p.add_argument("--rounds", type=int, default=MAX_ROUNDS)
    args = p.parse_args(argv)

    from openclaw.worker import AssuranceWorker
    from opencode_sandbox import apply as act
    from opencode_sandbox.worker import CodeActWorker

    # -- wire up: one peer per principal, same enforcement path either way --------
    if args.base_url:
        peers = _http_peers(args.base_url)
    else:
        factory, tokens = _in_process_senders()
        peers = {name: AgentPeer(send=factory(token)) for name, token in tokens.items()}

    hermes = peers["hermes"]
    expectations: list[Expectation] = []

    def note(actor: str, story: str, outcome: str, ok: bool) -> None:
        expectations.append(Expectation(actor, story, outcome, ok))

    # -- 1. understand: read the policy-derived agent directory --------------------
    directory = hermes.discover()
    cards = {c["name"]: c for c in directory.get("agents", [])}
    print("Agent directory (from enforced policy, not self-description):")
    for name, card in sorted(cards.items()):
        gov = card.get("x-governance", {})
        skills = ", ".join(s["id"] for s in card.get("skills", [])) or "(none)"
        print(f"  {name:<22} L{gov.get('autonomy_ceiling')} "
              f"({gov.get('autonomy_ceiling_name')})  skills: {skills}")
    print(f"  max delegation depth: {directory.get('max_delegation_depth')}\n")

    # -- 2. plan: a governed L1 model call under Hermes' own principal -------------
    try:
        plan_text = hermes.complete(PLAN_MODEL, f"plan: {args.objective}")
        plan = planner.parse_plan(plan_text)
        note("hermes", "plans within its L1 ceiling (governed model call)",
             f"phase={plan.get('PHASE') or '?'}", bool(plan.get("SAFE NEXT ACTION")))
    except PeerError as exc:
        note("hermes", "plans within its L1 ceiling (governed model call)",
             f"{exc.status} {exc.code}", False)

    # -- 3. delegate: match the step to a peer by card, least privilege first ------
    executor_card = hermes.find_peer(EXEC_SKILL, min_level=EXEC_LEVEL, exclude=("hermes",))
    if executor_card is None:
        print("No peer advertises code.apply at a sufficient ceiling; aborting.")
        return 1
    executor = executor_card["name"]
    note("hermes", f"discovers '{executor}' via its card for {EXEC_SKILL}",
         f"ceiling=L{executor_card['x-governance']['autonomy_ceiling']}", True)

    try:
        root = hermes.delegate(
            EXEC_SKILL, executor, level=EXEC_LEVEL,
            task=f"{args.objective} (confined sandbox apply; do not commit)",
        )
        note("hermes", f"delegates {EXEC_SKILL}@L{EXEC_LEVEL} -> {executor}",
             f"{root['id']} depth={root['depth']}", root["depth"] == 1)
    except PeerError as exc:
        note("hermes", f"delegates {EXEC_SKILL}@L{EXEC_LEVEL} -> {executor}",
             f"{exc.status} {exc.code}", False)
        print(_summary(expectations))
        return 1

    # -- 4. autonomous execution rounds --------------------------------------------
    approval = None
    if args.approve:
        approver, _, reason = args.approve.partition(":")
        approval = act.Approval(approver=approver.strip(), reason=reason.strip(),
                                granted=True)
    code_worker = CodeActWorker(peers[executor], approval=approval)
    verify_workers = [
        AssuranceWorker(peers[name])
        for name, card in cards.items()
        if name != executor and any(s["id"] == "assurance.verify"
                                    for s in card.get("skills", []))
        and name in peers
    ]

    final = root
    for _ in range(max(1, args.rounds)):
        code_worker.poll()
        for worker in verify_workers:
            worker.poll()
        final = hermes.get_task(root["id"]).get("task", {})
        if final.get("status") != "submitted":
            break

    # The full chain: the root plus whatever the executor sub-delegated under it.
    chain = [final] + [
        d
        for t in peers[executor].outbox()
        for d in [peers[executor].get_task(t["id"]).get("task", {})]
        if d.get("parent_id") == root["id"]
    ]
    note(executor, "applies in a confined sandbox, then sub-delegates verification",
         f"status={final.get('status')} verdict={final.get('verdict')}",
         final.get("status") == "completed" and final.get("verdict") == "PASS")
    sub = next((d for d in chain if d.get("depth") == 2), None)
    if sub:
        note(sub["delegatee"], "verifies from gateway evidence and reports up the chain",
             f"{sub['status']} {sub['verdict']} (depth 2, L{sub['granted_level']})",
             sub["status"] == "completed" and sub["granted_level"] <= 2)

    # -- 5. boundary probes: the same wire, abused on purpose ----------------------
    outcome, ok = _expect_refusal(
        lambda: hermes.delegate(EXEC_SKILL, executor, level=5, task="probe"),
        code="autonomy_amplification",
    )
    note("hermes", f"asks {executor} to run at L5 — above its enforced ceiling",
         outcome, ok)

    outcome, ok = _expect_refusal(
        lambda: hermes.delegate("payments.initiate", executor, level=1, task="probe"),
        code="skill_not_delegable",
    )
    note("hermes", "routes payments.initiate — a skill it was never granted",
         outcome, ok)

    # A probe chain for depth/custody refusals, then cleaned up.
    verifier = sub["delegatee"] if sub else "openclaw"
    probe_root = hermes.delegate(EXEC_SKILL, executor, level=EXEC_LEVEL,
                                 task="probe chain")
    probe_sub = peers[executor].delegate("assurance.verify", verifier, level=2,
                                         parent=probe_root["id"], task="probe chain")
    outcome, ok = _expect_refusal(
        lambda: peers[verifier].delegate("assurance.verify", executor, level=2,
                                         parent=probe_sub["id"], task="third link"),
        code="delegation_too_deep",
    )
    note(verifier, "grows the chain past the policy depth limit", outcome, ok)

    outcome, ok = _expect_refusal(
        lambda: peers[executor].report(probe_sub["id"], "completed", verdict="FORGED"),
        code="not_task_holder",
    )
    note(executor, "tries to answer for the verifier's task", outcome, ok)

    peers[verifier].report(probe_sub["id"], "completed", result="probe chain closed",
                           verdict="PROBE")
    peers[executor].report(probe_root["id"], "completed", result="probe chain closed",
                           verdict="PROBE")

    # -- 6. evidence: the audit saw every hop ---------------------------------------
    auditors = [n for n, c in cards.items()
                if n in peers
                and (c.get("x-governance") or {}).get("can_read_audit")]
    audit_note = "(no auditor principal available)"
    if auditors:
        events = peers[auditors[0]].decisions(limit=200)
        delegations = [e for e in events if str(e.get("reason", "")).startswith(
            ("delegate:", "task_result:"))]
        denials = [e for e in events if e.get("decision") == "deny"]
        audit_note = (f"{len(delegations)} delegation events, "
                      f"{len(denials)} denials in the audit tail")
        note(auditors[0], "replays the whole chain from the decision audit",
             audit_note, len(delegations) >= 6)

    print(_chain_view(chain))
    print(_summary(expectations))
    return 0 if all(e.ok for e in expectations) else 1


def _chain_view(chain: list[dict]) -> str:
    lines = ["Delegation chain (authority attenuates, never amplifies):"]
    for d in chain:
        pad = "  " * d["depth"]
        lines.append(
            f"{pad}{d['delegator']} -> {d['delegatee']}  {d['skill']}@L{d['granted_level']}"
            f"  [{d['status']}{' ' + d['verdict'] if d['verdict'] else ''}]  {d['id']}"
        )
    return "\n".join(lines) + "\n"


def _summary(expectations: list[Expectation]) -> str:
    lines = ["Orchestration story — every line enforced on the wire, not narrated:", ""]
    for e in expectations:
        mark = "PASS" if e.ok else "FAIL"
        lines.append(f"  [{mark}] {e.actor:<12} {e.story:<62} -> {e.outcome}")
    good = sum(1 for e in expectations if e.ok)
    lines += ["", f"  {good}/{len(expectations)} steps behaved exactly as policy demands."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except PeerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
