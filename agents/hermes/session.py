"""Governed orchestration as a phased, transcript-producing session.

The same enforcement path as :mod:`hermes.orchestrate`, but split so a *human* can
drive it a step at a time — the data model behind the Governed Chat Console:

  * :meth:`GovernedSession.plan` — Hermes reads the policy-derived agent directory and
    makes a governed L1 model call, then *proposes* the delegation it would make. It
    executes nothing; authority stays with the human.
  * :meth:`GovernedSession.execute` — only after the human supplies an approval does the
    ``code.apply`` step delegate to the least-privileged capable peer, apply in a
    confined sandbox, and sub-delegate ``assurance.verify``. Without the approval the
    apply is refused, and that refusal is reported, not hidden.
  * :meth:`GovernedSession.probe` — the same wire abused on purpose (amplification,
    an unheld skill), each refused with the exact audit code.

Every ``Step`` below is a real decision the gateway returned on the wire. Nothing here
narrates an outcome it did not actually get — a governed chat, not a scripted one.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from interop import AgentPeer, PeerError

from hermes import planner

PLAN_MODEL = "strategy"
EXEC_SKILL = "code.apply"
EXEC_LEVEL = 3  # a sandbox apply is owner-initiated execution (L3)
VERIFY_SKILL = "assurance.verify"
MAX_ROUNDS = 10


@dataclass
class Step:
    """One line of the governed transcript, as it happened on the wire."""

    actor: str
    action: str
    detail: str = ""
    level: int | None = None
    decision: str = "allow"  # "allow" | "deny"
    code: str = ""            # gateway audit/error code when decision == "deny"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in ("", None)}


@dataclass
class _Result:
    phase: str
    steps: list[Step] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def add(self, step: Step) -> Step:
        self.steps.append(step)
        return step

    def to_dict(self) -> dict:
        out = {"phase": self.phase, "steps": [s.to_dict() for s in self.steps]}
        out.update(self.extra)
        return out


class OrchestrationUnavailable(RuntimeError):
    """The demo plane / peers required to orchestrate are not present."""


class GovernedSession:
    """A human-driven pass over the real governed delegation loop.

    ``peers`` maps principal name -> :class:`interop.AgentPeer`. The session never picks
    an executor by name; it discovers one from the enforced agent directory.
    """

    def __init__(self, peers: dict[str, AgentPeer], objective: str, run_id: str = ""):
        if "hermes" not in peers:
            raise OrchestrationUnavailable("no 'hermes' principal available to plan")
        self.peers = peers
        self.objective = objective.strip()
        self.hermes = peers["hermes"]
        # Correlation id for the whole goal->plan->approve->apply->verify loop. Minted by
        # the caller (the server, on plan); echoed on every phase result. Not yet enforced.
        self.run_id = run_id

    # -- phase 1: understand + plan + propose (no execution) ----------------------

    def plan(self) -> dict:
        r = _Result("plan")
        r.extra["run_id"] = self.run_id
        directory = self.hermes.discover()
        cards = {c["name"]: c for c in directory.get("agents", [])}
        depth = directory.get("max_delegation_depth")
        r.add(Step(
            "hermes", "reads the enforced agent directory",
            f"{len(cards)} agents; max delegation depth {depth}",
        ))

        # A governed L1 model call under Hermes' own principal.
        try:
            plan_text = self.hermes.complete(PLAN_MODEL, f"plan: {self.objective}")
            plan = planner.parse_plan(plan_text)
            phase = plan.get("PHASE") or "?"
            nxt = plan.get("SAFE NEXT ACTION") or "(none)"
            r.add(Step("hermes", "plans within its L1 ceiling (governed model call)",
                       f"phase={phase}; next={nxt}", level=1))
        except PeerError as exc:
            r.add(Step("hermes", "plans within its L1 ceiling (governed model call)",
                       exc.status and f"{exc.status}" or str(exc),
                       level=1, decision="deny", code=exc.code))
            r.extra["needs_approval"] = False
            return r.to_dict()

        # Discover — do not name — the executor for the apply step.
        card = self.hermes.find_peer(EXEC_SKILL, min_level=EXEC_LEVEL, exclude=("hermes",))
        if card is None:
            r.add(Step("hermes", f"finds no peer offering {EXEC_SKILL} at L{EXEC_LEVEL}",
                       "cannot proceed", decision="deny", code="no_capable_peer"))
            r.extra["needs_approval"] = False
            return r.to_dict()

        executor = card["name"]
        ceiling = (card.get("x-governance") or {}).get("autonomy_ceiling")
        r.add(Step("hermes", f"discovers '{executor}' via its card for {EXEC_SKILL}",
                   f"enforced ceiling L{ceiling}", level=EXEC_LEVEL))
        r.extra["proposal"] = {
            "executor": executor, "skill": EXEC_SKILL, "level": EXEC_LEVEL,
            "objective": self.objective,
        }
        r.extra["needs_approval"] = True
        return r.to_dict()

    # -- phase 2: execute, but only under a human approval ------------------------

    def execute(self, approver: str = "", reason: str = "", *, execute_ref=None) -> dict:
        from openclaw.worker import AssuranceWorker
        from opencode_sandbox import apply as act
        from opencode_sandbox.worker import CodeActWorker

        r = _Result("execute")
        r.extra["run_id"] = self.run_id
        card = self.hermes.find_peer(EXEC_SKILL, min_level=EXEC_LEVEL, exclude=("hermes",))
        if card is None:
            raise OrchestrationUnavailable("no peer offers code.apply")
        executor = card["name"]

        try:
            root = self.hermes.delegate(
                EXEC_SKILL, executor, level=EXEC_LEVEL,
                task=f"{self.objective} (confined sandbox apply; do not commit)",
            )
        except PeerError as exc:
            r.add(Step("hermes", f"delegates {EXEC_SKILL}@L{EXEC_LEVEL} -> {executor}",
                       f"{exc.status}", level=EXEC_LEVEL, decision="deny", code=exc.code))
            return r.to_dict()
        r.add(Step("hermes", f"delegates {EXEC_SKILL}@L{EXEC_LEVEL} -> {executor}",
                   f"task {root['id']} (depth {root['depth']})", level=EXEC_LEVEL))

        approval = None
        approver = (approver or "").strip()
        if approver:
            approval = act.Approval(approver=approver, reason=reason.strip(), granted=True)
            r.add(Step("owner", "approves the sandbox apply",
                       f"{approver}: {reason.strip() or '(no reason given)'}"))
        else:
            r.add(Step("owner", "withholds approval",
                       "the apply must refuse — authority was never granted",
                       decision="deny", code="apply_not_approved"))

        # Step 6B: the gateway-minted execute_validated reference (or None on the best-effort
        # path) is threaded to the executor so a signed apply_result can bind back to it. It
        # is never a client-supplied field — it originates from the gateway's own emit.
        code_worker = CodeActWorker(
            self.peers[executor], approval=approval, execute_ref=execute_ref
        )
        verify_workers = [
            AssuranceWorker(self.peers[n])
            for n, c in self._cards().items()
            if n != executor and n in self.peers
            and any(s["id"] == VERIFY_SKILL for s in c.get("skills", []))
        ]
        final = root
        for _ in range(MAX_ROUNDS):
            code_worker.poll()
            for w in verify_workers:
                w.poll()
            final = self.hermes.get_task(root["id"]).get("task", {})
            if final.get("status") != "submitted":
                break

        applied_ok = final.get("status") == "completed" and final.get("verdict") == "PASS"
        r.add(Step(
            executor, "applies in a confined sandbox, then sub-delegates verification",
            f"status={final.get('status')} verdict={final.get('verdict')}",
            level=EXEC_LEVEL, decision="allow" if applied_ok else "deny",
            code="" if applied_ok else "apply_refused",
        ))

        chain = self._chain(executor, root["id"], final)
        sub = next((d for d in chain if d.get("depth") == 2), None)
        if sub:
            r.add(Step(sub["delegatee"],
                       "verifies from gateway evidence and reports up the chain",
                       f"{sub['status']} {sub['verdict']} (depth 2, L{sub['level']})",
                       level=sub["level"]))
        r.extra["chain"] = chain
        r.extra["verdict"] = final.get("verdict") or "—"
        r.extra["applied"] = applied_ok
        return r.to_dict()

    # -- phase 3: prove the boundary holds ---------------------------------------

    def probe(self) -> dict:
        r = _Result("probe")
        r.extra["run_id"] = self.run_id
        card = self.hermes.find_peer(EXEC_SKILL, min_level=EXEC_LEVEL, exclude=("hermes",))
        executor = card["name"] if card else "opencode"

        for action, fn, want in (
            (f"asks {executor} to run at L5 — above its enforced ceiling",
             lambda: self.hermes.delegate(EXEC_SKILL, executor, level=5, task="probe"),
             "autonomy_amplification"),
            ("routes payments.initiate — a skill it was never granted",
             lambda: self.hermes.delegate("payments.initiate", executor, level=1,
                                          task="probe"),
             "skill_not_delegable"),
        ):
            try:
                fn()
                r.add(Step("hermes", action, "NOT refused", decision="deny",
                           code="boundary_hole"))
            except PeerError as exc:
                r.add(Step("hermes", action, f"refused {exc.status}",
                           decision="deny", code=exc.code or want))
        return r.to_dict()

    # -- helpers ------------------------------------------------------------------

    def _cards(self) -> dict:
        return {c["name"]: c for c in self.hermes.discover().get("agents", [])}

    def _chain(self, executor: str, root_id: str, final: dict) -> list[dict]:
        subs = [
            d
            for t in self.peers[executor].outbox()
            for d in [self.peers[executor].get_task(t["id"]).get("task", {})]
            if d.get("parent_id") == root_id
        ]
        rows = [final] + subs
        return [
            {
                "delegator": d.get("delegator"), "delegatee": d.get("delegatee"),
                "skill": d.get("skill"), "level": d.get("granted_level"),
                "depth": d.get("depth"), "status": d.get("status"),
                "verdict": d.get("verdict") or "",
            }
            for d in rows if d
        ]
