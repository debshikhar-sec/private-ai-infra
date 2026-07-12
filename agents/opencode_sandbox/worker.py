"""OpenCode as a delegatable executor: accepts ``code.apply`` tasks, applies under
confinement, and sub-delegates verification before reporting.

Delegation routes the task; it does not replace the approval axis. The apply still
runs through the same gated engine (:mod:`opencode_sandbox.apply`): without a granted
:class:`~opencode_sandbox.apply.Approval` — sourced from the owner who launched the
run, never from the proposer or the delegator — an authority-bearing apply is REFUSED
and the task is reported failed. With approval, the change lands in a confined sandbox
copy and is verified; the real target is never touched by this worker.

After a successful apply, the worker looks up a verifier peer from the agent directory
(never a hardcoded name), sub-delegates ``assurance.verify`` inside the parent grant,
and only reports its own task once the verifier's verdict is in — a chain of custody
the gateway can replay from its audit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from interop import AgentPeer, PeerError

from opencode_sandbox import apply as act
from opencode_sandbox.evidence_emit import emit_apply_result

SKILL = "code.apply"
VERIFY_SKILL = "assurance.verify"
VERIFY_LEVEL = 2  # verification is dry-run work; never ask for more than needed

_HERE = Path(__file__).resolve().parent
DEFAULT_PROPOSAL = _HERE / "examples" / "fix_sqli.proposal.json"
DEFAULT_TARGET = _HERE / "examples" / "review_target"
DEFAULT_RUNTIME = _HERE / "runtime"


class CodeActWorker:
    """Polls the inbox for ``code.apply`` tasks; applies, sub-delegates, reports."""

    def __init__(
        self,
        peer: AgentPeer,
        *,
        approval: act.Approval | None = None,
        proposal_path: str | Path = DEFAULT_PROPOSAL,
        target: str | Path = DEFAULT_TARGET,
        runtime_dir: str | Path = DEFAULT_RUNTIME,
        evidence_sink=None,
        evidence_key: bytes | None = None,
        emitter_key_id: str = "opencode-hmac-1",
        sink_id: str = "",
        run_id: str = "",
        approval_id: str | None = None,
        execute_ref=None,
    ):
        self.peer = peer
        self.approval = approval
        self.proposal_path = Path(proposal_path)
        self.target = Path(target)
        self.runtime_dir = Path(runtime_dir)
        # Evidence-sink emit (design step 3). All optional: when ``evidence_sink`` is None the
        # worker behaves exactly as before (no record emitted). The sink is *verifier-owned* —
        # it is injected here as a handle, never instantiated by the executor.
        self.evidence_sink = evidence_sink
        self.evidence_key = evidence_key
        self.emitter_key_id = emitter_key_id
        self.sink_id = sink_id
        self.run_id = run_id
        self.approval_id = approval_id
        # Step 6B: the gateway-produced ``execute_validated`` EvidenceRef this apply executes
        # under. Threaded in from the internal session boundary — never an external request
        # field — and, when present, bound into the signed ``apply_result`` as ``execute_ref``.
        self.execute_ref = execute_ref
        self._name: str | None = None
        # my task id -> the verification sub-task id I'm waiting on
        self._awaiting: dict[str, str] = {}

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = self.peer.whoami().get("principal", "opencode")
        return self._name

    def poll(self) -> list[dict]:
        """One scheduling round: start new tasks, close out verified ones."""
        outcomes = []
        for task in self.peer.inbox():
            if task.get("skill") != SKILL:
                continue
            handler = self._finish if task["id"] in self._awaiting else self._start
            outcome = handler(task)
            if outcome is not None:
                outcomes.append(outcome)
        return outcomes

    # -- phase 1: confined apply + sub-delegated verification ---------------------

    def _start(self, task: dict) -> dict | None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sandbox = self.runtime_dir / f"run_{run_id}_{uuid.uuid4().hex[:6]}" / "sandbox"
        sandbox.parent.mkdir(parents=True, exist_ok=True)

        proposal = act.load_proposal(str(self.proposal_path))
        report = act.apply_proposal(
            proposal, str(self.target), sandbox, approval=self.approval, commit_to=None
        )
        report_path = sandbox.parent / "apply_report.json"
        report_path.write_text(report.to_json(), encoding="utf-8")

        if not report.applied:
            # No/ungranted approval (or a validation failure): the delegation does not
            # manufacture the missing authority — the task fails, audibly.
            return self.peer.report(
                task["id"],
                "failed",
                result=f"apply {report.status}: "
                       f"{'; '.join(report.violations) or report.detail}"[:1900],
                verdict=report.status.upper(),
            )

        # Evidence-sink emit (design step 3): after a successful apply, push a signed
        # ``apply_result`` record into the verifier-owned sink so the verdict no longer rests
        # on the self-attested ``apply_report.json``. Additive and best-effort-but-loud — an
        # emit failure raises (never swallowed) and is not rolled back; when no sink is
        # injected this is skipped and behavior is unchanged.
        if self.evidence_sink is not None:
            emit_apply_result(
                self.evidence_sink,
                self.evidence_key,
                sink_id=self.sink_id,
                run_id=self.run_id,
                approval_id=self.approval_id,
                emitter_key_id=self.emitter_key_id,
                report=report,
                execute_ref=self.execute_ref,
            )

        verifier = self.peer.find_peer(
            VERIFY_SKILL, min_level=VERIFY_LEVEL, exclude=(self.name,)
        )
        if verifier is None:
            return self.peer.report(
                task["id"], "failed",
                result="no peer advertises assurance.verify at a sufficient ceiling",
                verdict="NO_VERIFIER",
            )

        # Stay inside the parent grant: request the smaller of what verification
        # needs and what this task was itself granted.
        level = min(VERIFY_LEVEL, int(task.get("granted_level", VERIFY_LEVEL)))
        try:
            sub = self.peer.delegate(
                VERIFY_SKILL,
                verifier["name"],
                level=level,
                task=f"verify the confined apply; apply_report={report_path}",
                parent=task["id"],
            )
        except PeerError as exc:
            return self.peer.report(
                task["id"], "failed",
                result=f"verification hand-off refused: {exc.code or exc}",
                verdict="UNVERIFIED",
            )
        self._awaiting[task["id"]] = sub["id"]
        return None

    # -- phase 2: only report once the verifier has spoken -------------------------

    def _finish(self, task: dict) -> dict | None:
        sub = self.peer.get_task(self._awaiting[task["id"]]).get("task", {})
        if sub.get("status") == "submitted":
            return None  # verifier hasn't acted yet; try next round
        del self._awaiting[task["id"]]
        verified = sub.get("status") == "completed" and sub.get("verdict") == "PASS"
        return self.peer.report(
            task["id"],
            "completed" if verified else "failed",
            result=f"confined apply verified by {sub.get('delegatee')}: "
                   f"{sub.get('result', '')}"[:1900],
            verdict=sub.get("verdict") or "UNVERIFIED",
        )
