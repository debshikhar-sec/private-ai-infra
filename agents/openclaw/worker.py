"""OpenClaw as a delegatable verifier: accepts ``assurance.verify`` tasks and reports.

OpenClaw stays what it is — an observer that changes nothing. The worker wraps one
assurance pass (fetch the decision audit and metrics *through the gateway* under its
own principal, run every control, build the verdict) behind the delegation protocol:
it polls its governed inbox, verifies, and reports PASS/FAIL back up the chain. If a
sub-delegation carried an apply-report path, that report is cross-checked too.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from interop import AgentPeer

from openclaw import checks, evidence
from openclaw.report import build_report

SKILL = "assurance.verify"

# Optional pointer embedded in a task description: "… apply_report=/path/to.json …"
_APPLY_REPORT_RE = re.compile(r"apply_report=(\S+)")


class AssuranceWorker:
    """Polls the inbox, runs one assurance pass per task, reports the verdict."""

    def __init__(
        self,
        peer: AgentPeer,
        *,
        audit_limit: int = 300,
        evidence_sink=None,
        run_id: str | None = None,
        approval_id: str | None = None,
        require_signed_apply_evidence: bool = False,
    ):
        self.peer = peer
        self.audit_limit = audit_limit
        # Verifier-owned evidence-sink consume (design step 4). All optional and additive:
        # with no sink injected the worker behaves exactly as before (file-mode apply
        # integrity). An injected sink lets a new control judge the apply from a signed,
        # chained ``apply_result`` record; ``require_signed_apply_evidence`` makes an unsigned
        # file alone insufficient for PASS. No gateway run_id is parsed from task text here.
        self.evidence_sink = evidence_sink
        self.run_id = run_id
        self.approval_id = approval_id
        self.require_signed_apply_evidence = require_signed_apply_evidence

    def poll(self) -> list[dict]:
        """Handle every submitted ``assurance.verify`` task; return the reports."""
        reported = []
        for task in self.peer.inbox():
            if task.get("skill") != SKILL:
                continue
            match = _APPLY_REPORT_RE.search(task.get("task", ""))
            verdict, summary = self.verify(
                apply_report_path=match.group(1) if match else None
            )
            reported.append(
                self.peer.report(
                    task["id"],
                    "completed" if verdict == "PASS" else "failed",
                    result=summary,
                    verdict=verdict,
                )
            )
        return reported

    def verify(self, *, apply_report_path: str | None = None) -> tuple[str, str]:
        """One assurance pass over gateway evidence; returns (verdict, summary)."""
        # Evidence comes through the governed surface: the audit tail needs OpenClaw's
        # own can_read_audit grant, and /metrics its bearer token — no side doors.
        decisions = self.peer.decisions(limit=self.audit_limit)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as fh:
            for event in decisions:
                fh.write(json.dumps(event) + "\n")
            audit_path = fh.name
        try:
            audit = evidence.load_audit(audit_path)
        finally:
            Path(audit_path).unlink(missing_ok=True)

        metrics = evidence.parse_metrics(self.peer.metrics_text())
        apply_report = (
            evidence.load_apply_report(apply_report_path) if apply_report_path else None
        )

        findings = checks.run_all(
            checks.Evidence(
                audit=audit,
                metrics=metrics,
                apply_report=apply_report,
                evidence_sink=self.evidence_sink,
                run_id=self.run_id,
                approval_id=self.approval_id,
                require_signed_apply_evidence=self.require_signed_apply_evidence,
            )
        )
        report = build_report(findings)
        counts = report.counts()
        summary = (
            f"{report.verdict}: {counts.get('pass', 0)} pass / "
            f"{counts.get('fail', 0)} fail / "
            f"{counts.get('inconclusive', 0)} inconclusive over "
            f"{len(audit.events)} audited decisions"
        )
        return report.verdict, summary
