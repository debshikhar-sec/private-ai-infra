"""The assurance report: collect findings, render them, and decide a verdict.

The verdict rule is deliberately strict-but-honest:

  - **FAIL** if any control failed.
  - **PASS** otherwise.

INCONCLUSIVE controls never *pass* the run on their own, but they also do not fail it —
they are listed explicitly so a reader sees exactly which controls had no evidence to
judge them. That visibility is the point: an assurance report that hides its own gaps is
worse than useless.

As a CI gate, ``exit_code()`` returns 1 only on FAIL.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from openclaw.checks import FAIL, INCONCLUSIVE, PASS, Finding

VERDICT_FAIL = "FAIL"
VERDICT_PASS = "PASS"  # nosec B105 — overall-verdict label, not a credential

_STATUS_GLYPH = {PASS: "PASS", FAIL: "FAIL", INCONCLUSIVE: "INCONCLUSIVE"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class AssuranceReport:
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = field(default_factory=_utc_now_iso)
    component: str = "openclaw"

    # -- summary -------------------------------------------------------------
    def counts(self) -> dict[str, int]:
        c = {PASS: 0, FAIL: 0, INCONCLUSIVE: 0}
        for f in self.findings:
            c[f.status] = c.get(f.status, 0) + 1
        return c

    @property
    def verdict(self) -> str:
        return VERDICT_FAIL if any(f.status == FAIL for f in self.findings) else VERDICT_PASS

    def exit_code(self) -> int:
        return 1 if self.verdict == VERDICT_FAIL else 0

    # -- rendering -----------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "generated_at": self.generated_at,
            "verdict": self.verdict,
            "counts": self.counts(),
            "findings": [asdict(f) for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def to_memory_record(self) -> dict:
        """A compact, serializable summary for another component to persist.

        This is OpenClaw's hand-off contract: it carries the verdict, the counts, and
        the *failing* controls (with enough detail to act on) without exposing OpenClaw's
        internal types. Hermes folds this into its memory so the next planning cycle
        plans from verified state. Kept deliberately small and JSON-only.
        """
        return {
            "verdict": self.verdict,
            "generated_at": self.generated_at,
            "counts": self.counts(),
            "passed_controls": [f.control_id for f in self.findings if f.status == PASS],
            "inconclusive_controls": [
                f.control_id for f in self.findings if f.status == INCONCLUSIVE
            ],
            "failed_controls": [
                {
                    "control_id": f.control_id,
                    "title": f.title,
                    "severity": f.severity,
                    "detail": f.detail,
                }
                for f in self.findings
                if f.status == FAIL
            ],
        }

    def to_markdown(self) -> str:
        c = self.counts()
        lines = [
            "# OpenClaw assurance report",
            "",
            f"- Generated: {self.generated_at}",
            f"- Verdict: **{self.verdict}**",
            f"- Controls: {c[PASS]} pass · {c[FAIL]} fail · {c[INCONCLUSIVE]} inconclusive",
            "",
            "| Control | Status | Severity | Detail |",
            "|---|---|---|---|",
        ]
        for f in self.findings:
            detail = f.detail.replace("\n", " ").replace("|", "\\|")
            lines.append(
                f"| `{f.control_id}` | {_STATUS_GLYPH.get(f.status, f.status)} "
                f"| {f.severity} | {detail} |"
            )
        lines.append("")
        return "\n".join(lines)

    def to_text(self) -> str:
        c = self.counts()
        lines = [
            "OpenClaw assurance report",
            f"generated: {self.generated_at}",
            f"verdict:   {self.verdict}  "
            f"({c[PASS]} pass / {c[FAIL]} fail / {c[INCONCLUSIVE]} inconclusive)",
            "",
        ]
        for f in self.findings:
            lines.append(f"[{_STATUS_GLYPH.get(f.status, f.status):>12}] {f.control_id} — {f.title}")
            lines.append(f"               {f.detail}")
            if f.evidence:
                lines.append(f"               evidence: {', '.join(f.evidence)}")
            lines.append("")
        return "\n".join(lines)


def build_report(findings: list[Finding]) -> AssuranceReport:
    return AssuranceReport(findings=findings)
