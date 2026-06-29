"""Hermes verification step — run OpenClaw assurance and fold it into memory.

This is the seam that closes the control loop. A planning cycle proposes a safe next
increment; once it is acted on, **OpenClaw verifies** the evidence the gateway emitted
(decision audit, metrics, OpenCode isolation manifests, policy); and the resulting
verdict is **recorded into Hermes' memory**. The next planning cycle therefore resumes
from *verified* state, with a failing control as its gate.

    plan ──▶ act ──▶ verify (OpenClaw) ──▶ record (Hermes memory) ──▶ re-plan

Hermes plans; OpenClaw verifies; the memory is the only thing they share. This module
is the composition root where the orchestrator (Hermes) invokes the verifier — the two
leaf packages stay decoupled, meeting only at the JSON assurance record.

Usage:
    PYTHONPATH=agents python -m hermes.verify \
        --memory-dir agents/hermes/memory \
        --audit logs/decisions.jsonl \
        --policy config/policy.toml \
        --opencode-report agents/opencode_sandbox/examples/isolated_review.report.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from openclaw import checks, evidence
from openclaw.checks import Evidence
from openclaw.report import build_report

from hermes.store import MemoryStore

DEFAULT_AUDIT = "logs/decisions.jsonl"
_HERE = Path(__file__).resolve().parent
DEFAULT_MEMORY = _HERE / "memory"


def gather_and_record(
    *,
    memory_dir: str | Path,
    audit: str | Path,
    policy: str | Path | None = None,
    metrics_file: str | Path | None = None,
    opencode_report: str | Path | None = None,
    backup: bool = True,
) -> dict:
    """Run OpenClaw over the evidence and persist the verdict into Hermes memory.

    Returns the assurance memory record that was stored (verdict, counts, failing
    controls). No network and no gateway call: this folds *already-emitted* evidence
    into memory, so it runs offline and is fully deterministic.
    """
    audit_log = evidence.load_audit(audit)
    pol = evidence.load_policy(policy) if policy else None
    iso = evidence.load_isolation_report(opencode_report) if opencode_report else None
    metrics = (
        evidence.parse_metrics(Path(metrics_file).read_text(encoding="utf-8"))
        if metrics_file
        else None
    )

    ev = Evidence(audit=audit_log, metrics=metrics, policy=pol, isolation=iso)
    report = build_report(checks.run_all(ev))
    record = report.to_memory_record()

    MemoryStore(memory_dir).record_assurance(record, backup=backup)
    return record


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hermes.verify",
        description="Run OpenClaw assurance and record the verdict into Hermes memory",
    )
    p.add_argument("--memory-dir", default=str(DEFAULT_MEMORY), help="Hermes memory directory")
    p.add_argument("--audit", default=DEFAULT_AUDIT, help="Path to decisions.jsonl")
    p.add_argument("--policy", help="Path to policy.toml (enables model-allowlist cross-check)")
    p.add_argument("--metrics-file", help="Read Prometheus metrics from a file")
    p.add_argument("--opencode-report", help="Path to an OpenCode isolation run report")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    record = gather_and_record(
        memory_dir=args.memory_dir,
        audit=args.audit,
        policy=args.policy,
        metrics_file=args.metrics_file,
        opencode_report=args.opencode_report,
    )

    verdict = record["verdict"]
    counts = record.get("counts", {})
    print(
        f"[hermes] assurance {verdict} "
        f"({counts.get('pass', 0)} pass / {counts.get('fail', 0)} fail / "
        f"{counts.get('inconclusive', 0)} inconclusive) recorded to {args.memory_dir}"
    )
    for fc in record.get("failed_controls", []):
        print(f"  FAIL {fc['control_id']}: {fc['title']}", file=sys.stderr)
    if verdict == "FAIL":
        print(
            "[hermes] next planning cycle is gated on remediating the failing control.",
            file=sys.stderr,
        )
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
