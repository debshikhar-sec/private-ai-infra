"""OpenClaw assurance runner.

One assurance pass: gather evidence (decision audit, optionally metrics, policy, and an
OpenCode isolation report), run every control over it, render a report, and exit
non-zero only if a control failed. OpenClaw observes; it changes nothing.

Usage:
    # audit-only pass (no gateway needed)
    python -m openclaw.run --audit logs/decisions.jsonl

    # full pass: cross-check policy, reconcile against live metrics, verify isolation
    python -m openclaw.run \
        --audit logs/decisions.jsonl \
        --policy config/policy.toml \
        --metrics-url http://127.0.0.1:8081 \
        --opencode-report agents/opencode_sandbox/examples/isolated_review.report.txt \
        --format json --output assurance.json

Environment:
    PRIVATE_AI_OPENCLAW_TOKEN  API key for the `openclaw` principal, used only to scrape
                               /metrics (falls back to PRIVATE_AI_AUTH_TOKEN). Not needed
                               unless --metrics-url is given.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from openclaw import checks, evidence
from openclaw.checks import Evidence
from openclaw.client import MetricsClient, MetricsError
from openclaw.report import build_report

DEFAULT_AUDIT = "logs/decisions.jsonl"
DEFAULT_BASE_URL = "http://127.0.0.1:8081"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="openclaw.run", description="OpenClaw assurance pass")
    p.add_argument("--audit", default=DEFAULT_AUDIT, help="Path to decisions.jsonl")
    p.add_argument("--policy", help="Path to policy.toml (enables model-allowlist cross-check)")
    p.add_argument("--opencode-report", help="Path to an OpenCode isolation run report")
    p.add_argument(
        "--eval-report",
        help="Path to a security-eval report JSON (python -m evals.run --format json)",
    )
    p.add_argument(
        "--apply-report",
        help="Path to an act-step apply report JSON (opencode_sandbox.act --format json)",
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--metrics-file", help="Read Prometheus metrics from a file")
    src.add_argument("--metrics-url", help="Scrape GET /metrics from this gateway base URL")
    p.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Report format (default: text)",
    )
    p.add_argument("--output", help="Write the report to this file instead of stdout")
    return p


def _gather_metrics(args, *, metrics_client_factory) -> evidence.MetricSet | None:
    if args.metrics_file:
        text = Path(args.metrics_file).read_text(encoding="utf-8")
        return evidence.parse_metrics(text)
    if args.metrics_url:
        token = os.environ.get("PRIVATE_AI_OPENCLAW_TOKEN") or os.environ.get(
            "PRIVATE_AI_AUTH_TOKEN"
        )
        if not token:
            raise MetricsError(
                "set PRIVATE_AI_OPENCLAW_TOKEN (or PRIVATE_AI_AUTH_TOKEN) to scrape "
                "--metrics-url"
            )
        client = metrics_client_factory(args.metrics_url, token)
        return evidence.parse_metrics(client.fetch())
    return None


def main(argv: list[str] | None = None, *, metrics_client_factory=MetricsClient) -> int:
    args = build_parser().parse_args(argv)

    audit = evidence.load_audit(args.audit)
    policy = evidence.load_policy(args.policy) if args.policy else None
    isolation = (
        evidence.load_isolation_report(args.opencode_report) if args.opencode_report else None
    )
    eval_report = (
        evidence.load_eval_report(args.eval_report) if args.eval_report else None
    )
    apply_report = (
        evidence.load_apply_report(args.apply_report) if args.apply_report else None
    )
    try:
        metrics = _gather_metrics(args, metrics_client_factory=metrics_client_factory)
    except (MetricsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ev = Evidence(
        audit=audit,
        metrics=metrics,
        policy=policy,
        isolation=isolation,
        eval_report=eval_report,
        apply_report=apply_report,
    )
    report = build_report(checks.run_all(ev))

    rendered = {
        "json": report.to_json,
        "markdown": report.to_markdown,
        "text": report.to_text,
    }[args.format]()

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"[openclaw] {report.verdict} — report written to {args.output}", file=sys.stderr)
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
