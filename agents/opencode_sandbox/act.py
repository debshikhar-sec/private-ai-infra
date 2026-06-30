"""OpenCode act-step CLI: review a proposal, approve it, apply it under confinement.

The default is *propose-and-review*: with no ``--approve`` an authority-bearing proposal
is REFUSED and its diff is printed, so a human sees exactly what would change before
granting authority. Supplying ``--approve "name:reason"`` grants the approval (sourced
separately from the proposal — the proposer cannot approve itself); the change is then
applied into a confined sandbox copy and verified. ``--commit`` additionally mirrors the
verified change onto the real ``--target`` (still gated by the same approval).

Usage:
    # review only — see the diff, no write (exit 1: refused, pending approval)
    PYTHONPATH=src:agents python -m opencode_sandbox.act PROPOSAL.json --show-diff

    # approve and apply into a sandbox copy (verified; target untouched)
    PYTHONPATH=src:agents python -m opencode_sandbox.act PROPOSAL.json \
        --approve "alice:reviewed the diff, fixes the SQLi"

    # approve and commit onto the real target
    PYTHONPATH=src:agents python -m opencode_sandbox.act PROPOSAL.json \
        --target path/to/tree --approve "alice:ship it" --commit
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from opencode_sandbox import apply as act

_HERE = Path(__file__).resolve().parent
DEFAULT_TARGET = _HERE / "examples" / "review_target"
DEFAULT_RUNTIME = _HERE / "runtime"


def _parse_approval(spec: str | None) -> act.Approval | None:
    """``"approver:reason"`` -> a granted Approval. The proposal never carries this."""
    if not spec:
        return None
    approver, _, reason = spec.partition(":")
    approver = approver.strip()
    if not approver:
        raise ValueError("--approve must be 'approver:reason' with a non-empty approver")
    return act.Approval(approver=approver, reason=reason.strip(), granted=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="opencode_sandbox.act",
        description="Approval-gated, confined, verified apply of a proposed change set",
    )
    p.add_argument("proposal", help="Path to a change-proposal JSON")
    p.add_argument(
        "--target", default=str(DEFAULT_TARGET), help="Target tree the proposal applies to"
    )
    p.add_argument(
        "--runtime-dir",
        default=str(DEFAULT_RUNTIME),
        help="Where the confined sandbox copy is written (gitignored)",
    )
    p.add_argument(
        "--approve",
        metavar="APPROVER:REASON",
        help="Grant approval to apply (without it, an authority-bearing apply is refused)",
    )
    p.add_argument(
        "--commit",
        action="store_true",
        help="Also mirror the verified change onto the real --target (needs --approve)",
    )
    p.add_argument("--show-diff", action="store_true", help="Print the proposed unified diff")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--output", help="Write the report to this file instead of stdout")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    proposal = act.load_proposal(args.proposal)
    try:
        approval = _parse_approval(args.approve)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.show_diff:
        diff = act.render_diff(proposal, args.target)
        print(diff if diff else "(empty diff)", file=sys.stderr)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    sandbox_root = Path(args.runtime_dir) / f"run_{run_id}" / "sandbox"
    sandbox_root.parent.mkdir(parents=True, exist_ok=True)

    report = act.apply_proposal(
        proposal,
        args.target,
        sandbox_root,
        approval=approval,
        commit_to=args.target if args.commit else None,
    )

    rendered = report.to_json() if args.format == "json" else report.to_text()
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"[opencode-act] {report.status.upper()} — report written to {args.output}", file=sys.stderr)
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    if report.status == act.REFUSED:
        print(
            "[opencode-act] refused: supply --approve 'approver:reason' to authorize the apply.",
            file=sys.stderr,
        )
    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
