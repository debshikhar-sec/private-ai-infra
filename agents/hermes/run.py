"""Hermes planning runner.

One planning cycle: load the contract and persistent memory, compose the request,
delegate it to the gateway as the ``hermes`` principal, parse the structured plan, and
record it back to memory (run history + next gate + updated state). ``--show-prompt``
runs the whole thing *offline* (no gateway call), printing exactly what would be sent —
useful for review and for testing the contract without a model.

Usage:
    python -m hermes.run --objective "Plan the next safe increment"
    python -m hermes.run --objective "..." --show-prompt   # offline, no gateway call

Environment:
    PRIVATE_AI_HERMES_TOKEN   API key for the `hermes` principal (falls back to
                              PRIVATE_AI_AUTH_TOKEN for zero-config local dev).
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from hermes import planner
from hermes.client import GatewayClient, GatewayError
from hermes.store import MemoryStore, NextGate, RunEntry

DEFAULT_BASE_URL = "http://127.0.0.1:8081"
_HERE = Path(__file__).resolve().parent
DEFAULT_CONTRACT = _HERE / "HERMES_PLANNER_CONTRACT.md"
DEFAULT_MEMORY = _HERE / "memory"


def _load_contract(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hermes.run", description="Hermes planning cycle")
    p.add_argument("--objective", required=True, help="What to plan the next step for")
    p.add_argument("--memory-dir", default=str(DEFAULT_MEMORY), help="Hermes memory directory")
    p.add_argument("--contract", default=str(DEFAULT_CONTRACT), help="Planner contract file")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Gateway base URL")
    p.add_argument("--model", default="strategy", help="Model alias to plan with")
    p.add_argument("--autonomy-level", default="L1", help="Declared autonomy level (Hermes ceiling)")
    p.add_argument("--max-tokens", type=int, default=1024)
    p.add_argument(
        "--show-prompt",
        action="store_true",
        help="Offline: print the composed messages and exit without calling the gateway",
    )
    return p


def main(argv: list[str] | None = None, *, client_factory=GatewayClient) -> int:
    args = build_parser().parse_args(argv)

    contract = _load_contract(Path(args.contract))
    store = MemoryStore(args.memory_dir)
    state = store.load_state()
    messages = planner.build_messages(contract, state, args.objective)

    if args.show_prompt:
        for msg in messages:
            print(f"\n===== {msg['role'].upper()} =====\n{msg['content']}")
        return 0

    token = os.environ.get("PRIVATE_AI_HERMES_TOKEN") or os.environ.get("PRIVATE_AI_AUTH_TOKEN")
    if not token:
        print(
            "error: set PRIVATE_AI_HERMES_TOKEN (or PRIVATE_AI_AUTH_TOKEN) to the "
            "hermes principal's key",
            file=sys.stderr,
        )
        return 2

    client = client_factory(
        args.base_url, token, model=args.model, autonomy_level=args.autonomy_level
    )
    try:
        reply = client.complete(messages, max_tokens=args.max_tokens)
    except GatewayError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    plan = planner.parse_plan(reply)
    print(reply)

    # Record the cycle to persistent memory.
    store.append_run(RunEntry(**plan.to_run_entry_kwargs(args.objective)))
    store.set_next_gate(
        NextGate(
            current_gate=plan.get("PHASE") or "planning",
            allowed_next_action=plan.safe_next_action or "(see plan)",
            not_allowed=[plan.get("DO NOT DO YET")] if plan.get("DO NOT DO YET") else [],
            approval_needed=(
                [plan.get("APPROVAL REQUIRED")] if plan.requires_approval else []
            ),
        )
    )
    store.save_state(planner.state_after_plan(state, plan, args.objective))

    if plan.requires_approval:
        print("\n[hermes] APPROVAL REQUIRED before the owner runs this step.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
