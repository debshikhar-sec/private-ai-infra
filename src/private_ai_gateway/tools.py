"""MCP-style tool registry — governed tool execution.

The Model Context Protocol (MCP) connects an agent to *tools*. The thesis of this
project applies unchanged: a tool call is not authority. Every invocation is gated by
the same plane that gates inference — the principal must be granted the tool
(``allowed_tools``) and must sit at or above the tool's required autonomy level — before
any handler runs.

The built-in tools here are deliberately **pure and side-effect-free** (no filesystem,
no network, no process exec). The point of this surface is to demonstrate *enforced
authorization*, not to ship a privileged tool belt: a high-blast-radius tool would carry
a high ``min_level`` so a low-autonomy principal is refused before the handler is reached.
Adding a real tool later is a matter of registering it with an honest ``min_level``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Tool:
    """A governed tool: a name, the minimum autonomy level to call it, and a handler."""

    name: str
    min_level: int  # the autonomy ladder level a caller must be permitted to reach
    description: str
    handler: Callable[[dict], dict]


def _clock_now(_args: dict) -> dict:
    return {"utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _echo(args: dict) -> dict:
    return {"text": str(args.get("text", ""))}


def _sha256(args: dict) -> dict:
    text = str(args.get("text", ""))
    return {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def _wordcount(args: dict) -> dict:
    text = str(args.get("text", ""))
    return {"words": len(text.split()), "chars": len(text)}


# --- Starter-kit tools -------------------------------------------------------------
# Simulated line-of-business tools shaped like what an agent would hold in a financial
# enterprise. All are pure and deterministic (canned data, no I/O) — what matters is
# their *declared blast radius*: each carries the autonomy floor a real deployment of
# that capability would demand, so the enforcement story is realistic even though the
# handlers are stand-ins.
def _market_snapshot(args: dict) -> dict:
    ticker = str(args.get("ticker", "EURUSD")).upper() or "EURUSD"
    # Deterministic pseudo-quote derived from the ticker so demos are reproducible.
    seed = int(hashlib.sha256(ticker.encode("utf-8")).hexdigest()[:8], 16)
    price = round(50 + (seed % 10_000) / 100, 2)
    return {"ticker": ticker, "price": price, "currency": "USD", "simulated": True}


def _docs_search(args: dict) -> dict:
    query = str(args.get("query", ""))
    return {
        "query": query,
        "hits": [
            {"doc": "risk-committee-2026-06.md", "snippet": "…exposure within mandate…"},
            {"doc": "counterparty-review-q2.md", "snippet": "…two names flagged for review…"},
        ],
        "simulated": True,
    }


def _sanctions_screen(args: dict) -> dict:
    name = str(args.get("name", "")).strip()
    return {
        "name": name,
        "lists_checked": ["OFAC-SDN", "EU-CFSP", "UN-SC"],
        "match": False,
        "simulated": True,
    }


def _email_draft(args: dict) -> dict:
    to = str(args.get("to", "client"))
    subject = str(args.get("subject", "(no subject)"))
    return {
        "draft": f"To: {to}\nSubject: {subject}\n\n[simulated draft — nothing was sent]",
        "sent": False,
        "simulated": True,
    }


def _payment_initiate(args: dict) -> dict:
    # High-blast-radius stand-in: the handler is a no-op on purpose. The control being
    # demonstrated is that callers below L5 are refused *before* this line ever runs.
    return {
        "instruction": "REJECTED-IF-YOU-SEE-THIS-UNGOVERNED",
        "amount": args.get("amount"),
        "executed": False,
        "simulated": True,
    }


# The registry. Levels map onto the L0–L6 autonomy ladder (see autonomy.py):
#   L0 observe  — read-only, no input effect
#   L1 suggest  — transforms caller-supplied input, still no side effects
#   L2 dry_run  — validation-shaped actions (e.g. a screening check)
#   L3+         — actions whose real-world analogue has side effects
REGISTRY: dict[str, Tool] = {
    "clock.now": Tool("clock.now", 0, "Return the current UTC time.", _clock_now),
    "text.wordcount": Tool("text.wordcount", 0, "Count words/chars in text.", _wordcount),
    "echo": Tool("echo", 1, "Echo the supplied text back.", _echo),
    "hash.sha256": Tool("hash.sha256", 1, "SHA-256 hash of the supplied text.", _sha256),
    "market.snapshot": Tool(
        "market.snapshot", 0, "Read a (simulated) market quote for a ticker.", _market_snapshot
    ),
    "docs.search": Tool(
        "docs.search", 1, "Search the (simulated) internal research corpus.", _docs_search
    ),
    "kyc.sanctions_screen": Tool(
        "kyc.sanctions_screen", 2,
        "Screen a counterparty name against (simulated) sanctions lists.", _sanctions_screen,
    ),
    "email.draft": Tool(
        "email.draft", 3, "Draft (never send) a client email — simulated.", _email_draft
    ),
    "payments.initiate": Tool(
        "payments.initiate", 5,
        "Initiate a payment instruction (simulated; high blast radius).", _payment_initiate,
    ),
}


def get_tool(name: str) -> Tool | None:
    return REGISTRY.get(name)


def list_tools() -> list[dict]:
    """A discovery listing (name, required autonomy level, description)."""
    return [
        {"name": t.name, "min_autonomy_level": t.min_level, "description": t.description}
        for t in sorted(REGISTRY.values(), key=lambda t: t.name)
    ]
