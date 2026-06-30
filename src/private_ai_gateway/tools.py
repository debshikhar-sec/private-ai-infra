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


# The registry. Levels map onto the L0–L6 autonomy ladder (see autonomy.py):
#   L0 observe  — read-only, no input effect
#   L1 suggest  — transforms caller-supplied input, still no side effects
REGISTRY: dict[str, Tool] = {
    "clock.now": Tool("clock.now", 0, "Return the current UTC time.", _clock_now),
    "text.wordcount": Tool("text.wordcount", 0, "Count words/chars in text.", _wordcount),
    "echo": Tool("echo", 1, "Echo the supplied text back.", _echo),
    "hash.sha256": Tool("hash.sha256", 1, "SHA-256 hash of the supplied text.", _sha256),
}


def get_tool(name: str) -> Tool | None:
    return REGISTRY.get(name)


def list_tools() -> list[dict]:
    """A discovery listing (name, required autonomy level, description)."""
    return [
        {"name": t.name, "min_autonomy_level": t.min_level, "description": t.description}
        for t in sorted(REGISTRY.values(), key=lambda t: t.name)
    ]
