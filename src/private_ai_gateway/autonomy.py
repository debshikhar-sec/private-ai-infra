"""Autonomy ladder (L0–L6) for the governance plane.

The original control-plane design governed *how much autonomy* a delegated agent
could exercise — but only at the prompt level (a boot prompt asked the model to
behave). This module makes the same ladder an *enforceable* control: each request
declares the autonomy level it intends to operate at, each principal carries a
``max_autonomy_level``, and the gateway refuses any request that exceeds its
principal's ceiling. Capability is not authority — and here that is mechanical, not
advisory.

The ladder:

  L0 observe         — read/observe only
  L1 suggest         — propose text/plans, take no action
  L2 dry_run         — dry-run / no-op execution (e.g. ``bash -n``, validation)
  L3 owner_run       — owner-initiated local execution
  L4 monitored_auto  — finite, monitored automation
  L5 continuous_auto — continuous automation
  L6 unbounded       — unbounded autonomy (break-glass / owner only)

A request declares its level via the ``X-Autonomy-Level`` header or an
``autonomy_level`` body field (``"L3"``, ``"3"``, or ``3`` are all accepted). When
neither a principal ceiling nor a policy default is configured, enforcement is off
and behaviour is unchanged — autonomy gating is opt-in.
"""

from __future__ import annotations

# Level number -> short stable name.
LEVELS: dict[int, str] = {
    0: "observe",
    1: "suggest",
    2: "dry_run",
    3: "owner_run",
    4: "monitored_auto",
    5: "continuous_auto",
    6: "unbounded",
}

MAX_LEVEL = 6

# A bare inference call (no declared level) is treated as "suggest": the model
# proposes text and the caller is not asserting any execution authority.
DEFAULT_REQUEST_LEVEL = 1


def parse_level(value, default: int | None = None) -> int | None:
    """Parse ``"L3"`` / ``"3"`` / ``3`` into ``3``; return ``default`` on failure."""
    if value is None:
        return default
    try:
        if isinstance(value, str):
            token = value.strip().upper()
            if token.startswith("L"):
                token = token[1:]
            number = int(token)
        else:
            number = int(value)
    except (TypeError, ValueError):
        return default
    if 0 <= number <= MAX_LEVEL:
        return number
    return default


def level_name(number: int | None) -> str:
    """Human-readable name for a level number."""
    if number is None:
        return "unset"
    return LEVELS.get(number, "unknown")
