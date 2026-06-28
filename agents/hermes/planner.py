"""Compose Hermes' prompt from memory, and parse the structured plan it returns.

This module is the pure, model-free half of Hermes: it turns persistent state plus an
objective into a chat request, and turns the model's reply back into a structured
``Plan``. Keeping it free of I/O and network makes the planning contract directly
testable — the discipline (one phase at a time, autonomy level declared, approval
gates) is verified in unit tests, not just asserted in a prompt.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

# The labelled sections Hermes must emit, in order. Parsing keys off these.
PLAN_FIELDS = [
    "PHASE",
    "CURRENT READ",
    "SAFE NEXT ACTION",
    "AUTONOMY LEVEL",
    "DO NOT DO YET",
    "COMMANDS OR SCRIPT",
    "VALIDATION",
    "EXPECTED RESULT",
    "IF IT FAILS",
    "APPROVAL REQUIRED",
    "NEXT OWNER ACTION",
]


def summarize_state(state: dict) -> str:
    """Render canonical state into compact text for the system context.

    The model gets a stable, readable digest of what is already verified rather than
    raw JSON, so it plans the *next* increment instead of repeating finished work.
    """
    if not state:
        return "No prior project state recorded. This is the first planning cycle."

    lines: list[str] = []
    gate = state.get("current_gate")
    if gate:
        lines.append(f"Current gate: {gate}")

    components = state.get("components", {})
    if isinstance(components, dict) and components:
        lines.append("Components:")
        for name, meta in components.items():
            meta = meta if isinstance(meta, dict) else {}
            status = meta.get("status", "?")
            ceiling = meta.get("autonomy_ceiling", "?")
            role = meta.get("role", "?")
            lines.append(f"  - {name}: role={role} status={status} autonomy_ceiling={ceiling}")

    phases = state.get("phases", [])
    if isinstance(phases, list) and phases:
        lines.append("Phases:")
        for ph in phases:
            ph = ph if isinstance(ph, dict) else {}
            lines.append(f"  - {ph.get('name', '?')}: {ph.get('status', '?')}")

    restrictions = state.get("restrictions", [])
    if isinstance(restrictions, list) and restrictions:
        lines.append("Standing restrictions (need approval to cross):")
        lines.extend(f"  - {r}" for r in restrictions)

    return "\n".join(lines)


def build_messages(contract: str, state: dict, objective: str) -> list[dict]:
    """Assemble the OpenAI-style chat messages for a planning cycle."""
    system = (
        f"{contract.strip()}\n\n"
        "## Current project state (from Hermes memory)\n\n"
        f"{summarize_state(state)}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": objective.strip()},
    ]


@dataclass
class Plan:
    """A parsed Hermes plan."""

    sections: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def get(self, field_name: str) -> str:
        return self.sections.get(field_name, "").strip()

    @property
    def autonomy_level(self) -> str:
        return self.get("AUTONOMY LEVEL") or "L1"

    @property
    def safe_next_action(self) -> str:
        return self.get("SAFE NEXT ACTION")

    @property
    def next_owner_action(self) -> str:
        return self.get("NEXT OWNER ACTION")

    @property
    def requires_approval(self) -> bool:
        """True unless the APPROVAL REQUIRED section is explicitly 'none'."""
        val = self.get("APPROVAL REQUIRED").lower()
        if not val:
            # Absent approval section on a plan is treated conservatively as gated.
            return True
        return val not in ("none", "n/a", "not required", "-")

    def to_run_entry_kwargs(self, objective: str) -> dict:
        results = [f"{name}: {self.get(name)}" for name in PLAN_FIELDS if self.get(name)]
        return {
            "goal": objective.strip(),
            "autonomy_level": self.autonomy_level,
            "results": results,
            "next_action": self.safe_next_action or self.next_owner_action,
            "approval_required": self.get("APPROVAL REQUIRED") or "none",
        }


def parse_plan(text: str) -> Plan:
    """Parse a labelled-section plan into a ``Plan``.

    Sections are delimited by the ``LABEL:`` headers in :data:`PLAN_FIELDS`. Text
    before the first recognised label is ignored, so a model preamble does not corrupt
    parsing. Unrecognised lines attach to the current section.
    """
    sections: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []

    def flush() -> None:
        if current is not None:
            sections[current] = "\n".join(buf).strip()

    label_lookup = {f.upper(): f for f in PLAN_FIELDS}
    for line in text.splitlines():
        head, sep, rest = line.partition(":")
        key = head.strip().upper()
        if sep and key in label_lookup:
            flush()
            current = label_lookup[key]
            buf = [rest.strip()]
        elif current is not None:
            buf.append(line)
    flush()
    return Plan(sections=sections, raw=text)


def state_after_plan(state: dict, plan: Plan, objective: str) -> dict:
    """Return an updated state dict reflecting the latest plan (non-mutating)."""
    new = json.loads(json.dumps(state)) if state else {}
    new["last_objective"] = objective.strip()
    new["last_plan_phase"] = plan.get("PHASE")
    new["last_autonomy_level"] = plan.autonomy_level
    new["last_approval_required"] = plan.get("APPROVAL REQUIRED") or "none"
    return new
