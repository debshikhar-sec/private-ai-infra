"""A2A (Agent2Agent) governance — agent cards and governed delegation.

A2A connects agents to *each other* (horizontal interop); each agent publishes an
**Agent Card** describing who it is and what skills it offers, and peers use it to decide
what to hand off. A2A v1.0 (Linux Foundation) serves this at
``/.well-known/agent-card.json`` and authenticates with bearer/OAuth tokens.

This module renders an Agent Card from a governance-plane ``Principal`` and adds the one
attribute A2A leaves to the deployment: the principal's **autonomy ceiling**. The card is
therefore not just "what this agent can talk about" but "what authority it actually holds"
— so a delegation decision can be made against enforced policy, not a self-description.
The card is derived from policy, never self-asserted by the agent.
"""

from __future__ import annotations

from private_ai_gateway import autonomy as autonomy_mod
from private_ai_gateway.policy import Principal

PROTOCOL_VERSION = "0.3.0"  # A2A spec series this card shape follows


def agent_card(principal: Principal, *, base_url: str, ceiling: int | None) -> dict:
    """Render an A2A-style Agent Card for a principal, scoped to its granted skills.

    ``ceiling`` is the principal's effective autonomy ceiling (its own, else the policy
    default) — surfaced under a vendor extension so peers can see the authority bound, not
    just the advertised capabilities.
    """
    skills = sorted(s for s in principal.allowed_skills if s != "*")
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "name": principal.name,
        "description": (
            f"Governed agent '{principal.name}' on a local-first AI authority plane. "
            "Capability is bounded by an enforced autonomy ceiling."
        ),
        "url": f"{base_url}/a2a/tasks",
        "version": "0.13.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": skill,
                "name": skill,
                "description": f"Delegatable skill '{skill}' (governed).",
                "tags": ["governed"],
            }
            for skill in skills
        ],
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"}
        },
        "security": [{"bearer": []}],
        # Governance extension: the enforced authority bound for this principal.
        "x-governance": {
            "autonomy_ceiling": ceiling,
            "autonomy_ceiling_name": autonomy_mod.level_name(ceiling),
            "allowed_models": sorted(m for m in principal.allowed_models if m != "*"),
            "wildcard_models": "*" in principal.allowed_models,
        },
    }
