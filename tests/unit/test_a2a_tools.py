"""Unit tests for the A2A agent-card builder, the MCP tool registry, and the policy
grants that gate them. These modules are pure (no MLX), so they run everywhere."""

from __future__ import annotations

from private_ai_gateway import a2a, tools
from private_ai_gateway.policy import Principal


# --------------------------------------------------------------- policy grants
def test_skill_and_tool_grants():
    p = Principal(
        "analyst",
        frozenset({"strategy"}),
        allowed_skills=frozenset({"plan.summarize"}),
        allowed_tools=frozenset({"clock.now"}),
    )
    assert p.may_use_skill("plan.summarize")
    assert not p.may_use_skill("deploy.prod")
    assert p.may_use_tool("clock.now")
    assert not p.may_use_tool("echo")
    # wildcard (owner)
    owner = Principal("owner", frozenset({"*"}), allowed_skills=frozenset({"*"}),
                      allowed_tools=frozenset({"*"}))
    assert owner.may_use_skill("anything") and owner.may_use_tool("anything")
    # default empty grants deny everything
    bare = Principal("bare", frozenset())
    assert not bare.may_use_skill("x") and not bare.may_use_tool("y")


# --------------------------------------------------------------- tool registry
def test_tools_are_pure_and_declared():
    listing = {t["name"]: t for t in tools.list_tools()}
    assert {"clock.now", "echo", "hash.sha256", "text.wordcount"} <= set(listing)
    # read-only tools sit at L0, input-transforming ones at L1
    assert listing["clock.now"]["min_autonomy_level"] == 0
    assert listing["echo"]["min_autonomy_level"] == 1

    assert tools.get_tool("nope") is None
    # known SHA-256 of "abc"
    out = tools.get_tool("hash.sha256").handler({"text": "abc"})
    assert out["sha256"].startswith("ba7816bf8f01cfea")
    assert tools.get_tool("echo").handler({"text": "hi"}) == {"text": "hi"}
    assert tools.get_tool("text.wordcount").handler({"text": "a b c"})["words"] == 3


# --------------------------------------------------------------- agent card
def test_agent_card_is_scoped_to_grants_and_surfaces_ceiling():
    p = Principal(
        "hermes",
        frozenset({"strategy"}),
        max_autonomy_level=1,
        allowed_skills=frozenset({"plan.summarize"}),
    )
    card = a2a.agent_card(p, base_url="http://127.0.0.1:8080", ceiling=1)
    assert card["name"] == "hermes"
    assert card["url"].endswith("/a2a/tasks")
    skill_ids = {s["id"] for s in card["skills"]}
    assert skill_ids == {"plan.summarize"}  # only granted skills are advertised
    # the enforced authority bound is on the card, not just the capabilities
    assert card["x-governance"]["autonomy_ceiling"] == 1
    assert card["x-governance"]["autonomy_ceiling_name"] == "suggest"
    assert card["securitySchemes"]["bearer"]["scheme"] == "bearer"
