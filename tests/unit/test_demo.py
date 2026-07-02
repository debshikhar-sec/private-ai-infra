"""Tests for the starter-kit demo: policy/token parity and the scripted traffic.

The demo is only worth shipping if it is *true*: every scripted step must be judged
by the real enforcement code and land exactly as the story claims. These tests run
the whole scenario in-process and pin the packaged demo policy to the published
demo tokens so the two can never drift apart.
"""

import importlib.resources

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway import demo, tools
from private_ai_gateway.audit import DecisionLog
from private_ai_gateway.policy import Policy


@pytest.fixture
def demo_env(monkeypatch, tmp_path):
    """Demo plane installed on the gateway, with state restored after the test."""
    # Re-registering current values with monkeypatch makes it restore them on teardown,
    # so install_demo_plane's direct mutation cannot leak into other tests.
    for attr in ("POLICY", "BACKEND", "RATE_LIMITER", "GUARDRAILS"):
        monkeypatch.setattr(gw, attr, getattr(gw, attr))
    monkeypatch.setattr(gw, "DECISION_LOG", DecisionLog(str(tmp_path / "decisions.jsonl")))
    monkeypatch.setattr(gw, "AUTH_TOKEN", "demo-owner-token")
    demo.install_demo_plane(gw)
    return gw


def test_demo_policy_matches_published_tokens():
    policy_file = importlib.resources.files("private_ai_gateway").joinpath("demo_policy.toml")
    policy = Policy.load(str(policy_file))
    for name, token in demo.TOKENS.items():
        principal = policy.identify(token)
        assert principal is not None, f"demo token for {name} does not resolve"
        assert principal.name == name
    assert policy.guardrail_action == "redact"
    assert policy.default_model_alias == "strategy"


def test_demo_scenario_all_steps_hold(demo_env):
    results = demo.run_traffic(demo_env.app.test_client())
    failures = [r for r in results if not r.ok]
    assert not failures, "\n".join(
        f"{r.step.actor}: {r.step.story} -> {r.status} {r.code}" for r in failures
    )
    # The story exercises every decision class the plane can produce.
    statuses = {r.status for r in results}
    assert {200, 202, 403} <= statuses


def test_demo_denials_are_audited(demo_env):
    demo.run_traffic(demo_env.app.test_client())
    events = demo_env.DECISION_LOG.tail(200)
    reasons = " ".join(e.get("reason", "") for e in events)
    for expected in (
        "model_not_allowed",
        "autonomy_exceeded",
        "tool_not_allowed",
        "skill_not_allowed",
        "audit_not_allowed",
        "egress_redact",
    ):
        assert expected in reasons, f"audit trail is missing {expected}"


def test_high_blast_radius_tool_floors_at_l5():
    tool = tools.get_tool("payments.initiate")
    assert tool is not None and tool.min_level == 5


def test_starter_kit_tools_are_simulated_and_pure():
    for name in ("market.snapshot", "docs.search", "kyc.sanctions_screen", "email.draft"):
        tool = tools.get_tool(name)
        assert tool is not None
        result = tool.handler({})
        assert result.get("simulated") is True


def test_format_results_reports_the_tally(demo_env):
    results = demo.run_traffic(demo_env.app.test_client())
    text = demo.format_results(results)
    assert f"{len(results)}/{len(results)} steps" in text


def test_cli_exposes_demo_command():
    from private_ai_gateway.cli import build_parser

    args = build_parser().parse_args(["demo", "--no-serve", "--port", "8123"])
    assert args.no_serve is True and args.port == 8123 and callable(args.func)
