"""Models & Routing: a deterministic recommender, a proposal, and four separate answers.

The console page this backs has one job that is easy to get wrong: it must show *what is
available*, *what is qualified for this task*, *what is routed*, and *what authority the
principal holds* as four independent facts. Collapsing them into one badge is how a
capability number becomes a permission in someone's head.

What these tests hold it to:

  * **No model chooses the model.** The recommender is ordinal comparison over four checkable
    facts, every candidate carries the reason codes that produced its standing, and the same
    inputs always produce the same order.
  * **UNQUALIFIED is not overridable.** The measured 0/2 keeps the local engineering model out
    of the security lane, and only a new measurement could change that.
  * **A dropdown mutates nothing.** Selecting a model produces a proposal; no policy file is
    written, no authority moves, and the activation gap is stated rather than papered over.
  * **Deterministic controls have no selector**, and OpenClaw never gains one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway import registry as reg
from private_ai_gateway.demo import TOKENS, install_demo_plane

_OWNER_TOKEN = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER_TOKEN}"}
QWEN = "mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit"
CONSOLE = Path("src/private_ai_gateway/static/console.html")


def _host(**over):
    base = dict(platform="Darwin", architecture="arm64",
                total_memory_bytes=128 * 1024 ** 3,
                backends_available=("demo", "mlx"), active_backend="mlx")
    base.update(over)
    return reg.HostSnapshot(**base)


def _model(alias, *, qualified=reg.QUALIFIED, security=reg.UNQUALIFIED,
           availability=reg.AVAIL_INSTALLED, fit=reg.FIT_FITS, model_id=QWEN):
    identity = reg.ModelIdentity(route_alias=alias, backend="mlx", resolved_model=model_id,
                                 revision="rev", quantization="8bit")
    return reg.RegisteredModel(
        identity=identity,
        availability=availability,
        fit=reg.HardwareFit(fit, reason="fixture"),
        lanes={
            reg.LANE_ENGINEERING: reg.LaneQualification(reg.LANE_ENGINEERING, qualified),
            reg.LANE_SECURITY_REVIEW: reg.LaneQualification(reg.LANE_SECURITY_REVIEW, security),
            reg.LANE_STRATEGY: reg.LaneQualification(reg.LANE_STRATEGY, reg.NOT_EVALUATED),
            reg.LANE_GENERAL_REVIEW: reg.LaneQualification(
                reg.LANE_GENERAL_REVIEW, reg.NOT_EVALUATED),
        },
    )


def _registry(*models, default_alias="engineering"):
    return reg.CapabilityRegistry(
        host=_host(), models=tuple(models), default_alias=default_alias,
        policy_hash="sha256:" + "a" * 64,
    )


# --- the recommender -----------------------------------------------------------------------

def test_a_qualified_installed_fitting_model_is_recommended():
    got = reg.recommend(_registry(_model("engineering")), reg.LANE_ENGINEERING)
    assert got[0].eligible is True
    assert reg.R_QUALIFIED_FOR_TASK in got[0].reasons
    assert reg.R_LOCAL_MODEL_AVAILABLE in got[0].reasons
    assert reg.R_HOST_COMPATIBLE in got[0].reasons


def test_the_current_engineering_model_is_never_recommended_for_the_security_lane():
    """0/2 measured. No prompt, preference or override moves this."""
    got = reg.recommend(_registry(_model("engineering")), reg.LANE_SECURITY_REVIEW)
    assert got[0].qualification == reg.UNQUALIFIED
    assert got[0].eligible is False
    assert reg.R_SECURITY_UNQUALIFIED in got[0].reasons
    assert not any(r.eligible for r in got)


def test_an_unmeasured_model_is_not_eligible_for_the_security_lane():
    """"We have not checked" is a no for this lane, not a weaker yes."""
    built = _registry(_model("fresh", security=reg.NOT_EVALUATED))
    got = reg.recommend(built, reg.LANE_SECURITY_REVIEW)
    assert got[0].eligible is False
    assert reg.R_NOT_EVALUATED in got[0].reasons
    # The same model stays eligible for a lane where being unmeasured is merely unknown.
    assert reg.recommend(built, reg.LANE_ENGINEERING)[0].eligible is True


def test_no_model_is_currently_eligible_for_the_security_lane(client):
    """Nothing on this host has been measured as declining control-weakening changes."""
    body = client.get("/v1/models/routing", headers=OWNER).get_json()
    security = next(lane for lane in body["lanes"]
                    if lane["lane"] == reg.LANE_SECURITY_REVIEW)
    assert security["recommendations"]
    assert not any(r["eligible"] for r in security["recommendations"])


def test_an_uninstalled_model_is_not_recommended():
    got = reg.recommend(
        _registry(_model("offsec", availability=reg.AVAIL_NOT_INSTALLED)),
        reg.LANE_ENGINEERING,
    )
    assert got[0].eligible is False
    assert reg.R_MODEL_NOT_INSTALLED in got[0].reasons


def test_a_model_that_does_not_fit_is_not_recommended():
    got = reg.recommend(
        _registry(_model("big", fit=reg.FIT_DOES_NOT_FIT)), reg.LANE_ENGINEERING
    )
    assert got[0].eligible is False
    assert reg.R_HOST_INCOMPATIBLE in got[0].reasons


def test_unknown_hardware_fit_is_surfaced_as_unknown_never_fabricated():
    got = reg.recommend(
        _registry(_model("mystery", fit=reg.FIT_UNKNOWN)), reg.LANE_ENGINEERING
    )
    assert got[0].fit == reg.FIT_UNKNOWN
    assert reg.R_HOST_FIT_UNKNOWN in got[0].reasons
    assert reg.R_HOST_COMPATIBLE not in got[0].reasons


def test_an_unevaluated_model_says_so_rather_than_being_recommended_on_vibes():
    got = reg.recommend(
        _registry(_model("fresh", qualified=reg.NOT_EVALUATED)), reg.LANE_ENGINEERING
    )
    assert reg.R_NOT_EVALUATED in got[0].reasons


def test_a_model_outside_the_principals_allowlist_is_not_eligible():
    got = reg.recommend(
        _registry(_model("engineering"), _model("offsec")),
        reg.LANE_ENGINEERING, policy_eligible={"engineering"},
    )
    offsec = next(r for r in got if r.route_alias == "offsec")
    assert offsec.eligible is False
    assert reg.R_NOT_POLICY_ELIGIBLE in offsec.reasons


def test_the_ranking_is_deterministic_and_prefers_qualified_then_fit():
    built = _registry(
        _model("zzz-advisory", qualified=reg.ADVISORY_ONLY),
        _model("aaa-qualified"),
        _model("mmm-marginal", fit=reg.FIT_MARGINAL),
    )
    first = [r.route_alias for r in reg.recommend(built, reg.LANE_ENGINEERING)]
    second = [r.route_alias for r in reg.recommend(built, reg.LANE_ENGINEERING)]
    assert first == second                       # same inputs, same order, every time
    assert first[0] == "aaa-qualified"
    assert first.index("mmm-marginal") < first.index("zzz-advisory")


def test_every_recommendation_carries_explainable_reason_codes():
    for rec in reg.recommend(_registry(_model("engineering")), reg.LANE_ENGINEERING):
        assert rec.reasons
        assert all(code.isupper() or "_" in code for code in rec.reasons)


def test_the_recommender_consults_no_model():
    """No LLM chooses the LLM — asserted structurally, not just by inspection."""
    source = Path("src/private_ai_gateway/registry.py").read_text(encoding="utf-8")
    body = source.split('"""', 2)[-1]
    for forbidden in ("complete(", "chat/completions", "GatewayClient", "backends.select",
                      "generate("):
        assert forbidden not in body, forbidden


# --- route proposals -------------------------------------------------------------------------

def test_a_proposal_shows_before_and_after_and_applies_nothing():
    built = _registry(_model("engineering"), _model("strategy", qualified=reg.NOT_EVALUATED))
    proposal = reg.propose_route(
        built, lane=reg.LANE_ENGINEERING, route_alias="strategy", activation="proposal_only"
    )
    assert proposal.current["route_alias"] == "engineering"
    assert proposal.proposed["route_alias"] == "strategy"
    assert proposal.current_policy_hash.startswith("sha256:")
    assert proposal.activation == "proposal_only"


def test_a_proposal_never_fabricates_a_prospective_policy_hash():
    """Nothing can write the changed config, so nothing may print its hash."""
    built = _registry(_model("engineering"))
    proposal = reg.propose_route(
        built, lane=reg.LANE_ENGINEERING, route_alias="engineering",
        activation="proposal_only",
    )
    assert proposal.prospective_policy_hash == ""


def test_a_proposal_for_the_security_lane_warns_loudly():
    built = _registry(_model("engineering"))
    proposal = reg.propose_route(
        built, lane=reg.LANE_SECURITY_REVIEW, route_alias="engineering",
        activation="proposal_only",
    )
    assert any("UNQUALIFIED" in w for w in proposal.warnings)
    assert any("new qualification measurement" in w for w in proposal.warnings)


def test_a_proposal_warns_about_unavailability_and_unknown_fit():
    built = _registry(_model("gone", availability=reg.AVAIL_NOT_INSTALLED,
                             fit=reg.FIT_UNKNOWN))
    proposal = reg.propose_route(
        built, lane=reg.LANE_ENGINEERING, route_alias="gone", activation="proposal_only"
    )
    assert any("not available" in w for w in proposal.warnings)
    assert any("unknown, not confirmed" in w for w in proposal.warnings)


def test_a_proposal_for_an_unknown_alias_says_so():
    proposal = reg.propose_route(
        _registry(_model("engineering")), lane=reg.LANE_ENGINEERING,
        route_alias="nope", activation="proposal_only",
    )
    assert proposal.proposed == {}
    assert any("no route named" in w for w in proposal.warnings)


def test_a_proposal_carries_no_authority_field_at_all():
    proposal = reg.propose_route(
        _registry(_model("engineering")), lane=reg.LANE_ENGINEERING,
        route_alias="engineering", activation="proposal_only",
    )
    blob = json.dumps(proposal.to_mapping())
    for forbidden in ("autonomy", "skills", "tools", "approval", "ceiling"):
        assert forbidden not in blob, forbidden


# --- the endpoints -------------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    install_demo_plane(gw)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "QUALIFICATION_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    return gw.app.test_client()


@pytest.mark.parametrize("who", ["hermes", "opencode", "openclaw", "shadow-engineer"])
def test_no_agent_principal_may_read_routing_or_propose(client, who):
    headers = {"Authorization": f"Bearer {TOKENS[who]}"}
    assert client.get("/v1/models/routing", headers=headers).status_code == 403
    assert client.post("/v1/models/route-proposal", headers=headers,
                       json={"lane": reg.LANE_ENGINEERING,
                             "route_alias": "engineering"}).status_code == 403


def test_hermes_cannot_change_its_own_route(client):
    """The planner cannot re-point the model that answers it."""
    resp = client.post("/v1/models/route-proposal",
                       headers={"Authorization": f"Bearer {TOKENS['hermes']}"},
                       json={"lane": reg.LANE_STRATEGY, "route_alias": "engineering"})
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "owner_required"


def test_shadow_engineer_cannot_change_its_own_route(client):
    resp = client.post("/v1/models/route-proposal",
                       headers={"Authorization": f"Bearer {TOKENS['shadow-engineer']}"},
                       json={"lane": reg.LANE_ENGINEERING, "route_alias": "strategy"})
    assert resp.status_code == 403


def test_the_routing_view_answers_the_four_questions_separately(client):
    body = client.get("/v1/models/routing", headers=OWNER).get_json()
    assert body["registry"]["models"]                     # what is available
    assert body["lanes"]                                  # what is qualified per task
    assert body["registry"]["default_alias"]              # what is routed
    assert body["authority"]                              # what authority is held
    # Authority is its own block, sourced from policy — not folded into a model's entry.
    for model in body["registry"]["models"]:
        assert "max_autonomy_level" not in json.dumps(model)
    for entry in body["authority"]:
        assert "qualification" not in entry and "fit" not in entry


def test_the_routing_view_lists_deterministic_controls_without_a_selector(client):
    body = client.get("/v1/models/routing", headers=OWNER).get_json()
    names = {c["name"] for c in body["deterministic_controls"]}
    assert {"pytest", "ruff", "OpenClaw assurance"} <= names
    for control in body["deterministic_controls"]:
        assert set(control) == {"name", "why"}       # no model, no options, no chooser


def test_openclaw_assurance_never_gains_a_verifier_model_dropdown(client):
    body = client.get("/v1/models/routing", headers=OWNER).get_json()
    lanes = {lane["lane"] for lane in body["lanes"]}
    assert "assurance" not in lanes and "verifier" not in lanes
    page = CONSOLE.read_text(encoding="utf-8")
    assert "verifier model" not in page.lower()
    assert "choose verifier" not in page.lower()


def test_the_route_proposal_endpoint_applies_nothing(client, monkeypatch):
    before = dict(gw.ROUTE_MAP)
    policy_before = gw.POLICY
    resp = client.post("/v1/models/route-proposal", headers=OWNER,
                       json={"lane": reg.LANE_ENGINEERING, "route_alias": "strategy"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["applied"] is False
    assert body["authority_unchanged"] is True
    # The proposal path still applies nothing, even though activation now exists: proposing
    # and activating are separate endpoints with separate gates.
    assert body["activation"] == "owner_gated_revision"
    assert gw.ROUTE_MAP == before                       # the route map is untouched
    assert gw.POLICY is policy_before                   # and so is the loaded policy


def test_a_route_proposal_writes_no_policy_file(client, monkeypatch):
    policy_path = Path(gw.POLICY_PATH)
    before = policy_path.read_bytes() if policy_path.is_file() else None

    def forbidden(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("the routing path opened a file for writing")

    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(Path, "write_bytes", forbidden)
    client.post("/v1/models/route-proposal", headers=OWNER,
                json={"lane": reg.LANE_ENGINEERING, "route_alias": "strategy"})
    if before is not None:
        assert policy_path.read_bytes() == before


def test_an_unknown_lane_is_refused(client):
    resp = client.post("/v1/models/route-proposal", headers=OWNER,
                       json={"lane": "make_me_an_admin", "route_alias": "engineering"})
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == "unknown_lane"


def test_the_activation_gap_is_stated_not_hidden(client):
    body = client.get("/v1/models/routing", headers=OWNER).get_json()
    activation = body["activation"]
    assert activation["state"] == "owner_gated_revision"
    # The mechanism states what it does *and* what it deliberately cannot do, in the response
    # itself rather than only in a doc a reader may never open.
    assert "policy file is never written" in activation["reason"]
    assert "in flight" in activation["effect"]
    assert "autonomy" in activation["limits"] and "security" in activation["limits"]


def test_the_routing_view_leaks_no_host_identifiers(client):
    blob = json.dumps(client.get("/v1/models/routing", headers=OWNER).get_json())
    for forbidden in (str(Path.home()), "/Users/", "/home/", "serial", "uuid"):
        assert forbidden not in blob, forbidden


# --- the console page ----------------------------------------------------------------------------

def test_the_console_has_a_models_and_routing_pane_without_replacing_the_others():
    page = CONSOLE.read_text(encoding="utf-8")
    assert 'id="pane-models"' in page
    for kept in ("pane-overview", "pane-audit", "pane-probe", "pane-tools",
                 "pane-agents", "pane-metrics"):
        assert f'id="{kept}"' in page, kept


def test_the_console_shows_authority_separately_from_capability():
    page = CONSOLE.read_text(encoding="utf-8")
    assert 'id="mr-authority"' in page
    assert "separate axis" in page
    assert "does not change" in page and "permitted to do" in page


def test_the_console_never_persists_a_token():
    page = CONSOLE.read_text(encoding="utf-8")
    for forbidden in ("localStorage", "sessionStorage", "document.cookie"):
        assert forbidden not in page, forbidden


def test_the_console_route_chooser_only_builds_a_proposal():
    page = CONSOLE.read_text(encoding="utf-8")
    assert "/v1/models/route-proposal" in page
    assert "Not applied." in page
    # There is no activation call to make yet, so the page must not pretend otherwise.
    assert "/v1/models/route-activate" not in page
