"""Owner-gated route activation — a managed revision, never a file edit.

Two properties carry the design. **The hash follows the configuration**: activating a route
changes the effective policy hash, so authority cannot bind to a description of a
configuration that is no longer in force. And **activation is narrow by construction**: a
revision has no field for autonomy, skills, tools, principals or approval rights, so there is
nothing to set rather than merely a check that refuses to set it.
"""

from __future__ import annotations

import json

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway import registry as reg
from private_ai_gateway import route_revision as rev
from private_ai_gateway.demo import TOKENS, install_demo_plane

_OWNER_TOKEN = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER_TOKEN}"}
HERMES = {"Authorization": f"Bearer {TOKENS['hermes']}"}


@pytest.fixture
def revision_dir(tmp_path, monkeypatch):
    directory = tmp_path / "route-revisions"
    monkeypatch.setattr(gw, "ROUTE_REVISION_DIR", str(directory))
    return directory


@pytest.fixture
def client(revision_dir, monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    install_demo_plane(gw)
    return gw.app.test_client()


def _activate(client, *, lane=reg.LANE_ENGINEERING, alias="strategy", headers=None):
    return client.post(
        "/v1/models/route-activate",
        headers=OWNER if headers is None else headers,
        json={"lane": lane, "route_alias": alias},
    )


# ------------------------------------------------------------------------- the store itself


def test_a_revision_is_written_atomically_and_numbered(revision_dir):
    store = rev.RouteRevisionStore(revision_dir)
    assert store.active() is None
    assert store.next_number() == 1
    revision = rev.RouteRevision(
        revision=1, routes={"strategy": "m/one"}, base_policy_hash="sha256:base"
    )
    store.append(revision)
    assert (revision_dir / "000001.json").exists()
    assert store.active().revision == 1
    assert store.next_number() == 2
    # No temp files survive a successful write.
    assert not list(revision_dir.glob("*.tmp"))


def test_a_revision_number_is_never_reused(revision_dir):
    store = rev.RouteRevisionStore(revision_dir)
    store.append(rev.RouteRevision(revision=1, routes={}))
    with pytest.raises(rev.RouteRevisionError):
        store.append(rev.RouteRevision(revision=1, routes={}))


def test_revisions_are_append_only(revision_dir):
    store = rev.RouteRevisionStore(revision_dir)
    store.append(rev.RouteRevision(revision=1, routes={"a": "one"}))
    store.append(rev.RouteRevision(revision=2, routes={"a": "two"}))
    assert [r.revision for r in store.revisions()] == [1, 2]
    # The earlier revision is still readable — "what was in force then" stays answerable.
    assert store.revisions()[0].routes == {"a": "one"}


def test_an_unreadable_revision_is_an_error_not_an_empty_store(revision_dir):
    revision_dir.mkdir(parents=True)
    (revision_dir / "000001.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(rev.RouteRevisionError):
        rev.RouteRevisionStore(revision_dir).revisions()


# --------------------------------------------------------------------------- the hash story


def test_activation_changes_the_effective_policy_hash(client, revision_dir):
    before = gw.effective_routes()
    assert before.state == rev.ACTIVATION_NONE
    resp = _activate(client)
    assert resp.status_code == 200
    after = gw.effective_routes()
    assert after.state == rev.ACTIVATION_ACTIVE
    assert after.effective_policy_hash != before.effective_policy_hash
    assert resp.get_json()["effective_policy_hash"] == after.effective_policy_hash


def test_a_no_op_revision_still_produces_a_distinct_hash(revision_dir):
    """"No revision" and "a revision that changes nothing" are different configurations."""
    base = "sha256:" + "a" * 64
    assert rev.effective_policy_hash(base, {}) != base


def test_a_revision_records_the_base_policy_it_was_computed_against(client, revision_dir):
    _activate(client)
    active = rev.RouteRevisionStore(revision_dir).active()
    assert active.base_policy_hash == rev.base_policy_hash(gw.POLICY_PATH)


def test_a_hand_edited_policy_file_makes_the_revision_stale_not_silently_reinterpreted(
    client, revision_dir, tmp_path, monkeypatch
):
    """The dangerous case: someone edits the file a revision was approved against."""
    _activate(client)
    assert gw.effective_routes().state == rev.ACTIVATION_ACTIVE

    edited = tmp_path / "policy.toml"
    edited.write_text(
        gw.POLICY_PATH and open(gw.POLICY_PATH, encoding="utf-8").read() + "\n# edited\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gw, "POLICY_PATH", str(edited))

    effective = gw.effective_routes()
    assert effective.state == rev.ACTIVATION_STALE
    # And the override is *not* applied — falling back to the file, not to a route nobody
    # reviewed against this file.
    assert effective.routes == dict(gw.ROUTE_MAP)


# ------------------------------------------------------------------------------- the gating


def test_activation_is_owner_only(client):
    assert _activate(client, headers=HERMES).status_code == 403


def test_an_agent_cannot_activate_its_own_route(client):
    for token in ("hermes", "opencode", "openclaw"):
        resp = _activate(client, headers={"Authorization": f"Bearer {TOKENS[token]}"})
        assert resp.status_code == 403, token


def test_an_unqualified_model_cannot_be_activated_for_the_security_lane(client):
    """Not a warning here. Activation is where a warning stops being read."""
    resp = _activate(client, lane=reg.LANE_SECURITY_REVIEW, alias="engineering")
    assert resp.status_code == 403
    body = resp.get_json()
    assert body["error"]["code"] == "security_lane_not_qualified"
    assert gw.effective_routes().state == rev.ACTIVATION_NONE


def test_no_alias_is_qualified_for_the_security_lane_today(client):
    """The measured 0/14 means nothing may be activated there at all."""
    for alias in gw.ROUTE_MAP:
        resp = _activate(client, lane=reg.LANE_SECURITY_REVIEW, alias=alias)
        assert resp.status_code == 403, alias


def test_an_unknown_lane_or_alias_is_refused(client):
    assert _activate(client, lane="not_a_lane").status_code == 400
    assert _activate(client, alias="not_a_route").status_code == 400


# ----------------------------------------------------------------- narrow by construction


def test_a_revision_has_no_field_for_authority():
    """The strongest form of the guarantee: there is nothing to set."""
    fields = set(rev.RouteRevision().to_mapping())
    for forbidden in rev.FORBIDDEN_FIELDS:
        assert forbidden not in fields, f"a revision must not be able to carry {forbidden!r}"
    assert "routes" in fields


def test_activation_ignores_extra_body_fields(client, revision_dir):
    resp = client.post(
        "/v1/models/route-activate",
        headers=OWNER,
        json={
            "lane": reg.LANE_ENGINEERING,
            "route_alias": "strategy",
            "autonomy": 6,
            "allowed_skills": ["code.apply"],
            "allowed_tools": ["payments.initiate"],
            "principals": [{"name": "attacker"}],
        },
    )
    assert resp.status_code == 200
    body = json.loads((revision_dir / "000001.json").read_text(encoding="utf-8"))
    for forbidden in rev.FORBIDDEN_FIELDS:
        assert forbidden not in body
    assert "attacker" not in json.dumps(body)


def test_activation_does_not_change_loaded_authority(client, revision_dir):
    policy_before = gw.POLICY
    principals_before = [p.name for p in gw.POLICY.principals()]
    ceilings_before = {p.name: gw.autonomy_ceiling_for(p) for p in gw.POLICY.principals()}
    _activate(client)
    assert gw.POLICY is policy_before
    assert [p.name for p in gw.POLICY.principals()] == principals_before
    assert {p.name: gw.autonomy_ceiling_for(p) for p in gw.POLICY.principals()} == ceilings_before


def test_activation_never_writes_the_policy_file(client, revision_dir):
    before = open(gw.POLICY_PATH, "rb").read()
    resp = _activate(client)
    assert resp.get_json()["policy_file_written"] is False
    assert open(gw.POLICY_PATH, "rb").read() == before


def test_activation_does_not_hot_patch_the_route_map(client, revision_dir):
    """``ROUTE_MAP`` stays the base policy's view; the merge happens in one resolver."""
    before = dict(gw.ROUTE_MAP)
    _activate(client)
    assert gw.ROUTE_MAP == before


def test_the_module_never_writes_the_policy_file():
    """Structural: no code path in the revision module opens the policy file for writing."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path(rev.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open":
            modes = [a for a in node.args[1:]] + [
                kw.value for kw in node.keywords if kw.arg == "mode"
            ]
            for mode in modes:
                if isinstance(mode, ast.Constant):
                    assert "w" not in str(mode.value) and "a" not in str(mode.value)


# ------------------------------------------------------------- new runs vs runs in flight


def _plan(client):
    body = client.post(
        "/v1/orchestrate", headers=HERMES,
        json={"objective": "Apply the reviewed fix and verify it", "phase": "plan"},
    ).get_json()
    return body["run_id"], body["canonical_plan_hash"]


def test_a_run_planned_after_activation_uses_the_new_revision(client, revision_dir):
    _, hash_before = _plan(client)
    _activate(client)
    _, hash_after = _plan(client)
    # The canonical plan hash covers the policy hash, which now covers the revision.
    assert hash_after != hash_before


def test_a_run_in_flight_keeps_the_configuration_it_was_planned_under(client, revision_dir):
    """A route change must never retroactively reinterpret an approved run."""
    run_id, plan_hash = _plan(client)
    _activate(client)
    approval = client.post(
        "/v1/approvals", headers=OWNER,
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": "reviewed"},
    )
    # The approval still binds to the hash the run was planned under.
    assert approval.status_code == 200
    assert approval.get_json()["canonical_plan_hash"] == plan_hash
    out = client.post(
        "/v1/orchestrate", headers=HERMES,
        json={"objective": "Apply the reviewed fix and verify it", "phase": "execute",
              "run_id": run_id, "approval_id": approval.get_json()["approval_id"]},
    ).get_json()
    assert out["applied"] is True


def test_activation_is_audited(client, revision_dir):
    _activate(client)
    decisions = client.get("/v1/decisions", headers=OWNER).get_json()
    entries = decisions if isinstance(decisions, list) else decisions.get("decisions", [])
    assert any("route_activated" in str(entry.get("reason", "")) for entry in entries)


def test_the_revision_records_who_activated_it(client, revision_dir):
    _activate(client)
    assert rev.RouteRevisionStore(revision_dir).active().activated_by


def test_effective_routes_survives_an_unreadable_store(client, monkeypatch):
    """A broken store falls back to the policy file rather than to nothing."""
    monkeypatch.setattr(gw, "ROUTE_REVISION_DIR", "/nonexistent/\x00bad")
    effective = gw.effective_routes()
    assert effective.routes == dict(gw.ROUTE_MAP)


def test_activation_grants_no_autonomy_widening_end_to_end(client, revision_dir):
    """The whole point, checked through the wire: an activated route is still capped."""
    _activate(client)
    resp = client.post(
        "/v1/chat/completions",
        headers={**HERMES, "X-Autonomy-Level": "6"},
        json={"model": "strategy", "messages": [{"role": "user", "content": "hi"}]},
    )
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "autonomy_exceeded"
