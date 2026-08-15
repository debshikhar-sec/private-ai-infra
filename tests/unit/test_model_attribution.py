"""Signed model attribution — the generator is recorded, not looked up later.

The central test in this file is :func:`test_route_change_after_generation_does_not_move_attribution`.
Everything else supports it. The failure it guards against is subtle and flattering: attribute
by asking "what is routed to this lane?" at evidence time, re-point the alias, and every run
still in flight silently transfers its record to a build that never saw it — a brand-new,
unmeasured model inheriting a good history it did not earn.
"""

from __future__ import annotations

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway import attribution as attrib
from private_ai_gateway.demo import TOKENS, install_demo_plane

HERMES = f"Bearer {TOKENS['hermes']}"
_OBJ = "Apply the reviewed fix and verify it"
_OWNER_TOKEN = "test-owner-break-glass-token"
_TEST_KEY = b"0123456789abcdef0123456789abcdef"
_TEST_KEY_ID = "gw-test-1"


@pytest.fixture
def client():
    install_demo_plane(gw)
    return gw.app.test_client()


@pytest.fixture
def owner_token(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    return _OWNER_TOKEN


@pytest.fixture
def sink(monkeypatch):
    from openclaw.sink import EMITTER_GATEWAY, EmitterKeyRegistry, EvidenceSink

    registry = EmitterKeyRegistry()
    registry.register(EMITTER_GATEWAY, _TEST_KEY_ID, _TEST_KEY)
    injected = EvidenceSink("sink-attrib", registry)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", injected)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _TEST_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", _TEST_KEY_ID)
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", False)
    return injected


def _post(client, **body):
    return client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES}, json=body
    ).get_json()


def _plan(client):
    body = _post(client, objective=_OBJ, phase="plan")
    return body["run_id"], body["canonical_plan_hash"]


def _approve(client, run_id, plan_hash):
    r = client.post(
        "/v1/approvals",
        headers={"Authorization": f"Bearer {_OWNER_TOKEN}"},
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": "reviewed"},
    )
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def _execute(client, run_id, approval_id):
    return _post(client, objective=_OBJ, phase="execute",
                 run_id=run_id, approval_id=approval_id)


def _records(sink, record_type):
    return [r for r in sink.records if r.envelope.record_type == record_type]


def _attribution_of(sink, run_id):
    rec = next(
        r for r in _records(sink, "execute_validated") if r.envelope.run_id == run_id
    )
    return rec.payload["attribution"], rec.payload["attribution_recorded"]


# ------------------------------------------------------------------ the record is written


def test_plan_emits_a_candidate_attributed_record(client, owner_token, sink):
    run_id, _ = _plan(client)
    recs = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)
    assert len(recs) == 1
    assert recs[0].envelope.run_id == run_id


def test_attribution_names_the_build_not_the_alias(client, owner_token, sink):
    _plan(client)
    payload = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload
    assert payload["route_alias"] == "strategy"
    assert payload["resolved_model"] == gw.ROUTE_MAP["strategy"]
    assert payload["model_fingerprint"].startswith("sha256:")
    # The fingerprint must not be a function of the alias alone.
    assert "strategy" not in payload["model_fingerprint"]


def test_attribution_payload_shape_is_pinned(client, owner_token, sink):
    _plan(client)
    payload = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload
    assert set(payload) == set(attrib.ATTRIBUTION_FIELDS)


def test_attribution_binds_policy_hash_and_candidate_digest(client, owner_token, sink):
    _plan(client)
    payload = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload
    assert payload["policy_hash"].startswith("sha256:")
    assert payload["candidate_digest"].startswith("sha256:")
    assert payload["task_class"] == "code_apply"


def test_generation_record_carries_no_approval_id(client, owner_token, sink):
    """There is no approval yet. Binding one would be an invented link."""
    _plan(client)
    assert _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].envelope.approval_id == ""


# ---------------------------------------------------------------- the attribution survives


def test_execute_validated_carries_the_recorded_attribution(client, owner_token, sink):
    run_id, plan_hash = _plan(client)
    generated = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    carried, recorded = _attribution_of(sink, run_id)
    assert recorded is True
    assert carried == generated


def test_route_change_after_generation_does_not_move_attribution(
    client, owner_token, sink, monkeypatch
):
    """Model A generates; the route is re-pointed to B; the evidence still says A.

    This is the whole point of the module. If attribution were resolved at evidence time,
    this run would be credited to B — a build that never saw the candidate.
    """
    run_id, plan_hash = _plan(client)
    generated = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload
    model_a = generated["resolved_model"]

    # Re-point the alias at a different build, exactly as an operator would.
    model_b = "mlx-community/Some-Other-Model-70B-4bit"
    monkeypatch.setitem(gw.ROUTE_MAP, "strategy", model_b)
    assert gw.ROUTE_MAP["strategy"] != model_a

    _execute(client, run_id, _approve(client, run_id, plan_hash))

    carried, recorded = _attribution_of(sink, run_id)
    assert recorded is True
    assert carried["resolved_model"] == model_a
    assert carried["resolved_model"] != model_b
    assert carried["model_fingerprint"] == generated["model_fingerprint"]


def test_a_later_run_is_attributed_to_the_new_build(client, owner_token, sink, monkeypatch):
    """The mirror image: after a route change, *new* runs do belong to the new build."""
    run_a, hash_a = _plan(client)
    first = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload

    monkeypatch.setitem(gw.ROUTE_MAP, "strategy", "mlx-community/Some-Other-Model-70B-4bit")
    run_b, hash_b = _plan(client)

    by_run = {
        r.envelope.run_id: r.payload
        for r in _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)
    }
    assert by_run[run_a]["resolved_model"] == first["resolved_model"]
    assert by_run[run_b]["resolved_model"] == "mlx-community/Some-Other-Model-70B-4bit"
    assert by_run[run_a]["model_fingerprint"] != by_run[run_b]["model_fingerprint"]

    _execute(client, run_a, _approve(client, run_a, hash_a))
    _execute(client, run_b, _approve(client, run_b, hash_b))
    assert _attribution_of(sink, run_a)[0]["model_fingerprint"] == by_run[run_a]["model_fingerprint"]
    assert _attribution_of(sink, run_b)[0]["model_fingerprint"] == by_run[run_b]["model_fingerprint"]


# ------------------------------------------------------------------ the caller cannot forge


@pytest.mark.parametrize(
    "forged",
    [
        {"model_fingerprint": "sha256:" + "f" * 64},
        {"attribution": {"model_fingerprint": "sha256:" + "e" * 64}},
        {"resolved_model": "a-model-that-does-not-exist"},
        {"policy_hash": "sha256:" + "d" * 64},
        {"candidate_digest": "sha256:" + "c" * 64},
    ],
)
def test_request_body_cannot_set_attribution(client, owner_token, sink, forged):
    """Every field is server-derived. Nothing a caller sends may reach the payload."""
    body = _post(client, objective=_OBJ, phase="plan", **forged)
    run_id = body["run_id"]
    payload = next(
        r.payload
        for r in _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)
        if r.envelope.run_id == run_id
    )
    assert payload["resolved_model"] == gw.ROUTE_MAP["strategy"]
    assert payload["model_fingerprint"] != "sha256:" + "f" * 64
    assert payload["model_fingerprint"] != "sha256:" + "e" * 64
    assert payload["policy_hash"] != "sha256:" + "d" * 64
    assert payload["candidate_digest"] != "sha256:" + "c" * 64


def test_attribution_module_reads_no_request_state():
    """Structural: the module must not reach for a request, header, or environment value.

    Walks the AST rather than grepping the text — the docstring necessarily discusses request
    fields, and a prose match would make the guard fire on its own explanation.
    """
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(attrib.__file__).read_text(encoding="utf-8"))
    forbidden = {"request", "headers", "environ", "getenv", "argv", "flask"}
    seen: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            seen.add(node.id)
        elif isinstance(node, ast.Attribute):
            seen.add(node.attr)
        elif isinstance(node, ast.Import):
            seen.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            seen.add((node.module or "").split(".")[0])
    leaked = seen & forbidden
    assert not leaked, f"attribution.py reaches for {sorted(leaked)}; it must be server-derived"


# -------------------------------------------------------------------- legacy stays honest


def test_run_without_a_generation_record_is_not_backfilled(client, owner_token, sink):
    """A run whose attribution was never written stays unattributed — never inferred."""
    unrecorded = attrib.unrecorded_attribution()
    assert unrecorded["model_fingerprint"] == attrib.MODEL_NOT_RECORDED
    assert unrecorded["policy_hash"] == attrib.POLICY_NOT_RECORDED
    assert set(unrecorded) == set(attrib.ATTRIBUTION_FIELDS)
    # Every field says "not recorded" rather than being blank, so a reader cannot mistake
    # an unwritten fact for an absent model.
    assert "" not in unrecorded.values()


def test_resolution_returns_none_without_a_sink():
    assert attrib.resolve_recorded_attribution(None, run_id="run-x") is None


def test_resolution_returns_none_for_an_unknown_run(client, owner_token, sink):
    _plan(client)
    assert attrib.resolve_recorded_attribution(sink, run_id="run-never-existed") is None


def test_two_generation_records_for_one_run_resolve_to_nothing(client, owner_token, sink):
    """Ambiguity is not resolved by preference. Neither record can be the right one."""
    run_id, _ = _plan(client)
    assert attrib.resolve_recorded_attribution(sink, run_id=run_id) is not None
    # Emit a second attribution record for the same run.
    from private_ai_gateway import orchestration

    orchestration._emit_candidate_attributed(gw, run_id=run_id, proposal={"a": 1})
    assert attrib.resolve_recorded_attribution(sink, run_id=run_id) is None


def test_no_sink_means_no_attribution_and_no_failure(client, owner_token):
    """With no evidence plane the loop is unchanged and simply records nothing."""
    assert gw.EVIDENCE_SINK is None
    run_id, plan_hash = _plan(client)
    out = _execute(client, run_id, _approve(client, run_id, plan_hash))
    assert out["applied"] is True


def test_candidate_digest_is_stable_and_order_independent():
    a = attrib.candidate_digest({"skill": "code.apply", "level": 2})
    b = attrib.candidate_digest({"level": 2, "skill": "code.apply"})
    assert a == b
    assert a != attrib.candidate_digest({"skill": "code.apply", "level": 3})


def test_unknown_alias_refuses_rather_than_guessing():
    class _Gw:
        ROUTE_MAP = {"strategy": "some/model"}
        BACKEND = None

    with pytest.raises(attrib.AttributionError):
        attrib.attribute_candidate(
            _Gw(), route_alias="nope", task_class="t", proposal={}, policy_hash="sha256:x"
        )


# ------------------------------------------------------------------------- the trust ledger


def test_ledger_keys_attributed_runs_by_fingerprint(client, owner_token, sink):
    from private_ai_gateway import trust_ledger as tl

    run_id, plan_hash = _plan(client)
    generated = _records(sink, attrib.CANDIDATE_ATTRIBUTED_RECORD_TYPE)[0].payload
    _execute(client, run_id, _approve(client, run_id, plan_hash))

    ledger = tl.derive_ledger(gw.APPROVAL_STORE, sink)
    keys = [e.key for e in ledger.entries]
    assert any(k.model_fingerprint == generated["model_fingerprint"] for k in keys)
    assert any(k.policy_hash == generated["policy_hash"] for k in keys)


def test_attributed_entry_reports_no_unattributable_dimensions(client, owner_token, sink):
    from private_ai_gateway import trust_ledger as tl

    run_id, plan_hash = _plan(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    ledger = tl.derive_ledger(gw.APPROVAL_STORE, sink)
    attributed = [
        e for e in ledger.entries if e.key.model_fingerprint != tl.NOT_RECORDED
    ]
    assert attributed, "the run should be attributed"
    for entry in attributed:
        assert entry.unattributable == ()


def test_unattributed_entry_still_reports_both_dimensions():
    from private_ai_gateway import trust_ledger as tl

    key = tl.TrustKey(principal="hermes", task_class="code_apply")
    assert tl.TrustEntry.unattributable_for(key) == ("model_fingerprint", "policy_hash")


def test_history_does_not_transfer_between_builds(client, owner_token, sink, monkeypatch):
    """Two builds behind one alias must not share a row, however the alias is configured."""
    from private_ai_gateway import trust_ledger as tl

    run_a, hash_a = _plan(client)
    _execute(client, run_a, _approve(client, run_a, hash_a))
    monkeypatch.setitem(gw.ROUTE_MAP, "strategy", "mlx-community/Some-Other-Model-70B-4bit")
    run_b, hash_b = _plan(client)
    _execute(client, run_b, _approve(client, run_b, hash_b))

    ledger = tl.derive_ledger(gw.APPROVAL_STORE, sink)
    fingerprints = {
        e.key.model_fingerprint
        for e in ledger.entries
        if e.key.model_fingerprint != tl.NOT_RECORDED
    }
    assert len(fingerprints) == 2, "each build must hold its own row"


def test_ledger_still_grants_nothing(client, owner_token, sink):
    """Attribution adds a dimension, not a decision. No score, no level, nowhere."""
    from private_ai_gateway import trust_ledger as tl

    run_id, plan_hash = _plan(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    mapping = tl.derive_ledger(gw.APPROVAL_STORE, sink).to_mapping()
    assert mapping["grants"] == "nothing"
    for entry in mapping["entries"]:
        assert "score" not in entry["facts"]
        assert "autonomy" not in entry["facts"]
        assert "eligible" not in entry["facts"]


def test_no_authorization_module_imports_attribution():
    """The firewall: describing who ran must not become a way to decide what may run."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "src" / "private_ai_gateway"
    for name in ("autonomy.py", "policy.py", "approvals.py", "delegation.py"):
        source = (root / name).read_text(encoding="utf-8")
        assert "attribution" not in source, f"{name} must not consume model attribution"
