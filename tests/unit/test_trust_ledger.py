"""The derived trust ledger: facts, no score, no grant.

What these tests hold it to:

  * **A chain that does not verify yields no ledger** — not an empty one. An empty ledger
    reads as "no bad history", which is the opposite of what "could not be read" means.
  * **Facts, never a score.** No single number, no rating, no autonomy level anywhere in the
    output — a scalar invites a threshold, and a threshold is a grant with extra steps.
  * **History does not transfer.** Keyed by principal *and* task class, so success at
    documentation work never becomes trust for security work.
  * **Unattributable dimensions are named, not invented.** No signed record carries a model
    identity, so runtime history is not credited to a model build.
  * **Qualification and runtime history never merge.** Corpus results are not production
    evidence.
  * **The authority firewall holds**, and the falsification proves the test bites.

Deterministic: real durable stores, real signing, real restarts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from openclaw import assurance
from openclaw.sink import EMITTER_GATEWAY, EMITTER_OPENCLAW, EMITTER_OPENCODE, sign_envelope

from private_ai_gateway import app as gw
from private_ai_gateway import trust_ledger as tl
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.state import StateConfig, open_backend

_GW_HEX, _OC_HEX, _CLAW_HEX = "aa" * 32, "bb" * 32, "cc" * 32
_OWNER_TOKEN = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER_TOKEN}"}


def _env(tmp_path):
    return {
        "PRIVATE_AI_EVIDENCE_KEY_GATEWAY": _GW_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCODE": _OC_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCLAW": _CLAW_HEX,
        "PRIVATE_AI_STATE_BACKEND": "sqlite",
        "PRIVATE_AI_STATE_DIR": str(tmp_path / "state"),
        "PRIVATE_AI_EVIDENCE_MODE": "durable",
    }


@pytest.fixture
def opened(tmp_path):
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    env = _env(tmp_path)
    backend = open_backend(StateConfig.from_env(env), environ=env)
    yield backend
    try:
        backend.close()
    except Exception:  # noqa: BLE001
        pass


def _run(opened, *, principal="hermes", task_class="code.apply", run_id="run-1"):
    store = opened.authority_store
    store.create_run(run_id=run_id, principal_id=principal,
                     canonical_plan_hash="sha256:" + "1" * 64,
                     effective_autonomy=3, policy_ceiling=6)
    appr = store.create_pending_approval(run_id, task_class=task_class)
    store.decide_approval(appr.approval_id, decision="approve", approver="owner")
    return run_id, appr.approval_id


def _append(sink, *, record_type, run_id, approval_id, payload,
            emitter=EMITTER_GATEWAY, key=None, nonce="n-1"):
    from openclaw import sink as sinkmod

    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(), sink_id=sink.sink_id, run_id=run_id,
        emitter=emitter, emitter_key_id=assurance.EMITTER_KEY_IDS[emitter],
        record_type=record_type, payload_hash=sinkmod.payload_digest(payload),
        ts="2026-08-15T00:00:00+00:00", nonce=nonce, approval_id=approval_id,
    )
    keys = {EMITTER_GATEWAY: _GW_HEX, EMITTER_OPENCODE: _OC_HEX, EMITTER_OPENCLAW: _CLAW_HEX}
    return sink.append(env, payload, sign_envelope(env, key or bytes.fromhex(keys[emitter])))


# --- derivation ---------------------------------------------------------------------------

def test_an_unverifiable_chain_yields_no_ledger_not_an_empty_one(opened, monkeypatch):
    from openclaw.sink import EvidenceError

    monkeypatch.setattr(
        opened.evidence_sink, "verify_chain",
        lambda: (_ for _ in ()).throw(EvidenceError("chain_broken: index 3")),
    )
    with pytest.raises(tl.TrustLedgerError) as exc:
        tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    assert "did not verify" in str(exc.value)


def test_no_evidence_sink_yields_no_ledger(opened):
    with pytest.raises(tl.TrustLedgerError):
        tl.derive_ledger(opened.authority_store, None)


def test_an_unreadable_authority_store_yields_no_ledger(opened, monkeypatch):
    monkeypatch.setattr(
        opened.authority_store, "snapshot_approvals",
        lambda: (_ for _ in ()).throw(OSError("disk gone")),
    )
    with pytest.raises(tl.TrustLedgerError) as exc:
        tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    assert "authority store" in str(exc.value)


def test_the_ledger_is_re_derived_deterministically_and_persists_nothing(opened, tmp_path):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "PASS", "evidence_graph_verified": True})

    first = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    second = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    assert first.to_mapping() == second.to_mapping()
    # Nothing new on disk: the projection is derived, not stored.
    assert not list((tmp_path / "state").glob("*ledger*"))


def test_a_verified_run_counts_as_verified_complete(opened):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "PASS", "evidence_graph_verified": True})
    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    entry = ledger.entries[0]
    assert entry.facts.verified_complete == 1
    assert entry.facts.non_pass_verdicts == 0


def test_a_non_pass_verdict_is_counted_as_such(opened):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "FAIL", "evidence_graph_verified": False})
    facts = tl.derive_ledger(opened.authority_store, opened.evidence_sink).entries[0].facts
    assert facts.non_pass_verdicts == 1
    assert facts.verified_complete == 0
    assert facts.evidence_failures == 1


def test_a_disposition_counts_as_a_dirty_execution_a_human_closed(opened):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="run_disposition", run_id=run_id,
            approval_id=approval_id, nonce="d1",
            payload={"disposition": "closed_unknown", "basis_type": "execute_validated",
                     "basis_ref": {}, "human_actor": "owner"})
    facts = tl.derive_ledger(opened.authority_store, opened.evidence_sink).entries[0].facts
    assert facts.dirty_executions == 1
    assert facts.closed_unknown == 1
    assert facts.human_asserted == 0


def test_a_human_asserted_disposition_is_counted_separately_from_closed_unknown(opened):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="run_disposition", run_id=run_id,
            approval_id=approval_id, nonce="d1",
            payload={"disposition": "human_asserted_applied",
                     "basis_type": "execute_validated", "basis_ref": {},
                     "human_actor": "owner"})
    facts = tl.derive_ledger(opened.authority_store, opened.evidence_sink).entries[0].facts
    assert facts.human_asserted == 1
    assert facts.closed_unknown == 0


def test_rollback_outcomes_are_counted_including_containment(opened):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="rollback_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCODE, nonce="r1",
            payload={"status": "restored", "contained": False, "origin_run_id": run_id})
    _append(opened.evidence_sink, record_type="rollback_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCODE, nonce="r2",
            payload={"status": "failed", "contained": True, "origin_run_id": run_id})
    facts = tl.derive_ledger(opened.authority_store, opened.evidence_sink).entries[0].facts
    assert facts.rollback_attempted == 2
    assert facts.rollback_restored == 1
    assert facts.rollback_failed == 1
    assert facts.contained == 1


# --- dimensions ---------------------------------------------------------------------------------

def test_history_is_keyed_by_principal_and_task_class_never_principal_alone(opened):
    docs_run, docs_appr = _run(opened, task_class="docs.edit", run_id="run-docs")
    sec_run, sec_appr = _run(opened, task_class="security.review", run_id="run-sec")
    _append(opened.evidence_sink, record_type="verification_result", run_id=docs_run,
            approval_id=docs_appr, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "PASS", "evidence_graph_verified": True})

    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    by_class = {e.key.task_class: e.facts for e in ledger.entries}
    assert by_class["docs.edit"].verified_complete == 1
    # Success at documentation work is not trust for security work.
    assert by_class["security.review"].verified_complete == 0
    assert sec_run and sec_appr


def test_different_principals_never_share_history(opened):
    a_run, a_appr = _run(opened, principal="hermes", run_id="run-a")
    _run(opened, principal="opencode", run_id="run-b")
    _append(opened.evidence_sink, record_type="verification_result", run_id=a_run,
            approval_id=a_appr, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "PASS", "evidence_graph_verified": True})
    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    by_principal = {e.key.principal: e.facts for e in ledger.entries}
    assert by_principal["hermes"].verified_complete == 1
    assert by_principal["opencode"].verified_complete == 0


def test_the_model_dimension_is_named_unattributable_rather_than_invented(opened):
    """No signed record names the model that served a run, so nothing is credited to one."""
    run_id, approval_id = _run(opened)
    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    entry = ledger.entries[0]
    assert entry.key.model_fingerprint == tl.NOT_RECORDED
    assert entry.key.policy_hash == tl.NOT_RECORDED
    assert "model_fingerprint" in entry.unattributable
    blob = json.dumps(ledger.to_mapping())
    assert "mlx-community" not in blob          # never filled in from the configured route
    assert run_id and approval_id


def test_evidence_with_no_authority_projection_is_not_charged_to_anyone(opened):
    """Whose history would it be? Guessing is worse than omitting."""
    _run(opened)
    _append(opened.evidence_sink, record_type="verification_result", run_id="run-orphan",
            approval_id="appr-" + "f" * 32, emitter=EMITTER_OPENCLAW, nonce="v9",
            payload={"verdict": "FAIL", "evidence_graph_verified": False})
    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    assert sum(e.facts.non_pass_verdicts for e in ledger.entries) == 0


# --- facts, not a score ------------------------------------------------------------------------------

def test_the_ledger_exposes_no_score_rating_or_autonomy_level(opened):
    """Asserted on the data keys, not on the prose that says there is no score."""
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "PASS", "evidence_graph_verified": True})
    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)

    for entry in ledger.entries:
        fields = set(entry.facts.to_mapping()) | set(entry.key.to_mapping())
        for forbidden in ("score", "rating", "autonomy", "level", "tier", "grade",
                          "threshold", "trust"):
            assert not any(forbidden in name for name in fields), forbidden
        # Every fact is a plain count — an integer occurrence tally, never a derived ratio.
        for name, value in entry.facts.to_mapping().items():
            assert isinstance(value, int) and value >= 0, name


def test_the_module_computes_no_aggregate_scalar():
    """No division, no weighting, no summing of facts into one number — checked on code."""
    import ast

    source = Path("src/private_ai_gateway/trust_ledger.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mult, ast.Pow)), (
                f"the ledger computes a derived value at line {node.lineno}"
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("sum", "mean", "round"), node.func.id
    # And no field anywhere in the dataclasses is a float.
    for name, value in tl.TrustFacts().to_mapping().items():
        assert isinstance(value, int), name


# --- qualification vs runtime history ------------------------------------------------------------------

def test_qualification_and_runtime_history_are_never_combined(opened):
    from private_ai_gateway import registry as reg

    run_id, approval_id = _run(opened)
    ledger = tl.derive_ledger(opened.authority_store, opened.evidence_sink)
    identity = reg.ModelIdentity(route_alias="engineering", backend="mlx",
                                 resolved_model="m", revision="r", quantization="8bit")
    model = reg.RegisteredModel(
        identity=identity, availability=reg.AVAIL_INSTALLED,
        fit=reg.HardwareFit(reg.FIT_FITS),
        lanes={reg.LANE_SECURITY_REVIEW: reg.LaneQualification(
            reg.LANE_SECURITY_REVIEW, reg.UNQUALIFIED, "0 of 2",
            {"security_refusal_correct": 0, "security_refusal_total": 2})},
    )
    registry = reg.CapabilityRegistry(host=reg.HostSnapshot(), models=(model,))

    view = tl.build_view(registry, ledger)
    assert all(q["kind"] == "QUALIFICATION" for q in view.qualification)
    assert all(r["kind"] == "RUNTIME HISTORY" for r in view.runtime)
    # A corpus result never appears among runtime counts, and vice versa.
    assert not any("security_refusal_total" in r for r in view.runtime)
    assert not any("verified_complete" in q for q in view.qualification)
    assert "never combined" in view.to_mapping()["separation"]
    assert run_id and approval_id


# --- the endpoint --------------------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path, opened):
    install_demo_plane(gw)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "APPROVAL_STORE", opened.authority_store)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "QUALIFICATION_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    return gw.app.test_client()


@pytest.mark.parametrize("who", ["hermes", "opencode", "openclaw", "shadow-engineer"])
def test_the_trust_history_endpoint_is_owner_gated(client, who):
    resp = client.get("/v1/trust-history",
                      headers={"Authorization": f"Bearer {TOKENS[who]}"})
    assert resp.status_code == 403


def test_the_endpoint_separates_the_two_kinds_and_grants_nothing(client, opened):
    run_id, approval_id = _run(opened)
    _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce="v1",
            payload={"verdict": "PASS", "evidence_graph_verified": True})
    body = client.get("/v1/trust-history", headers=OWNER).get_json()
    assert body["grants"] == "nothing"
    assert body["ledger"]["grants"] == "nothing"
    assert "never combined" in body["separation"]
    assert all(r["kind"] == "RUNTIME HISTORY" for r in body["runtime"])


def test_the_endpoint_reports_no_ledger_rather_than_an_empty_one(client, monkeypatch, opened):
    from openclaw.sink import EvidenceError

    monkeypatch.setattr(
        opened.evidence_sink, "verify_chain",
        lambda: (_ for _ in ()).throw(EvidenceError("chain_broken")),
    )
    body = client.get("/v1/trust-history", headers=OWNER).get_json()
    assert body["ledger"] is None
    assert "did not verify" in body["ledger_error"]
    assert body["runtime"] == []


# --- the authority firewall -----------------------------------------------------------------------------------

def test_no_authorization_path_consumes_the_trust_ledger():
    """A falsification proves this test bites; see the PR description."""
    repo = Path(__file__).resolve().parents[2]
    guarded = [
        "src/private_ai_gateway/policy.py",
        "src/private_ai_gateway/autonomy.py",
        "src/private_ai_gateway/approvals.py",
        "src/private_ai_gateway/approvals_sqlite.py",
        "src/private_ai_gateway/guardrails.py",
        "src/private_ai_gateway/disposition.py",
        "src/private_ai_gateway/reconciliation.py",
        "src/private_ai_gateway/canonical.py",
        "src/private_ai_gateway/rollback.py",
    ]
    for rel in guarded:
        source = (repo / rel).read_text(encoding="utf-8")
        for forbidden in ("trust_ledger", "TrustLedger", "trust_history", "TrustFacts"):
            assert forbidden not in source, f"{rel} consumes trust history ({forbidden})"


def test_the_ledger_module_reaches_no_authorization_primitive():
    source = Path("src/private_ai_gateway/trust_ledger.py").read_text(encoding="utf-8")
    body = source.split('"""', 2)[-1]
    for forbidden in ("max_autonomy", "allowed_skills", "allowed_tools",
                      "validate_for_execute", "decide_approval", "create_pending_approval",
                      "invalidate_run", "mark_used"):
        assert forbidden not in body, forbidden


def test_a_principals_authority_is_identical_before_and_after_deriving_a_ledger(client,
                                                                                 opened):
    principal = gw.POLICY.identify(TOKENS["hermes"])
    before = (principal.max_autonomy_level, frozenset(principal.allowed_skills),
              frozenset(principal.allowed_tools), frozenset(principal.allowed_models))
    run_id, approval_id = _run(opened)
    for i in range(3):
        _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
                approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce=f"v{i}",
                payload={"verdict": "PASS", "evidence_graph_verified": True})
    client.get("/v1/trust-history", headers=OWNER)
    after = gw.POLICY.identify(TOKENS["hermes"])
    assert (after.max_autonomy_level, frozenset(after.allowed_skills),
            frozenset(after.allowed_tools), frozenset(after.allowed_models)) == before


def test_a_spotless_history_still_grants_nothing(client, opened):
    """The point of the firewall: even a perfect record changes no ceiling."""
    run_id, approval_id = _run(opened)
    for i in range(10):
        _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
                approval_id=approval_id, emitter=EMITTER_OPENCLAW, nonce=f"p{i}",
                payload={"verdict": "PASS", "evidence_graph_verified": True})
    body = client.get("/v1/trust-history", headers=OWNER).get_json()
    assert body["runtime"][0]["verified_complete"] == 10
    hermes = gw.POLICY.identify(TOKENS["hermes"])
    assert hermes.max_autonomy_level == 1        # unchanged by a flawless record


def test_no_earned_autonomy_machinery_exists_yet():
    source = Path("src/private_ai_gateway/trust_ledger.py").read_text(encoding="utf-8")
    for forbidden in ("promote", "demote", "lease", "preauthor", "grant_", "escalat"):
        assert forbidden not in source.lower(), forbidden


# --- the console -----------------------------------------------------------------------------------------------

def test_the_console_shows_qualification_and_runtime_history_apart():
    page = Path("src/private_ai_gateway/static/console.html").read_text(encoding="utf-8")
    assert 'id="mr-qual"' in page and 'id="mr-runtime"' in page
    assert "QUALIFICATION" in page and "RUNTIME HISTORY" in page
    assert "never combined" in page
    assert "grants nothing" in page
