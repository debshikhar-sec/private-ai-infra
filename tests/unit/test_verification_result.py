"""Step 7C.1 — the verifier's verdict as a signed, durable assurance fact.

Until now OpenClaw's conclusion existed only as returned text, so anything downstream that
"knew" a run was verified knew it by hearsay. These tests hold the signed verdict to the
properties that make it worth signing:

  * **OpenClaw signs it, nobody else.** The gateway never receives the verifier's key.
  * **A PASS binds to the exact ``apply_result`` it judged**, and is unreachable over a
    broken authorization graph.
  * **An unrecordable verdict is never advertised as verified** — the mutation may already
    have happened, so the failure is loud and nothing is retried or rolled back.
  * **It survives a restart**, and a wrong or missing verifier key fails closed.
  * **Multiple verdicts are plural, never terminal** — no hidden "pick latest" rule.

Deterministic: real durable stores over a temp state dir, real signing, real restarts.
"""

from __future__ import annotations

import pytest
from openclaw import assurance, verification
from openclaw.checks import FAIL, INCONCLUSIVE, PASS, Finding
from openclaw.report import VERDICT_FAIL, VERDICT_PASS, build_report
from openclaw.sink import EMITTER_GATEWAY, EMITTER_OPENCLAW, EvidenceError

from private_ai_gateway import app as gw
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.state import StateConfig, StateError, open_backend

_GW_HEX = "aa" * 32
_OC_HEX = "bb" * 32
_CLAW_HEX = "cc" * 32
_WRONG_HEX = "dd" * 32
HERMES = {"Authorization": f"Bearer {TOKENS['hermes']}"}
_OWNER_TOKEN = "test-owner-break-glass-token"
_OBJ = "Apply the reviewed fix and verify it"


def _env(tmp_path, **extra):
    env = {
        "PRIVATE_AI_EVIDENCE_KEY_GATEWAY": _GW_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCODE": _OC_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCLAW": _CLAW_HEX,
        "PRIVATE_AI_STATE_BACKEND": "sqlite",
        "PRIVATE_AI_STATE_DIR": str(tmp_path),
        "PRIVATE_AI_EVIDENCE_MODE": "durable",
    }
    env.update(extra)
    return env


def _open(tmp_path, **extra):
    env = _env(tmp_path, **extra)
    return open_backend(StateConfig.from_env(env), environ=env)


@pytest.fixture
def wired(tmp_path, monkeypatch):
    install_demo_plane(gw)
    for name, value in (
        ("PRIVATE_AI_EVIDENCE_KEY_GATEWAY", _GW_HEX),
        ("PRIVATE_AI_EVIDENCE_KEY_OPENCODE", _OC_HEX),
        ("PRIVATE_AI_EVIDENCE_KEY_OPENCLAW", _CLAW_HEX),
    ):
        monkeypatch.setenv(name, value)
    opened = _open(tmp_path)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "APPROVAL_STORE", opened.authority_store)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", bytes.fromhex(_GW_HEX))
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", True, raising=False)
    yield gw.app.test_client(), opened
    try:
        opened.close()
    except Exception:  # noqa: BLE001
        pass


def _complete_run(client):
    """Drive the real governed loop to a complete, signature-linked execution."""
    body = client.post("/v1/orchestrate", headers=HERMES,
                       json={"objective": _OBJ, "phase": "plan"}).get_json()
    run_id, plan_hash = body["run_id"], body["canonical_plan_hash"]
    approval_id = client.post(
        "/v1/approvals", headers={"Authorization": f"Bearer {_OWNER_TOKEN}"},
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": "reviewed"},
    ).get_json()["approval_id"]
    assert client.post("/v1/orchestrate", headers=HERMES,
                       json={"objective": _OBJ, "phase": "execute", "run_id": run_id,
                             "approval_id": approval_id}).get_json()["applied"] is True
    return run_id, approval_id


def _report(*statuses):
    return build_report([
        Finding(f"AC-{i}", f"control {i}", status, "info", "detail")
        for i, status in enumerate(statuses)
    ])


def _emit(opened, report, run_id, approval_id, **over):
    kwargs = dict(
        run_id=run_id, approval_id=approval_id,
        signing_key=bytes.fromhex(_CLAW_HEX),
        key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCLAW],
    )
    kwargs.update(over)
    return verification.emit_verification_result(opened.evidence_sink, report, **kwargs)


# --- key custody -----------------------------------------------------------------------

def test_openclaw_has_its_own_emitter_key_and_stable_key_id():
    env = {"PRIVATE_AI_EVIDENCE_KEY_OPENCLAW": _CLAW_HEX}
    key, key_id = assurance.emitter_signing_key(env, EMITTER_OPENCLAW)
    assert key == bytes.fromhex(_CLAW_HEX)
    assert key_id == "openclaw-hmac-1"


def test_the_gateway_never_receives_the_verifier_key(wired):
    """The component being judged must not be able to author the judgement."""
    _, opened = wired
    assert gw.EVIDENCE_KEY == bytes.fromhex(_GW_HEX)
    assert gw.EVIDENCE_KEY != bytes.fromhex(_CLAW_HEX)
    assert gw.EVIDENCE_KEY_ID == "gateway-hmac-1"
    # Nothing on the gateway module holds the verifier's material or key id.
    for attr in dir(gw):
        if attr.startswith("EVIDENCE_KEY"):
            assert getattr(gw, attr) not in (bytes.fromhex(_CLAW_HEX), "openclaw-hmac-1")


def test_a_missing_verifier_key_fails_the_registry_closed():
    env = {"PRIVATE_AI_EVIDENCE_KEY_GATEWAY": _GW_HEX,
           "PRIVATE_AI_EVIDENCE_KEY_OPENCODE": _OC_HEX}
    with pytest.raises(assurance.AssuranceConfigError) as exc:
        assurance.load_registry(env)
    assert "PRIVATE_AI_EVIDENCE_KEY_OPENCLAW" in str(exc.value)
    assert _CLAW_HEX not in str(exc.value)          # names the variable, never the value


# --- the signed record -------------------------------------------------------------------

def test_a_pass_is_signed_by_openclaw_and_binds_to_the_apply_it_judged(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)

    emit = _emit(opened, _report(PASS, PASS), run_id, approval_id)
    assert emit.appended and emit.advertised_verdict == VERDICT_PASS
    assert emit.graph_verified

    rec = verification.verification_results_for(
        opened.evidence_sink, run_id=run_id, approval_id=approval_id)[0]
    assert rec.envelope.emitter == EMITTER_OPENCLAW
    assert rec.envelope.record_type == "verification_result"
    assert rec.envelope.emitter_key_id == "openclaw-hmac-1"
    # run/approval live in the signed envelope, not in the payload.
    assert rec.envelope.run_id == run_id and rec.envelope.approval_id == approval_id
    assert "run_id" not in rec.payload and "approval_id" not in rec.payload

    # apply_ref names the exact apply_result, resolvable by the verifier's own resolver.
    from openclaw.sink import EvidenceRef, resolve_evidence_ref
    ref = EvidenceRef.from_mapping(rec.payload["apply_ref"])
    resolved = resolve_evidence_ref(
        tuple(opened.evidence_sink.records), ref, sink_id=opened.evidence_sink.sink_id)
    assert resolved.envelope.record_type == "apply_result"
    assert resolved.envelope.run_id == run_id


def test_the_payload_is_minimal_and_carries_nothing_sensitive(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _emit(opened, _report(PASS, FAIL, INCONCLUSIVE), run_id, approval_id)

    payload = verification.verification_results_for(
        opened.evidence_sink, run_id=run_id)[0].payload
    assert set(payload) == {
        "verdict", "control_counts", "failed_control_ids",
        "inconclusive_control_ids", "evidence_graph_verified", "apply_ref",
    }
    assert payload["control_counts"] == {"pass": 1, "fail": 1, "inconclusive": 1}
    assert payload["failed_control_ids"] == ["AC-1"]
    assert payload["inconclusive_control_ids"] == ["AC-2"]
    rendered = str(payload)
    for secret in (_GW_HEX, _OC_HEX, _CLAW_HEX, _OWNER_TOKEN, TOKENS["hermes"], _OBJ):
        assert secret not in rendered


def test_graph_verified_is_derived_not_asserted(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    emit = _emit(opened, _report(PASS), run_id, approval_id)
    payload = verification.verification_results_for(opened.evidence_sink, run_id=run_id)[0]
    assert payload.payload["evidence_graph_verified"] is True
    assert emit.graph_verified is True


# --- a signed PASS is unreachable over a broken graph ------------------------------------

def test_a_pass_over_a_missing_graph_is_downgraded_not_signed_as_pass(wired):
    """No apply_result at all: the controls may pass, but nothing supports a signed PASS."""
    client, opened = wired
    body = client.post("/v1/orchestrate", headers=HERMES,
                       json={"objective": _OBJ, "phase": "plan"}).get_json()
    run_id = body["run_id"]
    approval_id = client.post(
        "/v1/approvals", headers={"Authorization": f"Bearer {_OWNER_TOKEN}"},
        json={"run_id": run_id, "canonical_plan_hash": body["canonical_plan_hash"],
              "decision": "approve", "reason": "reviewed"},
    ).get_json()["approval_id"]

    emit = _emit(opened, _report(PASS, PASS), run_id, approval_id)
    assert emit.appended
    assert emit.advertised_verdict == VERDICT_FAIL          # never PASS
    assert emit.graph_verified is False
    assert "downgraded" in emit.reason

    payload = verification.verification_results_for(opened.evidence_sink, run_id=run_id)[0]
    assert payload.payload["verdict"] == VERDICT_FAIL
    assert payload.payload["evidence_graph_verified"] is False
    assert "apply_ref" not in payload.payload               # nothing to bind to


def test_a_broken_upstream_graph_cannot_produce_a_signed_pass(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _complete_run(client)

    # The graph walk reports unusable (as it would for any broken edge upstream).
    from openclaw import verification as vmod

    class _Unusable:
        usable = False
        reason = "execute_validated carries no approval_ref"

    monkeypatch.setattr(vmod, "load_evidence_graph_from_sink", lambda *a, **k: _Unusable())
    emit = _emit(opened, _report(PASS), run_id, approval_id)
    assert emit.advertised_verdict == VERDICT_FAIL
    assert "approval_ref" in emit.reason


def test_a_genuine_fail_is_recorded_as_fail(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    emit = _emit(opened, _report(PASS, FAIL), run_id, approval_id)
    assert emit.appended and emit.advertised_verdict == VERDICT_FAIL
    assert emit.graph_verified is True                       # the graph was fine; a control failed


# --- emit failure must never advertise VERIFIED -------------------------------------------

class _RefusingSink:
    sink_id = "gateway-evidence"
    records: tuple = ()

    def append(self, *a, **k):
        raise EvidenceError("simulated append failure")

    def verify_chain(self):
        return True


def test_a_required_but_unrecordable_verdict_raises_loudly():
    with pytest.raises(verification.VerificationEmitError) as exc:
        verification.emit_verification_result(
            _RefusingSink(), _report(PASS), run_id="run-x", approval_id="appr-x",
            signing_key=bytes.fromhex(_CLAW_HEX), key_id="openclaw-hmac-1", required=True,
        )
    assert "could not be appended" in str(exc.value)


def test_an_unrecordable_verdict_never_advertises_a_verified_state():
    emit = verification.emit_verification_result(
        _RefusingSink(), _report(PASS), run_id="run-x", approval_id="appr-x",
        signing_key=bytes.fromhex(_CLAW_HEX), key_id="openclaw-hmac-1", required=False,
    )
    assert emit.appended is False
    assert emit.assurance_incomplete is True
    assert emit.advertised_verdict != VERDICT_PASS       # no signed support, no PASS
    assert "could not be appended" in emit.reason


def test_a_required_verdict_with_no_sink_configured_fails_closed():
    with pytest.raises(verification.VerificationEmitError):
        verification.emit_verification_result(
            None, _report(PASS), run_id="r", approval_id="a",
            signing_key=b"x" * 32, key_id="openclaw-hmac-1", required=True,
        )


def test_emit_failure_retries_no_mutation(wired, monkeypatch):
    """The mutation may already have happened: nothing is retried, nothing is rolled back."""
    import hermes.session as hs

    client, opened = wired
    run_id, approval_id = _complete_run(client)
    before = [r.envelope.record_type for r in opened.evidence_sink.records]

    called: list[str] = []
    monkeypatch.setattr(hs.GovernedSession, "execute", lambda *a, **k: called.append("x"))
    verification.emit_verification_result(
        _RefusingSink(), _report(PASS), run_id=run_id, approval_id=approval_id,
        signing_key=bytes.fromhex(_CLAW_HEX), key_id="openclaw-hmac-1",
    )
    assert called == []
    assert [r.envelope.record_type for r in opened.evidence_sink.records] == before


# --- restart ------------------------------------------------------------------------------

def test_the_whole_chain_including_the_verdict_survives_a_restart(tmp_path, wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _emit(opened, _report(PASS, PASS), run_id, approval_id)
    before = [r.envelope.record_type for r in opened.evidence_sink.records]
    assert before == ["candidate_attributed", "approval_decided", "execute_validated", "apply_result",
                      "verification_result"]
    opened.close()

    reopened = _open(tmp_path)
    try:
        reopened.evidence_sink.verify_chain()            # whole chain re-derives
        assert [r.envelope.record_type for r in reopened.evidence_sink.records] == before

        # The verdict still resolves its apply_ref ...
        from openclaw.sink import EvidenceRef, resolve_evidence_ref
        rec = verification.verification_results_for(
            reopened.evidence_sink, run_id=run_id)[0]
        ref = EvidenceRef.from_mapping(rec.payload["apply_ref"])
        apply_rec = resolve_evidence_ref(
            tuple(reopened.evidence_sink.records), ref,
            sink_id=reopened.evidence_sink.sink_id)
        assert apply_rec.envelope.record_type == "apply_result"

        # ... and the apply's own upstream graph still verifies.
        from openclaw.evidence import load_evidence_graph_from_sink
        view = load_evidence_graph_from_sink(
            reopened.evidence_sink, run_id=run_id, approval_id=approval_id)
        assert view.usable, view.reason
    finally:
        reopened.close()


def test_a_wrong_verifier_key_on_restart_fails_closed(tmp_path, wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _emit(opened, _report(PASS), run_id, approval_id)
    opened.close()

    with pytest.raises((StateError, EvidenceError, assurance.AssuranceConfigError)):
        _open(tmp_path, PRIVATE_AI_EVIDENCE_KEY_OPENCLAW=_WRONG_HEX)


def test_a_missing_verifier_key_on_restart_fails_closed(tmp_path, wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _emit(opened, _report(PASS), run_id, approval_id)
    opened.close()

    env = _env(tmp_path)
    del env["PRIVATE_AI_EVIDENCE_KEY_OPENCLAW"]
    with pytest.raises((StateError, assurance.AssuranceConfigError)):
        open_backend(StateConfig.from_env(env), environ=env)


# --- multiple verification passes ---------------------------------------------------------

def test_multiple_verdicts_are_all_returned_and_none_is_terminal(wired):
    """Re-verification is legitimate; resolving to one silently would be a hidden rule."""
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _emit(opened, _report(PASS), run_id, approval_id)
    _emit(opened, _report(PASS, FAIL), run_id, approval_id)

    found = verification.verification_results_for(
        opened.evidence_sink, run_id=run_id, approval_id=approval_id)
    assert len(found) == 2
    # Each carries its own evidence identity, and both are retained in append order.
    assert len({r.envelope.evidence_id for r in found}) == 2
    assert [r.payload["verdict"] for r in found] == [VERDICT_PASS, VERDICT_FAIL]
    opened.evidence_sink.verify_chain()


def test_reconciliation_is_unaffected_by_verification_records(tmp_path, wired):
    """A verdict is assurance evidence: it must not change any run's classification."""
    from private_ai_gateway.approvals import RunStatus
    from private_ai_gateway.reconciliation import reconcile

    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _emit(opened, _report(PASS), run_id, approval_id)
    opened.close()

    reopened = _open(tmp_path)
    try:
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        finding = next(f for f in report.findings if f.approval_id == approval_id)
        assert (finding.class_id, finding.outcome) == (4, "clean")
        assert reopened.authority_store.get_run(run_id).status is not RunStatus.INVALIDATED
    finally:
        reopened.close()


# --- the worker keeps its external contract ------------------------------------------------

def test_the_worker_returns_the_same_shape_with_no_verifier_key_configured():
    from interop import AgentPeer
    from openclaw.worker import AssuranceWorker

    worker = AssuranceWorker(AgentPeer.__new__(AgentPeer))
    assert worker.verification_signing_key is None
    emit = worker._record_verdict(_report(PASS))
    assert emit.appended is False
    assert emit.advertised_verdict == VERDICT_PASS       # unchanged legacy behaviour
