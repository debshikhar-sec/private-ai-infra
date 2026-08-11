"""Step 7C.2 — terminal ``run_disposition``: a human's signed closure of a run.

Reconciliation could already tell a dirty run from a clean one and invalidate the dirty
ones, but nothing could ever *finish* one: every startup resurfaced the same anomaly, and
OpenClaw's 7C.1 verdicts are deliberately plural and non-terminal. These tests hold the new
fact to the properties that make it safe to be terminal:

  * **A dirty run with no valid ``apply_result`` is still disposable.** That is the whole
    point of the basis model — a 7C.1 verdict is apply-bound, so demanding one would make
    exactly the runs that need human closure permanently undisposable.
  * **When verdicts exist, the human names one.** Two verdicts do not become "the latest";
    the caller selects, and the server re-resolves that exact reference.
  * **The server constructs the evidence.** A client supplies a typed reference, never an
    envelope; a forged digest, a foreign run, a wrong record type or a dangling ref all fail
    closed.
  * **Only a human disposes.** Planner, executor and verifier principals are refused.
  * **Terminal means terminal.** Exactly one disposition per run under concurrency, and
    neither a late ``apply_result`` nor a late ``verification_result`` can supersede it.
  * **Unreadable never reads as undisposed.** A tampered or ambiguous disposition fails
    startup closed rather than silently reverting the run to "outstanding".

Deterministic throughout: real durable stores over a temp state dir, real signing, real
restarts, real threads. No sleeps.
"""

from __future__ import annotations

import threading

import pytest
from openclaw import assurance, verification
from openclaw.checks import FAIL, PASS, Finding
from openclaw.report import build_report
from openclaw.sink import EMITTER_GATEWAY, EMITTER_OPENCLAW, EMITTER_OPENCODE, sign_envelope

from private_ai_gateway import app as gw
from private_ai_gateway import disposition as disp
from private_ai_gateway import reconciliation
from private_ai_gateway.approvals import ApprovalStatus, RunStatus
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.reconciliation import ReconciliationError, reconcile
from private_ai_gateway.state import StateConfig, open_backend

_GW_HEX = "aa" * 32
_OC_HEX = "bb" * 32
_CLAW_HEX = "cc" * 32
_GW_KEY = bytes.fromhex(_GW_HEX)
HERMES = {"Authorization": f"Bearer {TOKENS['hermes']}"}
_OWNER_TOKEN = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER_TOKEN}"}
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
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _GW_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", True, raising=False)
    yield gw.app.test_client(), opened
    try:
        opened.close()
    except Exception:  # noqa: BLE001
        pass


# --- shapes ----------------------------------------------------------------------------

def _plan(client):
    body = client.post("/v1/orchestrate", headers=HERMES,
                       json={"objective": _OBJ, "phase": "plan"}).get_json()
    return body["run_id"], body["canonical_plan_hash"]


def _approve(client, run_id, plan_hash):
    return client.post(
        "/v1/approvals", headers=OWNER,
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": "reviewed"},
    ).get_json()["approval_id"]


def _dirty_run(client, opened, monkeypatch):
    """A genuine Class-3 run: authority consumed, mutation may have started, no apply_result.

    This is the shape that motivated the whole basis model — there is no ``apply_result``, so
    a 7C.1 ``verification_result`` cannot legitimately exist for it.
    """
    import hermes.session as hs

    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    original = hs.GovernedSession.execute
    monkeypatch.setattr(hs.GovernedSession, "execute",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    assert client.post("/v1/orchestrate", headers=HERMES,
                       json={"objective": _OBJ, "phase": "execute", "run_id": run_id,
                             "approval_id": approval_id}).status_code == 500
    # Restore explicitly rather than monkeypatch.undo(), which would also unwind the
    # `wired` fixture's own patches (same monkeypatch instance).
    monkeypatch.setattr(hs.GovernedSession, "execute", original)
    reconcile(opened.authority_store, opened.evidence_sink)
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
    assert "apply_result" not in [r.envelope.record_type for r in opened.evidence_sink.records]
    return run_id, approval_id


def _complete_run(client):
    """A run driven all the way through: USED authority and a full signed graph."""
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert client.post("/v1/orchestrate", headers=HERMES,
                       json={"objective": _OBJ, "phase": "execute", "run_id": run_id,
                             "approval_id": approval_id}).get_json()["applied"] is True
    return run_id, approval_id


def _verdict(opened, run_id, approval_id, *statuses):
    """Emit one real signed ``verification_result`` and return its typed reference."""
    report = build_report([
        Finding(f"AC-{i}", f"control {i}", status, "info", "detail")
        for i, status in enumerate(statuses or (PASS,))
    ])
    emit = verification.emit_verification_result(
        opened.evidence_sink, report, run_id=run_id, approval_id=approval_id,
        signing_key=bytes.fromhex(_CLAW_HEX),
        key_id=assurance.EMITTER_KEY_IDS[EMITTER_OPENCLAW],
    )
    assert emit.appended
    return emit.evidence_ref


def _ref(opened, record_type, run_id, emitter=EMITTER_GATEWAY):
    rec = next(r for r in opened.evidence_sink.records
               if r.envelope.record_type == record_type
               and (r.envelope.run_id or "") == run_id
               and r.envelope.emitter == emitter)
    return rec.evidence_ref()


def _append(sink, *, record_type, run_id, approval_id, payload, emitter=EMITTER_GATEWAY,
            key=None, nonce="n-x"):
    """Append one signed record through the sink's real validation path."""
    from openclaw import sink as sinkmod

    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(),
        sink_id=sink.sink_id,
        run_id=run_id,
        emitter=emitter,
        emitter_key_id=assurance.EMITTER_KEY_IDS[emitter],
        record_type=record_type,
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-08-11T00:00:00+00:00",
        nonce=nonce,
        approval_id=approval_id,
    )
    return sink.append(env, payload, sign_envelope(env, key or _GW_KEY))


def _post(client, run_id, approval_id, *, ref, basis_type, disposition=None, headers=None):
    return client.post(
        "/v1/dispositions", headers=headers or OWNER,
        json={"run_id": run_id, "approval_id": approval_id,
              "disposition": disposition or disp.DISPOSITION_CLOSED_UNKNOWN,
              "basis_type": basis_type,
              "basis_ref": ref.to_mapping() if hasattr(ref, "to_mapping") else ref},
    )


def _dispositions(sink):
    return [r for r in sink.records
            if r.envelope.record_type == disp.RUN_DISPOSITION_RECORD_TYPE]


def _owner_denials() -> float:
    for line in gw.METRICS.render().splitlines():
        if line.startswith("gateway_authz_denials_total") and 'owner_required' in line:
            return float(line.rsplit(" ", 1)[1])
    return 0.0


def _resurfacing_dirty_run(client, opened, monkeypatch):
    """A dirty run that genuinely resurfaces on every pass.

    An invalidated run with no evidence at all classifies quietly; the shape that keeps
    demanding attention is one where apply evidence exists against an invalidated run —
    exactly the "did the mutation land?" case a human has to close by hand.
    """
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    reconcile(opened.authority_store, opened.evidence_sink)
    reservation = _ref(opened, "execute_validated", run_id)
    _append(opened.evidence_sink, record_type="apply_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCODE,
            key=bytes.fromhex(_OC_HEX), nonce="n-late-apply",
            payload={"applied": True, "execute_ref": reservation.to_mapping()})
    return run_id, approval_id, reservation


# --- 1. the dirty run with no verdict: the case that had to work ------------------------

def test_a_dirty_run_with_no_verification_result_is_disposable(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    assert verification.verification_results_for(opened.evidence_sink, run_id=run_id) == ()

    resp = _post(client, run_id, approval_id,
                 ref=_ref(opened, "execute_validated", run_id),
                 basis_type=disp.BASIS_EXECUTION_RESERVATION)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["disposition"] == disp.DISPOSITION_CLOSED_UNKNOWN
    assert body["basis_type"] == disp.BASIS_EXECUTION_RESERVATION
    assert body["human_actor"] == "owner"
    assert body["terminal"] is True
    assert len(_dispositions(opened.evidence_sink)) == 1


def test_closed_unknown_asserts_no_outcome(wired, monkeypatch):
    """The default disposition must not claim the mutation did or did not land."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    payload = _dispositions(opened.evidence_sink)[0].payload
    assert payload["disposition"] == "closed_unknown"
    assert "applied" not in str(payload["disposition"])
    validated = disp.disposition_for_run(
        opened.evidence_sink.records, sink_id=opened.evidence_sink.sink_id, run_id=run_id
    )
    assert validated.asserts_outcome is False


def test_a_human_assertion_is_named_as_a_human_assertion(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION,
          disposition=disp.DISPOSITION_HUMAN_ASSERTED_APPLIED)
    payload = _dispositions(opened.evidence_sink)[0].payload
    assert payload["disposition"].startswith("human_asserted_")
    assert payload["human_actor"] == "owner"
    validated = disp.disposition_for_run(
        opened.evidence_sink.records, sink_id=opened.evidence_sink.sink_id, run_id=run_id
    )
    assert validated.asserts_outcome is True


def test_an_unknown_disposition_value_is_refused(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    resp = _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
                 basis_type=disp.BASIS_EXECUTION_RESERVATION, disposition="succeeded")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_INVALID_DISPOSITION
    assert _dispositions(opened.evidence_sink) == []


# --- 2/3. verdict-based disposition: explicit selection, never "latest" -----------------

def test_a_specific_verification_result_can_be_the_basis(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    ref = _verdict(opened, run_id, approval_id, PASS)
    resp = _post(client, run_id, approval_id, ref=ref,
                 basis_type=disp.BASIS_VERIFICATION_RESULT)
    assert resp.status_code == 200
    assert resp.get_json()["basis_type"] == disp.BASIS_VERIFICATION_RESULT
    stored = _dispositions(opened.evidence_sink)[0].payload
    assert stored["basis_ref"]["evidence_id"] == ref.evidence_id


def test_two_verdicts_require_the_caller_to_choose_one(wired):
    """Both verdicts stay resolvable; the disposition binds the one the human named."""
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    first = _verdict(opened, run_id, approval_id, FAIL)
    second = _verdict(opened, run_id, approval_id, PASS)
    assert first.evidence_id != second.evidence_id
    assert len(verification.verification_results_for(
        opened.evidence_sink, run_id=run_id)) == 2

    # The caller picks the *older* one; nothing prefers the newest record.
    assert _post(client, run_id, approval_id, ref=first,
                 basis_type=disp.BASIS_VERIFICATION_RESULT).status_code == 200
    stored = _dispositions(opened.evidence_sink)[0].payload
    assert stored["basis_ref"]["evidence_id"] == first.evidence_id


def test_the_basis_listing_never_recommends_a_verdict(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    _verdict(opened, run_id, approval_id, FAIL)
    _verdict(opened, run_id, approval_id, PASS)
    body = client.get(f"/v1/runs/{run_id}/disposition-basis", headers=OWNER).get_json()
    verdicts = [b for b in body["bases"] if b["basis_type"] == "verification_result"]
    assert len(verdicts) == 2
    assert body["disposition"] is None
    assert not any("recommend" in key or "selected" in key for b in body["bases"] for key in b)


# --- 4-8. basis validation: the server resolves, the caller never supplies evidence -----

def test_a_verification_ref_from_another_run_is_refused(wired):
    client, opened = wired
    run_a, appr_a = _complete_run(client)
    run_b, appr_b = _complete_run(client)
    foreign = _verdict(opened, run_b, appr_b, PASS)
    resp = _post(client, run_a, appr_a, ref=foreign,
                 basis_type=disp.BASIS_VERIFICATION_RESULT)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_RUN_MISMATCH
    assert _dispositions(opened.evidence_sink) == []


def test_a_basis_bound_to_another_approval_is_refused(wired, monkeypatch):
    """Same run, different approval: the binding is checked on both axes."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    # A second, hand-crafted reservation on the same run but a foreign approval id.
    _append(opened.evidence_sink, record_type="execute_validated", run_id=run_id,
            approval_id="appr-" + "f" * 32, nonce="n-foreign",
            payload={"canonical_plan_hash": "sha256:x", "validated": True})
    foreign = next(r for r in opened.evidence_sink.records
                   if r.envelope.approval_id == "appr-" + "f" * 32)
    resp = _post(client, run_id, approval_id, ref=foreign.evidence_ref(),
                 basis_type=disp.BASIS_EXECUTION_RESERVATION)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_APPROVAL_MISMATCH


def test_a_basis_of_the_wrong_record_type_is_refused(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    apply_ref = _ref(opened, "apply_result", run_id, emitter=EMITTER_OPENCODE)
    resp = _post(client, run_id, approval_id, ref=apply_ref,
                 basis_type=disp.BASIS_VERIFICATION_RESULT)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_TYPE_MISMATCH
    assert _dispositions(opened.evidence_sink) == []


def test_a_dangling_basis_reference_is_refused(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    real = _ref(opened, "execute_validated", run_id)
    dangling = real.to_mapping() | {"evidence_id": "ev-" + "0" * 32}
    resp = _post(client, run_id, approval_id, ref=dangling,
                 basis_type=disp.BASIS_EXECUTION_RESERVATION)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_UNRESOLVED


def test_a_forged_basis_digest_is_refused(wired, monkeypatch):
    """The server recomputes the digest, so naming a real record is not enough."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    real = _ref(opened, "execute_validated", run_id)
    forged = real.to_mapping() | {"evidence_digest": "sha256:" + "0" * 64}
    resp = _post(client, run_id, approval_id, ref=forged,
                 basis_type=disp.BASIS_EXECUTION_RESERVATION)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_UNRESOLVED
    assert _dispositions(opened.evidence_sink) == []


def test_a_malformed_basis_reference_is_refused(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    resp = _post(client, run_id, approval_id, ref={"evidence_id": "ev-" + "1" * 32},
                 basis_type=disp.BASIS_EXECUTION_RESERVATION)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_MALFORMED


def test_an_unknown_basis_type_is_refused(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    resp = _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
                 basis_type="approval_decided")
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_INVALID_BASIS_TYPE


def test_a_verdict_basis_must_be_authored_by_the_verifier(wired, monkeypatch):
    """A ``verification_result`` signed by the gateway is not a verifier verdict."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _append(opened.evidence_sink, record_type="verification_result", run_id=run_id,
            approval_id=approval_id, nonce="n-fake-verdict",
            payload={"verdict": "PASS"}, emitter=EMITTER_GATEWAY)
    fake = next(r for r in opened.evidence_sink.records
                if r.envelope.record_type == "verification_result")
    resp = _post(client, run_id, approval_id, ref=fake.evidence_ref(),
                 basis_type=disp.BASIS_VERIFICATION_RESULT)
    assert resp.status_code == 400
    assert resp.get_json()["error"]["code"] == disp.CODE_BASIS_EMITTER_INVALID


def test_an_unknown_run_is_refused(wired):
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    ref = _verdict(opened, run_id, approval_id, PASS)
    resp = _post(client, "run-does-not-exist", approval_id, ref=ref,
                 basis_type=disp.BASIS_VERIFICATION_RESULT)
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == disp.CODE_RUN_NOT_FOUND


def test_a_run_with_standing_authority_cannot_be_disposed(wired):
    """Disposal closes finished history; it is not a covert kill switch for a live run."""
    client, opened = wired
    run_id, plan_hash = _plan(client)
    approval_id = _approve(client, run_id, plan_hash)
    ref = _ref(opened, "approval_decided", run_id)
    resp = client.post(
        "/v1/dispositions", headers=OWNER,
        json={"run_id": run_id, "approval_id": approval_id,
              "disposition": disp.DISPOSITION_CLOSED_UNKNOWN,
              "basis_type": disp.BASIS_EXECUTION_RESERVATION,
              "basis_ref": ref.to_mapping()},
    )
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == disp.CODE_RUN_NOT_TERMINAL
    assert opened.authority_store.get_approval(approval_id).approval_status is (
        ApprovalStatus.APPROVED
    )


# --- 9/10. only a human disposes --------------------------------------------------------

@pytest.mark.parametrize("who", ["hermes", "opencode", "openclaw"])
def test_no_agent_principal_may_dispose_a_run(wired, monkeypatch, who):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    resp = _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
                 basis_type=disp.BASIS_EXECUTION_RESERVATION,
                 headers={"Authorization": f"Bearer {TOKENS[who]}"})
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "owner_required"
    assert _dispositions(opened.evidence_sink) == []


def test_a_non_owner_denial_increments_the_reconcilable_counter(wired, monkeypatch):
    """A 403 in the audit with no matching metric would fail OpenClaw's next run."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    before = _owner_denials()
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION,
          headers={"Authorization": f"Bearer {TOKENS['hermes']}"})
    assert _owner_denials() == before + 1


def test_the_basis_listing_is_owner_gated(wired, monkeypatch):
    client, opened = wired
    run_id, _ = _dirty_run(client, opened, monkeypatch)
    resp = client.get(f"/v1/runs/{run_id}/disposition-basis", headers=HERMES)
    assert resp.status_code == 403
    assert resp.get_json()["error"]["code"] == "owner_required"


# --- 11/12. terminality -----------------------------------------------------------------

def test_a_second_disposition_is_refused_and_appends_nothing(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    ref = _ref(opened, "execute_validated", run_id)
    assert _post(client, run_id, approval_id, ref=ref,
                 basis_type=disp.BASIS_EXECUTION_RESERVATION).status_code == 200
    first = _dispositions(opened.evidence_sink)[0].envelope.evidence_id

    resp = _post(client, run_id, approval_id, ref=ref,
                 basis_type=disp.BASIS_EXECUTION_RESERVATION,
                 disposition=disp.DISPOSITION_HUMAN_ASSERTED_NOT_APPLIED)
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == disp.CODE_ALREADY_DISPOSED
    remaining = _dispositions(opened.evidence_sink)
    assert len(remaining) == 1
    assert remaining[0].envelope.evidence_id == first          # not superseded


def test_concurrent_dispositions_produce_exactly_one_terminal_record(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    ref = _ref(opened, "execute_validated", run_id)
    at_boundary = threading.Barrier(2, timeout=5.0)
    results: list = []

    def attempt():
        try:
            at_boundary.wait()
        except threading.BrokenBarrierError:  # pragma: no cover - only on timeout
            pass
        try:
            results.append(disp.dispose_run(
                opened.authority_store, opened.evidence_sink,
                run_id=run_id, approval_id=approval_id,
                disposition=disp.DISPOSITION_CLOSED_UNKNOWN,
                basis_type=disp.BASIS_EXECUTION_RESERVATION,
                basis_ref=ref.to_mapping(), human_actor="owner",
                signing_key=_GW_KEY, key_id=assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY],
            ).disposition)
        except disp.DispositionError as exc:
            results.append(exc.code)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    assert sorted(results) == [disp.CODE_ALREADY_DISPOSED, disp.DISPOSITION_CLOSED_UNKNOWN]
    assert len(_dispositions(opened.evidence_sink)) == 1


# --- 13/14. late evidence cannot resurrect or supersede ---------------------------------

def test_a_late_apply_result_cannot_resurrect_a_disposed_run(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    reservation = _ref(opened, "execute_validated", run_id)
    _post(client, run_id, approval_id, ref=reservation,
          basis_type=disp.BASIS_EXECUTION_RESERVATION)

    _append(opened.evidence_sink, record_type="apply_result", run_id=run_id,
            approval_id=approval_id, emitter=EMITTER_OPENCODE,
            key=bytes.fromhex(_OC_HEX), nonce="n-late-apply",
            payload={"applied": True, "execute_ref": reservation.to_mapping()})

    report = reconcile(opened.authority_store, opened.evidence_sink)
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
    finding = next(f for f in report.findings if f.run_id == run_id)
    assert finding.disposed is True
    assert finding.outcome != reconciliation.OUTCOME_CLEAN
    assert report.outstanding == ()
    assert len(_dispositions(opened.evidence_sink)) == 1


def test_a_late_verification_result_cannot_supersede_a_disposition(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    before = disp.disposition_for_run(
        opened.evidence_sink.records, sink_id=opened.evidence_sink.sink_id, run_id=run_id
    )
    _verdict(opened, run_id, approval_id, FAIL)
    after = disp.disposition_for_run(
        opened.evidence_sink.records, sink_id=opened.evidence_sink.sink_id, run_id=run_id
    )
    assert after == before
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED


def test_a_disposed_run_cannot_be_approved_or_executed_again(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    plan_hash = opened.authority_store.get_run(run_id).canonical_plan_hash
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)

    denied = client.post("/v1/approvals", headers=OWNER,
                         json={"run_id": run_id, "canonical_plan_hash": plan_hash,
                               "decision": "approve", "reason": "again"})
    assert denied.status_code == 409
    result = client.post("/v1/orchestrate", headers=HERMES,
                         json={"objective": _OBJ, "phase": "execute", "run_id": run_id,
                               "approval_id": approval_id}).get_json()
    assert result["refused"] is True
    assert result.get("applied") is not True


# --- 15/16. restart, and fail-closed reading --------------------------------------------

def test_a_disposition_survives_a_restart_with_its_basis_and_chain(tmp_path, wired,
                                                                   monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    opened.close()

    reopened = _open(tmp_path)
    try:
        reopened.evidence_sink.verify_chain()
        validated = disp.disposition_for_run(
            reopened.evidence_sink.records, sink_id=reopened.evidence_sink.sink_id,
            run_id=run_id,
        )
        assert validated is not None
        assert validated.disposition == disp.DISPOSITION_CLOSED_UNKNOWN
        assert validated.human_actor == "owner"
        assert reopened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED
        report = reconcile(reopened.authority_store, reopened.evidence_sink)
        assert report.outstanding == ()
    finally:
        reopened.close()


def test_a_tampered_disposition_fails_startup_closed(wired, monkeypatch):
    """A disposition whose basis no longer binds must not read as 'not yet disposed'."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    reservation = _ref(opened, "execute_validated", run_id)
    tampered = reservation.to_mapping() | {"evidence_digest": "sha256:" + "9" * 64}
    _append(opened.evidence_sink, record_type=disp.RUN_DISPOSITION_RECORD_TYPE,
            run_id=run_id, approval_id=approval_id, nonce="n-tampered",
            payload={"disposition": disp.DISPOSITION_CLOSED_UNKNOWN,
                     "basis_type": disp.BASIS_EXECUTION_RESERVATION,
                     "basis_ref": tampered, "human_actor": "owner"})
    with pytest.raises(ReconciliationError) as exc:
        reconcile(opened.authority_store, opened.evidence_sink)
    assert disp.CODE_BASIS_UNRESOLVED in str(exc.value)


def test_two_dispositions_on_one_run_fail_startup_closed(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    ref = _ref(opened, "execute_validated", run_id).to_mapping()
    payload = {"disposition": disp.DISPOSITION_CLOSED_UNKNOWN,
               "basis_type": disp.BASIS_EXECUTION_RESERVATION,
               "basis_ref": ref, "human_actor": "owner"}
    _append(opened.evidence_sink, record_type=disp.RUN_DISPOSITION_RECORD_TYPE,
            run_id=run_id, approval_id=approval_id, nonce="n-d1", payload=payload)
    _append(opened.evidence_sink, record_type=disp.RUN_DISPOSITION_RECORD_TYPE,
            run_id=run_id, approval_id=approval_id, nonce="n-d2", payload=payload)
    with pytest.raises(ReconciliationError) as exc:
        reconcile(opened.authority_store, opened.evidence_sink)
    assert disp.CODE_AMBIGUOUS_DISPOSITION in str(exc.value)


def test_a_disposition_authored_by_the_verifier_fails_closed(wired, monkeypatch):
    """Only the authority plane may author a disposition; OpenClaw never decides one."""
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _append(opened.evidence_sink, record_type=disp.RUN_DISPOSITION_RECORD_TYPE,
            run_id=run_id, approval_id=approval_id, nonce="n-claw",
            emitter=EMITTER_OPENCLAW, key=bytes.fromhex(_CLAW_HEX),
            payload={"disposition": disp.DISPOSITION_CLOSED_UNKNOWN,
                     "basis_type": disp.BASIS_EXECUTION_RESERVATION,
                     "basis_ref": _ref(opened, "execute_validated", run_id).to_mapping(),
                     "human_actor": "openclaw"})
    with pytest.raises(ReconciliationError) as exc:
        reconcile(opened.authority_store, opened.evidence_sink)
    assert disp.CODE_BASIS_EMITTER_INVALID in str(exc.value)


# --- reconciliation integration ---------------------------------------------------------

def test_a_disposition_retires_the_finding_without_softening_the_class(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id, reservation = _resurfacing_dirty_run(client, opened, monkeypatch)
    before = reconcile(opened.authority_store, opened.evidence_sink)
    outstanding = next(f for f in before.outstanding if f.run_id == run_id)
    assert outstanding.class_id == 3

    _post(client, run_id, approval_id, ref=reservation,
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    after = reconcile(opened.authority_store, opened.evidence_sink)
    finding = next(f for f in after.findings if f.run_id == run_id)
    assert finding.class_id == 3                             # history is not rewritten
    assert finding.outcome != reconciliation.OUTCOME_CLEAN
    assert finding.disposition == disp.DISPOSITION_CLOSED_UNKNOWN
    assert after.outstanding == ()
    assert after.disposed


def test_an_undisposed_dirty_run_is_still_surfaced_every_startup(wired, monkeypatch):
    client, opened = wired
    run_id, _, _ = _resurfacing_dirty_run(client, opened, monkeypatch)
    for _ in range(3):
        report = reconcile(opened.authority_store, opened.evidence_sink)
        assert any(f.run_id == run_id for f in report.outstanding)


def test_a_disposition_never_reopens_or_reinstates_authority(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    before = opened.authority_store.get_approval(approval_id).approval_status
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    after = opened.authority_store.get_approval(approval_id)
    assert after.approval_status is before            # authority is not rewritten
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED


class _RunReopened:
    """An authority store that reports one run as OPEN — the state the seal prevents."""

    def __init__(self, inner, run_id):
        self._inner, self._run_id = inner, run_id
        self.invalidated: list[str] = []

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def get_run(self, run_id):
        run = self._inner.get_run(run_id)
        if run is not None and run_id == self._run_id:
            run.status = RunStatus.OPEN   # a detached copy; the store is untouched
        return run

    def invalidate_run(self, run_id):
        self.invalidated.append(run_id)
        self._inner.invalidate_run(run_id)


def test_reconciliation_invalidates_a_disposed_run_that_is_somehow_still_open(wired):
    """A disposition on a live run is a cross-store contradiction, handled as class 5."""
    client, opened = wired
    run_id, approval_id = _complete_run(client)
    ref = _verdict(opened, run_id, approval_id, PASS)
    assert _post(client, run_id, approval_id, ref=ref,
                 basis_type=disp.BASIS_VERIFICATION_RESULT).status_code == 200

    view = _RunReopened(opened.authority_store, run_id)
    report = reconcile(view, opened.evidence_sink)
    assert run_id in view.invalidated
    assert any(f.class_id == 5 and f.run_id == run_id for f in report.findings)
    assert opened.authority_store.get_run(run_id).status is RunStatus.INVALIDATED


def test_the_disposition_payload_carries_nothing_sensitive(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    payload = _dispositions(opened.evidence_sink)[0].payload
    assert set(payload) == {"disposition", "basis_type", "basis_ref", "human_actor"}
    assert _OBJ not in str(payload)
    assert _OWNER_TOKEN not in str(payload)
    assert _GW_HEX not in str(payload)


def test_the_disposition_is_signed_by_the_authority_plane(wired, monkeypatch):
    client, opened = wired
    run_id, approval_id = _dirty_run(client, opened, monkeypatch)
    _post(client, run_id, approval_id, ref=_ref(opened, "execute_validated", run_id),
          basis_type=disp.BASIS_EXECUTION_RESERVATION)
    env = _dispositions(opened.evidence_sink)[0].envelope
    assert env.emitter == EMITTER_GATEWAY
    assert env.emitter_key_id == assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY]
    assert env.run_id == run_id and env.approval_id == approval_id
    opened.evidence_sink.verify_chain()
