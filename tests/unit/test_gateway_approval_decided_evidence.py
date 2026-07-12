"""Step 5b — gateway ``approval_decided`` authorization evidence emit.

When an approval decision (approve OR reject) is recorded at ``POST /v1/approvals``, the
gateway emits ONE signed ``approval_decided`` record into an injected, verifier-owned
:class:`EvidenceSink` — before the decision response is returned. This is additive: with no
sink configured the endpoint behaves byte-for-byte as before.

Scope of this suite (and this increment): decision-time emit only. It does NOT exercise
``evidence_refs``, runtime fail-closed consume, OpenClaw/OpenCode changes, a trust ledger, or
earned autonomy — those are later, separately-authorized steps. The record is *decision*
evidence (authority granted/denied), distinct from Step 5's ``execute_validated`` (authority
consumed). The sink/key here are ephemeral and in-memory; nothing is loaded from disk or env.
"""

from __future__ import annotations

import subprocess

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.demo import TOKENS, install_demo_plane

HERMES = f"Bearer {TOKENS['hermes']}"
_OBJ = "Apply the reviewed fix and verify it"
_OWNER_TOKEN = "test-owner-break-glass-token"

# An ephemeral, in-test signing key — 32 bytes, never a production secret, never loaded from
# disk/env. Registered under the gateway emitter identity for the injected sink.
_TEST_KEY = b"0123456789abcdef0123456789abcdef"
_TEST_KEY_ID = "gw-test-1"


# --- harness (mirrors tests/unit/test_gateway_authorization_evidence.py) -----------------
@pytest.fixture
def client():
    install_demo_plane(gw)
    return gw.app.test_client()


@pytest.fixture
def owner_token(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    return _OWNER_TOKEN


def _owner_hdr():
    return {"Authorization": f"Bearer {_OWNER_TOKEN}"}


def _post(client, **body):
    return client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES}, json=body
    ).get_json()


def _plan_and_hash(client):
    body = _post(client, objective=_OBJ, phase="plan")
    return body["run_id"], body["canonical_plan_hash"]


def _decide_raw(client, run_id, plan_hash, *, decision, reason=""):
    """Raw approval POST — returns the response so error/refusal paths can be asserted."""
    return client.post(
        "/v1/approvals",
        headers=_owner_hdr(),
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": decision, "reason": reason},
    )


def _approve(client, run_id, plan_hash, reason="reviewed the diff"):
    r = _decide_raw(client, run_id, plan_hash, decision="approve", reason=reason)
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def _reject(client, run_id, plan_hash, reason="scope too broad"):
    r = _decide_raw(client, run_id, plan_hash, decision="reject", reason=reason)
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def _execute(client, run_id, approval_id, objective=_OBJ):
    return _post(client, objective=objective, phase="execute",
                 run_id=run_id, approval_id=approval_id)


def _install_sink(monkeypatch, *, sink_id="sink-test", require=False):
    """Inject an ephemeral in-memory sink + gateway key via monkeypatch (auto-reverted)."""
    from openclaw.sink import EMITTER_GATEWAY, EmitterKeyRegistry, EvidenceSink

    registry = EmitterKeyRegistry()
    registry.register(EMITTER_GATEWAY, _TEST_KEY_ID, _TEST_KEY)
    sink = EvidenceSink(sink_id, registry)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _TEST_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", _TEST_KEY_ID)
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", require)
    return sink


class _FailingSink:
    """A sink whose ``append`` always fails — to exercise the emit-failure policy."""

    sink_id = "sink-fail"

    def append(self, *args, **kwargs):
        from openclaw.sink import EvidenceError

        raise EvidenceError("append refused (test double)")


def _install_failing_sink(monkeypatch, *, require):
    sink = _FailingSink()
    monkeypatch.setattr(gw, "EVIDENCE_SINK", sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _TEST_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", _TEST_KEY_ID)
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", require)
    return sink


def _decision_records(sink):
    from openclaw.sink import EMITTER_GATEWAY

    return [
        r for r in sink.records
        if r.envelope.emitter == EMITTER_GATEWAY
        and r.envelope.record_type == "approval_decided"
    ]


def _execute_validated_records(sink):
    from openclaw.sink import EMITTER_GATEWAY

    return [
        r for r in sink.records
        if r.envelope.emitter == EMITTER_GATEWAY
        and r.envelope.record_type == "execute_validated"
    ]


# --- 1. no-sink compatibility -----------------------------------------------------------
def test_no_sink_preserves_approval_behavior(client, owner_token):
    # Default: no evidence plane -> the approval endpoint behaves exactly as before.
    assert gw.EVIDENCE_SINK is None
    run_id, plan_hash = _plan_and_hash(client)
    r = _decide_raw(client, run_id, plan_hash, decision="approve")
    assert r.status_code == 200
    body = r.get_json()
    assert body["run_id"] == run_id
    assert body["approval_status"] == "approved"
    assert body["canonical_plan_hash"] == plan_hash
    # And reject is still a governed 200 success.
    run2, hash2 = _plan_and_hash(client)
    r2 = _decide_raw(client, run2, hash2, decision="reject", reason="nope")
    assert r2.status_code == 200 and r2.get_json()["approval_status"] == "rejected"


# --- 2. approve emits approval_decided --------------------------------------------------
def test_approve_emits_approval_decided(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    assert len(_decision_records(sink)) == 1


# --- 3. reject emits approval_decided ---------------------------------------------------
def test_reject_emits_approval_decided(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _reject(client, run_id, plan_hash)
    assert len(_decision_records(sink)) == 1


# --- 4. emitter + record_type -----------------------------------------------------------
def test_record_emitter_and_type(client, owner_token, monkeypatch):
    from openclaw.sink import EMITTER_GATEWAY

    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    rec = _decision_records(sink)[0]
    assert rec.envelope.emitter == EMITTER_GATEWAY
    assert rec.envelope.record_type == "approval_decided"


# --- 5. envelope carries run_id ---------------------------------------------------------
def test_envelope_carries_run_id(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    assert _decision_records(sink)[0].envelope.run_id == run_id


# --- 6. envelope carries approval_id ----------------------------------------------------
def test_envelope_carries_approval_id(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    assert _decision_records(sink)[0].envelope.approval_id == approval_id


# --- 7. payload decision field ----------------------------------------------------------
def test_payload_decision_field(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_a, hash_a = _plan_and_hash(client)
    _approve(client, run_a, hash_a)
    run_r, hash_r = _plan_and_hash(client)
    _reject(client, run_r, hash_r)
    decisions = [r.payload["decision"] for r in _decision_records(sink)]
    assert decisions == ["approve", "reject"]


# --- 8. payload approver ----------------------------------------------------------------
def test_payload_approver(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    assert _decision_records(sink)[0].payload["approver"] == gw.OWNER_PRINCIPAL.name


# --- 9. payload canonical_plan_hash -----------------------------------------------------
def test_payload_canonical_plan_hash(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    assert _decision_records(sink)[0].payload["canonical_plan_hash"] == plan_hash


# --- 10. payload has no secrets / free-text reason --------------------------------------
def test_payload_has_no_secrets_or_reason(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    secret_reason = "SENSITIVE-REJECT-NOTE-do-not-sign-this"
    _reject(client, run_id, plan_hash, reason=secret_reason)
    payload = _decision_records(sink)[0].payload
    # Exactly the approved key set — no broader.
    assert set(payload.keys()) == {"decision", "approver", "canonical_plan_hash"}
    # The free-text rejection reason is deliberately excluded from the signed record.
    assert secret_reason not in str(payload)
    # No token / bearer material leaked into the record.
    assert _OWNER_TOKEN not in str(payload)
    for key in ("token", "authorization", "reason", "objective", "prompt"):
        assert key not in payload


# --- 11. chain verifies after a decision emit -------------------------------------------
def test_verify_chain_passes_after_decision(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    sink.verify_chain()  # raises on any integrity violation; silence == pass


# --- 12. no execute_validated at decision time ------------------------------------------
def test_no_execute_validated_at_decision_time(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)  # decision only; no execute
    types = {r.envelope.record_type for r in sink.records}
    assert types == {"approval_decided"}
    assert _execute_validated_records(sink) == []


# --- 13. evidence_refs untouched --------------------------------------------------------
def test_no_evidence_refs_populated(client, owner_token, monkeypatch):
    _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    # Step 5b does not bind approvals to sink records; the placeholder stays empty.
    assert gw.APPROVAL_STORE.get_approval(approval_id).evidence_refs == ()


# --- 14. require False preserves the decision when emit fails ----------------------------
def test_require_false_preserves_decision_when_emit_fails(client, owner_token, monkeypatch):
    _install_failing_sink(monkeypatch, require=False)
    run_id, plan_hash = _plan_and_hash(client)
    r = _decide_raw(client, run_id, plan_hash, decision="approve")
    # Best-effort: a failed emit does not change the governed outcome when not required.
    assert r.status_code == 200
    body = r.get_json()
    assert body["approval_status"] == "approved"
    # The approval remains usable at execute (the run was not invalidated).
    ex = _execute(client, run_id, body["approval_id"])
    assert ex["applied"] is True


# --- 15. require True + NO sink denies the decision -------------------------------------
def test_require_true_no_sink_denies_decision(client, owner_token, monkeypatch):
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    assert gw.EVIDENCE_SINK is None
    run_id, plan_hash = _plan_and_hash(client)
    r = _decide_raw(client, run_id, plan_hash, decision="approve")
    assert r.status_code == 503
    err = r.get_json()["error"]
    assert err["code"] == "authorization_evidence_unavailable"
    # Static, client-safe message — no internal path/key/exception detail.
    assert err["message"] == (
        "The approval evidence record could not be recorded — approval denied"
    )
    # Fail closed: the run was invalidated, so nothing can be executed under it.
    assert gw.APPROVAL_STORE.get_run(run_id).status.value == "invalidated"


# --- 16. require True + missing key denies the decision ---------------------------------
def test_require_true_missing_key_denies_decision(client, owner_token, monkeypatch):
    _install_sink(monkeypatch, require=True)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", None)
    run_id, plan_hash = _plan_and_hash(client)
    r = _decide_raw(client, run_id, plan_hash, decision="approve")
    assert r.status_code == 503
    assert r.get_json()["error"]["code"] == "authorization_evidence_unavailable"
    assert gw.APPROVAL_STORE.get_run(run_id).status.value == "invalidated"


# --- 17. require True + emit failure denies the decision --------------------------------
def test_require_true_emit_failure_denies_decision(client, owner_token, monkeypatch):
    _install_failing_sink(monkeypatch, require=True)
    run_id, plan_hash = _plan_and_hash(client)
    r = _decide_raw(client, run_id, plan_hash, decision="reject", reason="whatever")
    # Even a reject decision fails closed under require when the record cannot land.
    assert r.status_code == 503
    assert r.get_json()["error"]["code"] == "authorization_evidence_unavailable"
    assert gw.APPROVAL_STORE.get_run(run_id).status.value == "invalidated"


# --- 18. exactly one record per decision ------------------------------------------------
def test_one_record_per_decision(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    assert len(_decision_records(sink)) == 1


# --- 19. approve then execute sequences approval_decided then execute_validated ---------
def test_approve_then_execute_sequences_approval_decided_then_execute_validated(
    client, owner_token, monkeypatch
):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is True
    # Decision evidence lands first (at approve), execute evidence second (at execute).
    from openclaw.sink import EMITTER_GATEWAY

    ordered = [
        r.envelope.record_type for r in sink.records
        if r.envelope.emitter == EMITTER_GATEWAY
    ]
    assert ordered == ["approval_decided", "execute_validated"]


# --- 20. reject emits decision and no execute_validated ---------------------------------
def test_reject_emits_decision_and_no_execute_validated(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _reject(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False and ex["refusal_reason"] == "rejected"
    assert len(_decision_records(sink)) == 1
    assert _execute_validated_records(sink) == []


# --- 21. no OpenCode / OpenClaw runtime (or docs/site/static) files touched -------------
def test_no_opencode_or_openclaw_runtime_files_touched():
    import pathlib

    repo = pathlib.Path(gw.__file__).resolve().parents[2]
    out = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout
    changed = [line[3:].strip() for line in out.splitlines() if line.strip()]
    forbidden_prefixes = (
        "agents/openclaw/", "agents/opencode_sandbox/",
        "src/private_ai_gateway/static/", "docs/", "site/",
    )
    offenders = [
        p for p in changed
        if p.startswith(forbidden_prefixes) or p == "pyproject.toml"
    ]
    assert offenders == [], f"out-of-scope files changed: {offenders}"


# --- 22. no disk/env key loading in the shared emit helper ------------------------------
def test_no_disk_or_env_key_loading():
    import pathlib

    root = pathlib.Path(gw.__file__).parent
    orch_src = (root / "orchestration.py").read_text(encoding="utf-8")
    # The shared emit core resolves its key only from the injected gateway attributes — never
    # from the environment or a file. Guard the whole core + both thin wrappers.
    emit_region = orch_src[orch_src.index("def _emit_gateway_evidence"):]
    emit_region = emit_region[: emit_region.index("def _execute_refusal")]
    for forbidden in ("os.environ", "os.getenv", "getenv(", "open("):
        assert forbidden not in emit_region, f"emit helper must not use {forbidden!r}"


# --- 23. no hardcoded production key / sink ---------------------------------------------
def test_no_hardcoded_production_key():
    # The module defaults are inert injection points: no sink, no key, no key id, not required.
    assert gw.EVIDENCE_SINK is None
    assert gw.EVIDENCE_KEY is None
    assert gw.EVIDENCE_KEY_ID == ""
    assert gw.REQUIRE_AUTHORIZATION_EVIDENCE is False


# --- 14. Step 6A: the emitted decision record is v2 with a stable evidence_id ------------
def test_approval_decided_record_is_v2_with_evidence_id(client, owner_token, monkeypatch):
    import re

    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _approve(client, run_id, plan_hash)
    rec = _decision_records(sink)[0]
    assert rec.envelope.schema_version == 2
    assert re.match(r"^ev-[0-9a-f]{32}$", rec.envelope.evidence_id)
    # A stable EvidenceRef is derivable; the payload contract is unchanged (no ref embedded).
    assert rec.evidence_ref().record_type == "approval_decided"
    assert set(rec.payload.keys()) == {"decision", "approver", "canonical_plan_hash"}
