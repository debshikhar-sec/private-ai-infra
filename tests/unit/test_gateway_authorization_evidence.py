"""Step 5 — gateway ``execute_validated`` authorization evidence emit.

When execution authority is granted (a durable, owner-approved, single-use approval is
validated and consumed) the gateway emits ONE signed ``execute_validated`` record into an
injected, verifier-owned :class:`EvidenceSink` — *before* any mutation. This is additive:
with no sink configured the governed loop behaves byte-for-byte as before.

Scope of this suite (and this increment): emit only. It does NOT exercise ``approval_decided``,
``evidence_refs``, runtime fail-closed consume, or any OpenClaw/OpenCode change — those are
later, separately-authorized steps. The sink/key here are ephemeral and in-memory; nothing is
loaded from disk or env.
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


# --- harness (mirrors tests/unit/test_orchestration_chat.py; kept self-contained) -------
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


def _approve(client, run_id, plan_hash, reason="reviewed the diff"):
    r = client.post(
        "/v1/approvals",
        headers=_owner_hdr(),
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": reason},
    )
    assert r.status_code == 200
    return r.get_json()["approval_id"]


def _reject(client, run_id, plan_hash, reason="scope too broad"):
    r = client.post(
        "/v1/approvals",
        headers=_owner_hdr(),
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "reject", "reason": reason},
    )
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


def _gateway_records(sink):
    """Gateway `execute_validated` records only.

    Since Step 5b, the gateway also emits `approval_decided` records into the same sink, so
    filtering on emitter alone is no longer specific to this suite. These Step 5 assertions
    count the execute-authorization record precisely by also matching its record_type.
    """
    from openclaw.sink import EMITTER_GATEWAY

    return [
        r for r in sink.records
        if r.envelope.emitter == EMITTER_GATEWAY
        and r.envelope.record_type == "execute_validated"
    ]


# --- 1. no-sink compatibility -----------------------------------------------------------
def test_no_sink_preserves_execute_applies(client, owner_token):
    # Default app has no sink; the golden plan -> approve -> execute path is unchanged.
    assert gw.EVIDENCE_SINK is None
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is True and ex["verdict"] == "PASS"
    assert ex["run_id"] == run_id


# --- 2. emit happens on a granted execute -----------------------------------------------
def test_sink_emits_execute_validated_on_grant(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is True
    assert len(_gateway_records(sink)) == 1


# --- 3. emitter + record_type -----------------------------------------------------------
def test_record_has_gateway_emitter_and_type(client, owner_token, monkeypatch):
    from openclaw.sink import EMITTER_GATEWAY

    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    rec = _gateway_records(sink)[0]
    assert rec.envelope.emitter == EMITTER_GATEWAY
    assert rec.envelope.record_type == "execute_validated"


# --- 4. envelope carries run_id ---------------------------------------------------------
def test_record_envelope_carries_run_id(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    assert _gateway_records(sink)[0].envelope.run_id == run_id


# --- 5. envelope carries approval_id ----------------------------------------------------
def test_record_envelope_carries_approval_id(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    _execute(client, run_id, approval_id)
    assert _gateway_records(sink)[0].envelope.approval_id == approval_id


# --- 6. payload contract ----------------------------------------------------------------
def test_payload_has_canonical_plan_hash_and_validated_true(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    payload = _gateway_records(sink)[0].payload
    # The server recomputes the canonical hash at execute; it must equal the approved plan's.
    assert payload["canonical_plan_hash"] == plan_hash
    assert payload["validated"] is True


# --- 7. payload carries no secrets ------------------------------------------------------
def test_payload_has_no_secrets_or_tokens(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    payload = _gateway_records(sink)[0].payload
    # Exactly the two authorization-fact fields — no tokens, prompts, bodies, or plan text.
    assert set(payload.keys()) == {"canonical_plan_hash", "validated"}


# --- 8. chain still verifies ------------------------------------------------------------
def test_verify_chain_passes_after_gateway_emit(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    sink.verify_chain()  # raises on any integrity violation; silence == pass


# --- 9. emit precedes the mutation ------------------------------------------------------
def test_emit_happens_before_session_execute(client, owner_token, monkeypatch):
    import hermes.session as hs

    sink = _install_sink(monkeypatch)
    seen = {}
    original = hs.GovernedSession.execute

    def spy(self, approver, reason):
        # Capture how many gateway records exist at the instant execute (the mutation) runs.
        seen["records_at_execute"] = len(_gateway_records(sink))
        return original(self, approver, reason)

    monkeypatch.setattr(hs.GovernedSession, "execute", spy)
    run_id, plan_hash = _plan_and_hash(client)
    ex = _execute(client, run_id, _approve(client, run_id, plan_hash))
    assert ex["applied"] is True
    # The record was already appended BEFORE session.execute (the mutation) was invoked.
    assert seen["records_at_execute"] == 1


# --- 10. no emit on a rejected approval -------------------------------------------------
def test_no_emit_on_rejected_approval(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _reject(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False and ex["refusal_reason"] == "rejected"
    assert _gateway_records(sink) == []


# --- 11. no emit on hash mismatch -------------------------------------------------------
def test_no_emit_on_hash_mismatch(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id, objective="a different objective entirely")
    assert ex["applied"] is False and ex["refusal_reason"] == "hash_mismatch"
    assert _gateway_records(sink) == []


# --- 12. no emit on an already-used approval --------------------------------------------
def test_no_emit_on_already_used_approval(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    first = _execute(client, run_id, approval_id)
    assert first["applied"] is True
    second = _execute(client, run_id, approval_id)  # single-use replay
    assert second["applied"] is False and second["refusal_reason"] == "replay"
    # Exactly one record: the replay was refused before any second emit.
    assert len(_gateway_records(sink)) == 1


# --- 13. require flag denies when emit fails --------------------------------------------
def test_require_authorization_evidence_denies_execute_when_emit_fails(
    client, owner_token, monkeypatch
):
    # Since Step 5b the require flag also gates the approval decision, so obtain the approval
    # first (best-effort), then make the *execute* emit fail under require to isolate this gate.
    _install_sink(monkeypatch, require=False)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", _FailingSink())
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False and ex["verdict"] == "REFUSED"
    assert ex["refusal_reason"] == "authorization_evidence_unavailable"
    assert ex["chain"] == []  # no delegation/mutation happened


# --- 14. require False proceeds when emit fails -----------------------------------------
def test_require_false_preserves_execute_when_emit_fails(client, owner_token, monkeypatch):
    _install_failing_sink(monkeypatch, require=False)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    ex = _execute(client, run_id, approval_id)
    # Best-effort: a failed emit does not change the governed outcome when not required.
    assert ex["applied"] is True and ex["verdict"] == "PASS"


# --- 14a. require True + NO sink denies before mutation ---------------------------------
def test_require_authorization_evidence_denies_execute_when_no_sink(
    client, owner_token, monkeypatch
):
    # Required, but no evidence plane is configured: fail closed before any mutation. Obtain
    # the approval first (no sink, not required), then require evidence for the execute.
    assert gw.EVIDENCE_SINK is None
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False and ex["verdict"] == "REFUSED"
    assert ex["refusal_reason"] == "authorization_evidence_unavailable"
    assert ex["chain"] == []  # no delegation/mutation happened
    # The refusal message is static — it must not leak an internal path/key/exception text.
    detail = ex["steps"][0]["detail"]
    assert detail == "the authorization evidence record could not be recorded — execution denied"


# --- 14b. require True + missing key denies before mutation -----------------------------
def test_require_authorization_evidence_denies_execute_when_key_missing(
    client, owner_token, monkeypatch
):
    # A sink is present but the gateway signing key is absent: fail closed under require.
    # Approve first (not required), then drop the key and require evidence for the execute.
    _install_sink(monkeypatch, require=False)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", None)
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    ex = _execute(client, run_id, approval_id)
    assert ex["applied"] is False and ex["verdict"] == "REFUSED"
    assert ex["refusal_reason"] == "authorization_evidence_unavailable"
    assert ex["chain"] == []


# --- 15. exactly one emit per grant -----------------------------------------------------
def test_single_emit_per_grant_is_deterministic(client, owner_token, monkeypatch):
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    assert len(_gateway_records(sink)) == 1


# --- 16. evidence_refs untouched --------------------------------------------------------
def test_no_evidence_refs_populated_yet(client, owner_token, monkeypatch):
    _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    _execute(client, run_id, approval_id)
    # Step 5 does not bind approvals to sink records; the placeholder stays empty.
    assert gw.APPROVAL_STORE.get_approval(approval_id).evidence_refs == ()


# --- 17. execute still emits exactly one execute_validated (approval_decided co-exists) ---
def test_execute_emits_single_execute_validated_alongside_approval_decided(
    client, owner_token, monkeypatch
):
    # Since Step 5b the approve also emits an `approval_decided` record into the same sink.
    # The Step 5 guarantee is unchanged: the execute step emits exactly one `execute_validated`.
    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    _execute(client, run_id, _approve(client, run_id, plan_hash))
    types = {r.envelope.record_type for r in sink.records}
    assert types == {"approval_decided", "execute_validated"}
    assert len(_gateway_records(sink)) == 1  # exactly one execute_validated


# --- 18. OpenClaw apply_result consume ignores the gateway record -----------------------
def test_openclaw_apply_result_consume_ignores_gateway_record(client, owner_token, monkeypatch):
    from openclaw.evidence import load_apply_result_from_sink

    sink = _install_sink(monkeypatch)
    run_id, plan_hash = _plan_and_hash(client)
    approval_id = _approve(client, run_id, plan_hash)
    _execute(client, run_id, approval_id)
    # The sink holds a gateway execute_validated record, not an OpenCode apply_result. The
    # apply_result loader (emitter opencode) must not treat it as one: it is "missing".
    view = load_apply_result_from_sink(sink, run_id=run_id, approval_id=approval_id)
    assert view.configured is True
    assert view.missing is True
    assert view.usable is False


# --- 19. no disk/env key loading in the touched modules ---------------------------------
def test_no_disk_or_env_key_loading():
    import pathlib

    root = pathlib.Path(gw.__file__).parent
    orch_src = (root / "orchestration.py").read_text(encoding="utf-8")
    # The emit helper resolves its key only from the injected gateway attributes — never from
    # the environment or a file. Guard against a regression that reads a key from disk/env.
    # Cover the whole shared emit core + both thin wrappers (Step 5b generalized the helper).
    emit_region = orch_src[orch_src.index("def _emit_gateway_evidence"):]
    emit_region = emit_region[: emit_region.index("def _execute_refusal")]
    for forbidden in ("os.environ", "os.getenv", "getenv(", "open("):
        assert forbidden not in emit_region, f"emit helper must not use {forbidden!r}"


# --- 20. no hardcoded production key / sink ---------------------------------------------
def test_no_hardcoded_production_key():
    # The module defaults are inert injection points: no sink, no key, no key id, not required.
    assert gw.EVIDENCE_SINK is None
    assert gw.EVIDENCE_KEY is None
    assert gw.EVIDENCE_KEY_ID == ""
    assert gw.REQUIRE_AUTHORIZATION_EVIDENCE is False


# --- scope guard: no forbidden files touched by this increment --------------------------
def test_scope_guard_no_forbidden_files_touched():
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
