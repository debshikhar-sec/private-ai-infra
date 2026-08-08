"""Step 7B.0 — assurance-owned live durable evidence wiring.

Covers the three layers of the increment:

  * :mod:`openclaw.assurance` — assurance-owned key loading and durable-sink construction:
    each emitter reads only its own hex-encoded key; the full verification registry is
    assembled only by assurance construction; every misconfiguration fails closed with a
    message that names the variable and never the value.
  * :mod:`private_ai_gateway.state` — the ``PRIVATE_AI_EVIDENCE_MODE=durable`` backend:
    a live sink whose ownership is held while the backend is open, the exact
    write → close → restart → verify lifecycle over a *populated* database, and fail-closed
    reopen behavior for wrong/missing keys, unknown key ids, tampered records, unsupported
    schema, and ownership collisions — with cleanup proven by a corrected clean reopen.
  * the wired runtime — the real governed loop (plan → owner approval → execute) over the
    demo plane with the durable sink threaded end to end: the gateway's ``approval_decided``
    and ``execute_validated`` and OpenCode's ``apply_result`` land in ONE durable chain that
    OpenClaw verifies fail-closed (signed apply + signed linkage), and the chain survives a
    restart. No sleeps anywhere; keys are ephemeral in-test values.
"""

from __future__ import annotations

import sqlite3

import pytest
from openclaw import assurance
from openclaw.sink import (
    EMITTER_GATEWAY,
    EMITTER_OPENCODE,
    EmitterKeyRegistry,
    EvidenceError,
    sign_envelope,
    verify_envelope_signature,
)
from openclaw.sink_sqlite import SqliteEvidenceSink
from openclaw.sqlite_util import DatabaseOwnership, DurableStoreError

from private_ai_gateway import app as gw
from private_ai_gateway.approvals import ApprovalError
from private_ai_gateway.approvals_sqlite import SqliteApprovalStore
from private_ai_gateway.demo import TOKENS, install_demo_plane
from private_ai_gateway.state import StateConfig, StateError, open_backend

# Ephemeral in-test key material (hex for env vars, bytes for direct assertions).
_GW_HEX = "aa" * 32
_OC_HEX = "bb" * 32
_GW_KEY = bytes.fromhex(_GW_HEX)
_OC_KEY = bytes.fromhex(_OC_HEX)

HERMES = f"Bearer {TOKENS['hermes']}"
_OBJ = "Apply the reviewed fix and verify it"
_OWNER_TOKEN = "test-owner-break-glass-token"


def _env(tmp_path=None, **extra):
    env = {
        "PRIVATE_AI_EVIDENCE_KEY_GATEWAY": _GW_HEX,
        "PRIVATE_AI_EVIDENCE_KEY_OPENCODE": _OC_HEX,
    }
    if tmp_path is not None:
        env.update(
            PRIVATE_AI_STATE_BACKEND="sqlite",
            PRIVATE_AI_STATE_DIR=str(tmp_path),
            PRIVATE_AI_EVIDENCE_MODE="durable",
        )
    env.update(extra)
    return env


def _open(tmp_path, **extra):
    env = _env(tmp_path, **extra)
    return open_backend(StateConfig.from_env(env), environ=env)


# --- assurance key loading -----------------------------------------------------------
def test_emitter_signing_key_returns_only_own_material():
    key, key_id = assurance.emitter_signing_key(_env(), EMITTER_GATEWAY)
    assert (key, key_id) == (_GW_KEY, "gateway-hmac-1")
    key, key_id = assurance.emitter_signing_key(_env(), EMITTER_OPENCODE)
    assert (key, key_id) == (_OC_KEY, "opencode-hmac-1")


def test_unknown_emitter_fails_closed():
    with pytest.raises(assurance.AssuranceConfigError):
        assurance.emitter_signing_key(_env(), "shadow-emitter")


@pytest.mark.parametrize("missing", list(assurance.EMITTER_KEY_ENV.values()))
def test_missing_required_key_fails_closed(missing):
    env = _env()
    del env[missing]
    with pytest.raises(assurance.AssuranceConfigError) as exc:
        assurance.load_registry(env)
    assert missing in str(exc.value)  # names the variable...
    assert _GW_HEX not in str(exc.value) and _OC_HEX not in str(exc.value)  # ...never a value


@pytest.mark.parametrize("bad", ["not-hex-material", "abcd", "aA" * 7])
def test_malformed_or_short_key_fails_closed(bad):
    with pytest.raises(assurance.AssuranceConfigError):
        assurance.load_registry(_env(PRIVATE_AI_EVIDENCE_KEY_GATEWAY=bad))


def test_registry_verifies_what_each_emitter_signs():
    reg = assurance.load_registry(_env())
    for emitter, key in ((EMITTER_GATEWAY, _GW_KEY), (EMITTER_OPENCODE, _OC_KEY)):
        assert reg.get(emitter, assurance.EMITTER_KEY_IDS[emitter]) == key


# --- state config --------------------------------------------------------------------
def test_evidence_mode_defaults_off():
    assert StateConfig.from_env({}).evidence_mode == "off"


def test_unknown_evidence_mode_fails_closed():
    with pytest.raises(StateError):
        StateConfig.from_env({"PRIVATE_AI_EVIDENCE_MODE": "paranoid"})


def test_durable_evidence_requires_sqlite_backend():
    with pytest.raises(StateError):
        StateConfig.from_env({"PRIVATE_AI_EVIDENCE_MODE": "durable"})


def test_durable_open_requires_keys(tmp_path):
    env = _env(tmp_path)
    del env["PRIVATE_AI_EVIDENCE_KEY_OPENCODE"]
    with pytest.raises(StateError):
        open_backend(StateConfig.from_env(env), environ=env)
    # The failed open released the authority lock too (partial-startup cleanup).
    own = DatabaseOwnership(str(tmp_path / "authority.sqlite3"))
    own.release()


# --- durable lifecycle: write -> restart -> verify -----------------------------------
def _gateway_record(sink, i=0, record_type="approval_decided"):
    """Append one gateway-signed record through the sink's real validation path."""
    from openclaw import sink as sinkmod

    payload = {"decision": "approve", "i": i}
    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(),
        sink_id=sink.sink_id,
        run_id=f"run-{i}",
        emitter=EMITTER_GATEWAY,
        emitter_key_id=assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY],
        record_type=record_type,
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-07-05T00:00:00+00:00",
        nonce=f"n-{i}",
        approval_id="appr-x",
    )
    return sink.append(env, payload, sign_envelope(env, _GW_KEY))


def test_populated_database_survives_restart(tmp_path):
    opened = _open(tmp_path)
    sink = opened.evidence_sink
    assert isinstance(sink, SqliteEvidenceSink)
    assert sink.sink_id == assurance.DURABLE_SINK_ID
    assert len(sink) == 0
    _gateway_record(sink, 0)
    _gateway_record(sink, 1)
    head = sink.head_hash
    opened.close()  # clean shutdown releases both stores

    reopened = _open(tmp_path)  # same configured registry -> full chain re-verified
    sink2 = reopened.evidence_sink
    assert len(sink2) == 2
    assert sink2.head_hash == head
    sink2.verify_chain()
    _gateway_record(sink2, 2)  # still appendable after restart
    assert len(sink2) == 3
    reopened.close()


def test_backend_holds_evidence_ownership_while_open(tmp_path):
    opened = _open(tmp_path)
    with pytest.raises(DurableStoreError):  # ownership collision fails closed
        assurance.open_durable_sink(_env(), str(tmp_path / "evidence.sqlite3"))
    opened.close()
    # Released on close: a fresh owner may acquire now.
    again = assurance.open_durable_sink(_env(), str(tmp_path / "evidence.sqlite3"))
    again.close()


def test_wrong_verification_key_on_reopen_fails_closed(tmp_path):
    opened = _open(tmp_path)
    _gateway_record(opened.evidence_sink, 0)
    opened.close()
    wrong = _env(tmp_path, PRIVATE_AI_EVIDENCE_KEY_GATEWAY="cc" * 32)
    with pytest.raises(EvidenceError):
        open_backend(StateConfig.from_env(wrong), environ=wrong)
    # Constructor failure released everything: the corrected config reopens cleanly.
    fixed = _open(tmp_path)
    assert len(fixed.evidence_sink) == 1
    fixed.close()


def test_unknown_emitter_key_id_on_reopen_fails_closed(tmp_path):
    # A record signed under a rotated/unknown key id verifies only against a registry that
    # holds it; the standard configured registry must fail closed on reopen.
    path = str(tmp_path / "evidence.sqlite3")
    reg = EmitterKeyRegistry()
    reg.register(EMITTER_GATEWAY, "gateway-hmac-99", _GW_KEY)
    from openclaw import sink as sinkmod

    sink = SqliteEvidenceSink(assurance.DURABLE_SINK_ID, reg, path=path)
    payload = {"decision": "approve"}
    env = sinkmod.SigningEnvelope(
        schema_version=sinkmod.SCHEMA_VERSION,
        evidence_id=sinkmod.new_evidence_id(),
        sink_id=sink.sink_id, run_id="r", emitter=EMITTER_GATEWAY,
        emitter_key_id="gateway-hmac-99", record_type="approval_decided",
        payload_hash=sinkmod.payload_digest(payload),
        ts="2026-07-05T00:00:00+00:00", nonce="n",
    )
    sink.append(env, payload, sign_envelope(env, _GW_KEY))
    sink.close()
    with pytest.raises(EvidenceError):
        assurance.open_durable_sink(_env(), path)


def test_tampered_record_on_reopen_fails_closed(tmp_path):
    opened = _open(tmp_path)
    _gateway_record(opened.evidence_sink, 0)
    opened.close()
    path = str(tmp_path / "evidence.sqlite3")
    raw = sqlite3.connect(path)
    raw.execute("UPDATE records SET payload='{\"decision\":\"tampered\"}' WHERE seq=0")
    raw.commit()
    raw.close()
    with pytest.raises(EvidenceError):
        _open(tmp_path)
    own = DatabaseOwnership(path)  # failure path released ownership
    own.release()


def test_unsupported_evidence_schema_fails_closed(tmp_path):
    opened = _open(tmp_path)
    opened.close()
    path = str(tmp_path / "evidence.sqlite3")
    raw = sqlite3.connect(path)
    raw.execute("UPDATE schema_meta SET value='999' WHERE key='schema_version'")
    raw.commit()
    raw.close()
    with pytest.raises(DurableStoreError):
        _open(tmp_path)


def test_populated_database_in_off_mode_fails_with_remediation(tmp_path):
    opened = _open(tmp_path)
    _gateway_record(opened.evidence_sink, 0)
    opened.close()
    env = _env(tmp_path, PRIVATE_AI_EVIDENCE_MODE="off")
    with pytest.raises(StateError) as exc:
        open_backend(StateConfig.from_env(env), environ=env)
    assert "PRIVATE_AI_EVIDENCE_MODE=durable" in str(exc.value)


# --- the wired runtime: one governed loop, one durable chain -------------------------
@pytest.fixture
def client():
    install_demo_plane(gw)
    return gw.app.test_client()


@pytest.fixture
def wired(tmp_path, monkeypatch, client):
    """The durable-evidence runtime exactly as app startup configures it."""
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_GATEWAY", _GW_HEX)
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_OPENCODE", _OC_HEX)
    opened = _open(tmp_path)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "APPROVAL_STORE", opened.authority_store)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _GW_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", True)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", True, raising=False)
    yield client, opened
    opened.close()


def _drive_loop(client):
    plan = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": _OBJ, "phase": "plan"},
    ).get_json()
    run_id, plan_hash = plan["run_id"], plan["canonical_plan_hash"]
    appr = client.post(
        "/v1/approvals", headers={"Authorization": f"Bearer {_OWNER_TOKEN}"},
        json={"run_id": run_id, "canonical_plan_hash": plan_hash,
              "decision": "approve", "reason": "reviewed"},
    ).get_json()
    out = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": _OBJ, "phase": "execute",
              "run_id": run_id, "approval_id": appr["approval_id"]},
    ).get_json()
    return run_id, appr["approval_id"], out


def test_wired_loop_lands_all_three_records_in_one_durable_chain(tmp_path, wired):
    client, opened = wired
    run_id, approval_id, out = _drive_loop(client)
    assert out["applied"] is True and out["verdict"] == "PASS"

    sink = opened.evidence_sink
    # The transcript surfaces the gateway's own minted execute_validated reference (safe
    # identifiers only) so the chat can render the lineage truthfully from server data.
    ev = out["evidence"]
    assert ev["durable"] is True and ev["approval_id"] == approval_id
    exec_ref = ev["execute_validated"]
    assert exec_ref["record_type"] == "execute_validated"
    assert exec_ref["sink_id"] == assurance.DURABLE_SINK_ID
    durable_exec = next(
        r for r in sink.records if r.envelope.record_type == "execute_validated"
    )
    assert exec_ref["evidence_id"] == durable_exec.envelope.evidence_id
    assert exec_ref["evidence_digest"] == durable_exec.evidence_ref().evidence_digest
    assert set(exec_ref) == {"evidence_id", "evidence_digest", "record_type", "sink_id"}
    types = [r.envelope.record_type for r in sink.records]
    assert types == ["approval_decided", "execute_validated", "apply_result"]
    by_type = {r.envelope.record_type: r for r in sink.records}
    for r in sink.records:
        assert r.envelope.run_id == run_id
        assert r.envelope.approval_id == approval_id
        assert r.envelope.sink_id == assurance.DURABLE_SINK_ID
    # Signed linkage end to end: apply_result -> execute_validated -> approval_decided.
    exec_rec = by_type["execute_validated"]
    assert by_type["apply_result"].payload["execute_ref"] == exec_rec.evidence_ref().to_mapping()
    assert exec_rec.payload["approval_ref"] == by_type["approval_decided"].evidence_ref().to_mapping()
    # Authorship: the gateway signed its records, OpenCode signed the apply — own keys only.
    assert verify_envelope_signature(exec_rec.envelope, exec_rec.emitter_sig, _GW_KEY)
    apply_rec = by_type["apply_result"]
    assert apply_rec.envelope.emitter == EMITTER_OPENCODE
    assert verify_envelope_signature(apply_rec.envelope, apply_rec.emitter_sig, _OC_KEY)
    sink.verify_chain()

    # Restart: the populated runtime chain reopens and verifies under the same registry.
    opened.close()
    reopened = _open(tmp_path)
    assert [r.envelope.record_type for r in reopened.evidence_sink.records] == types
    reopened.evidence_sink.verify_chain()
    reopened.close()


def test_foreign_openclaw_package_is_displaced_before_assurance_import():
    # An unrelated PyPI distribution also named `openclaw` can shadow the repo's assurance
    # plane in a non-pytest process (the CLI). The state module must displace it and put
    # the repo's agents/ directory first — a silent identity swap here would hand
    # authority-adjacent code to foreign software. Every real openclaw module is snapshotted
    # and restored so sibling tests keep their original class identities.
    import sys
    import types

    from private_ai_gateway import state as state_mod

    saved = {m: sys.modules[m] for m in list(sys.modules)
             if m == "openclaw" or m.startswith("openclaw.")}
    try:
        foreign = types.ModuleType("openclaw")
        foreign.__file__ = "/site-packages/openclaw/__init__.py"
        sys.modules["openclaw"] = foreign

        state_mod._ensure_repo_openclaw_importable()

        import openclaw.assurance as reimported

        assert "agents/openclaw/assurance.py" in reimported.__file__.replace("\\", "/")
    finally:
        for m in [m for m in list(sys.modules) if m == "openclaw" or m.startswith("openclaw.")]:
            del sys.modules[m]
        sys.modules.update(saved)


def test_unwired_injected_sink_keeps_gateway_only_emit(tmp_path, monkeypatch, client):
    # Pre-7B.0 semantics are preserved for injected sinks without the runtime-wired flag:
    # the gateway emits its two records; no apply_result is forced through the executor.
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_GATEWAY", _GW_HEX)
    monkeypatch.setenv("PRIVATE_AI_EVIDENCE_KEY_OPENCODE", _OC_HEX)
    opened = _open(tmp_path)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "EVIDENCE_SINK", opened.evidence_sink)
    monkeypatch.setattr(gw, "EVIDENCE_KEY", _GW_KEY)
    monkeypatch.setattr(gw, "EVIDENCE_KEY_ID", assurance.EMITTER_KEY_IDS[EMITTER_GATEWAY])
    monkeypatch.setattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", False)
    monkeypatch.setattr(gw, "EVIDENCE_RUNTIME_WIRED", False, raising=False)
    _, _, out = _drive_loop(client)
    assert out["applied"] is True
    types = [r.envelope.record_type for r in opened.evidence_sink.records]
    assert types == ["approval_decided", "execute_validated"]
    opened.close()


def test_double_execute_loser_gets_governed_replay_not_500(client, monkeypatch):
    # The race window between validate_for_execute and mark_used: the loser must surface
    # as the governed replay refusal, never an unhandled ApprovalError/HTTP 500.
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    plan = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": _OBJ, "phase": "plan"},
    ).get_json()
    appr = client.post(
        "/v1/approvals", headers={"Authorization": f"Bearer {_OWNER_TOKEN}"},
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve", "reason": "reviewed"},
    ).get_json()

    def _consumed_by_winner(approval_id, **kwargs):
        raise ApprovalError(f"approval {approval_id!r} is not in an approved state (used)")

    monkeypatch.setattr(gw.APPROVAL_STORE, "mark_used", _consumed_by_winner)
    resp = client.post(
        "/v1/orchestrate", headers={"Authorization": HERMES},
        json={"objective": _OBJ, "phase": "execute",
              "run_id": plan["run_id"], "approval_id": appr["approval_id"]},
    )
    assert resp.status_code == 200
    out = resp.get_json()
    assert out["applied"] is False and out["refused"] is True
    assert out["refusal_reason"] == "replay"


def test_durable_authority_pairs_with_wired_evidence(tmp_path):
    # The durable configuration opens BOTH stores; authority state written through the
    # backend survives the same restart the evidence chain does.
    opened = _open(tmp_path)
    assert isinstance(opened.authority_store, SqliteApprovalStore)
    opened.authority_store.create_run(
        run_id="r1", principal_id="hermes", canonical_plan_hash="sha256:" + "a" * 64,
        effective_autonomy=2, policy_ceiling=3,
    )
    _gateway_record(opened.evidence_sink, 0)
    opened.close()
    reopened = _open(tmp_path)
    assert reopened.authority_store.get_run("r1") is not None
    assert len(reopened.evidence_sink) == 1
    reopened.close()
