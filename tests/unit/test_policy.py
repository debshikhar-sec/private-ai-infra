"""Unit tests for the governance policy layer (identity + authorization)."""

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.policy import Policy, Principal, hash_token


def test_hash_token_is_stable_sha256():
    # Known SHA-256 of "abc".
    assert (
        hash_token("abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_identify_resolves_known_key_only():
    key = "analyst-key"
    pol = Policy({hash_token(key): Principal("analyst", frozenset({"strategy"}), 2048)})
    p = pol.identify(key)
    assert p is not None and p.name == "analyst"
    assert pol.identify("wrong-key") is None
    assert pol.identify("") is None


def test_principal_may_use():
    restricted = Principal("a", frozenset({"strategy"}), None)
    assert restricted.may_use("strategy")
    assert not restricted.may_use("offsec")
    assert Principal("owner", frozenset({"*"}), None).may_use("anything")


def test_load_missing_file_returns_empty(tmp_path):
    assert Policy.load(str(tmp_path / "nope.toml")).principal_count == 0


def test_load_parses_principals(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text(
        "[[principals]]\n"
        'name = "analyst"\n'
        f'key_sha256 = "{hash_token("k1")}"\n'
        'allowed_models = ["strategy"]\n'
        "max_output_tokens = 1024\n"
    )
    pol = Policy.load(str(p))
    assert pol.principal_count == 1
    who = pol.identify("k1")
    assert who is not None and who.name == "analyst" and who.max_output_tokens == 1024


@pytest.fixture
def restricted_client(monkeypatch):
    key = "analyst-key"
    pol = Policy({hash_token(key): Principal("analyst", frozenset({"strategy"}), 2048)})
    monkeypatch.setattr(gw, "POLICY", pol)
    monkeypatch.setattr(gw, "AUTH_TOKEN", "")  # disable owner break-glass fallback
    return gw.app.test_client(), key


def test_unknown_key_rejected(restricted_client):
    client, _ = restricted_client
    r = client.post(
        "/v1/chat/completions",
        json={"model": "strategy", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": "Bearer not-a-key"},
    )
    assert r.status_code == 401


def test_disallowed_model_forbidden(restricted_client):
    # analyst may use "strategy" only; "offsec" must be denied before any model load.
    client, key = restricted_client
    r = client.post(
        "/v1/chat/completions",
        json={"model": "offsec", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "model_not_allowed"
