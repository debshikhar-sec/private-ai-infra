"""Unit tests for the gateway's auth boundary and request-size limit.

AUTH_TOKEN is read from the environment at import; tests monkeypatch the module
global, which the auth handler reads at request time.
"""

import pytest

from private_ai_gateway import app as gw


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-token")
    return gw.app.test_client()


def test_health_needs_no_auth(client):
    assert client.get("/health").status_code == 200


def test_missing_token_rejected(client):
    assert client.get("/v1/models").status_code == 401


def test_wrong_token_rejected(client):
    r = client.get("/v1/models", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_correct_token_accepted(client):
    r = client.get("/v1/models", headers={"Authorization": "Bearer test-token"})
    assert r.status_code == 200


def test_empty_configured_token_denies_all(client, monkeypatch):
    # A misconfigured (empty) token must not let "Bearer " through.
    monkeypatch.setattr(gw, "AUTH_TOKEN", "")
    r = client.get("/v1/models", headers={"Authorization": "Bearer "})
    assert r.status_code == 401


def test_oversized_body_rejected(client, monkeypatch):
    monkeypatch.setitem(gw.app.config, "MAX_CONTENT_LENGTH", 100)
    r = client.post(
        "/v1/chat/completions",
        data=b"x" * 1000,
        headers={
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 413
