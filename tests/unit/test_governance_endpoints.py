"""Integration tests for the governance endpoints and wiring.

These import app.py (and therefore MLX), so they run on Apple Silicon and auto-skip
elsewhere. They avoid real inference by hitting metadata endpoints or by
monkeypatching the model load + generate calls.
"""

import pytest

pytest.importorskip("mlx", reason="MLX is only available on Apple Silicon")

from private_ai_gateway import app as gw  # noqa: E402
from private_ai_gateway.guardrails import Guardrails  # noqa: E402
from private_ai_gateway.policy import Policy, Principal, hash_token  # noqa: E402
from private_ai_gateway.ratelimit import RateLimiter  # noqa: E402

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def owner_client(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-token")
    return gw.app.test_client()


def test_whoami_reports_owner(owner_client):
    r = owner_client.get("/v1/whoami", headers={"Authorization": "Bearer test-token"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["principal"] == "owner"
    assert body["allowed_models"] == ["*"]
    # Owner sits at the top of the autonomy ladder (L6, break-glass).
    assert body["max_autonomy_level"] == 6
    assert body["max_autonomy_name"] == "unbounded"


def test_metrics_requires_auth(owner_client):
    assert owner_client.get("/metrics").status_code == 401


def test_metrics_renders_prometheus_text(owner_client):
    r = owner_client.get("/metrics", headers={"Authorization": "Bearer test-token"})
    assert r.status_code == 200
    assert "# TYPE gateway_requests_total counter" in r.get_data(as_text=True)


def test_rate_limit_returns_429(monkeypatch):
    key = "throttled-key"
    pol = Policy({hash_token(key): Principal("limited", frozenset({"strategy"}), None, 1)})
    monkeypatch.setattr(gw, "POLICY", pol)
    monkeypatch.setattr(gw, "AUTH_TOKEN", "")  # no owner fallback
    monkeypatch.setattr(gw, "RATE_LIMITER", RateLimiter(0))  # fresh buckets, default unlimited
    client = gw.app.test_client()
    hdr = {"Authorization": f"Bearer {key}"}

    # First request consumes the single token; second is throttled.
    assert client.get("/v1/models", headers=hdr).status_code == 200
    r = client.get("/v1/models", headers=hdr)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


def _autonomy_client(monkeypatch, ceiling):
    """A client whose only principal is capped at the given autonomy level."""
    key = "agent-key"
    pol = Policy(
        {hash_token(key): Principal("agent", frozenset({"strategy"}), None, None, ceiling)}
    )
    monkeypatch.setattr(gw, "POLICY", pol)
    monkeypatch.setattr(gw, "AUTH_TOKEN", "")  # no owner break-glass fallback
    monkeypatch.setattr(gw, "RATE_LIMITER", RateLimiter(0))
    return gw.app.test_client(), key


def test_autonomy_over_ceiling_denied(monkeypatch):
    client, key = _autonomy_client(monkeypatch, ceiling=1)  # suggest only
    r = client.post(
        "/v1/chat/completions",
        json={"model": "strategy", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": f"Bearer {key}", "X-Autonomy-Level": "L3"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "autonomy_exceeded"


def test_autonomy_at_or_below_ceiling_allowed(monkeypatch):
    # At/below the ceiling, the request passes the gate and proceeds to inference,
    # which we stub out so no model loads.
    monkeypatch.setattr(gw, "swap_model_if_needed", lambda *a, **k: True)
    monkeypatch.setattr(gw, "generate", lambda *a, **k: "ok")
    client, key = _autonomy_client(monkeypatch, ceiling=3)
    r = client.post(
        "/v1/chat/completions",
        json={"model": "strategy", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": f"Bearer {key}", "X-Autonomy-Level": "L2"},
    )
    assert r.status_code == 200


def test_autonomy_level_via_body_field(monkeypatch):
    client, key = _autonomy_client(monkeypatch, ceiling=0)  # observe only
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "strategy",
            "messages": [{"role": "user", "content": "hi"}],
            "autonomy_level": "L2",
        },
        headers={"Authorization": f"Bearer {key}"},
    )
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "autonomy_exceeded"


def test_guardrail_redacts_secret_in_chat(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-token")
    monkeypatch.setattr(gw, "GUARDRAILS", Guardrails("redact"))
    monkeypatch.setattr(gw, "RATE_LIMITER", RateLimiter(0))
    monkeypatch.setattr(gw, "swap_model_if_needed", lambda *a, **k: True)
    monkeypatch.setattr(gw, "generate", lambda *a, **k: f"the key is {AWS_KEY} ok")

    client = gw.app.test_client()
    r = client.post(
        "/v1/chat/completions",
        json={"model": "strategy", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    content = r.get_json()["choices"][0]["message"]["content"]
    assert AWS_KEY not in content
    assert "[REDACTED:aws_access_key_id]" in content
