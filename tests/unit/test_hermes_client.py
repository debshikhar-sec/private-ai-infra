"""Unit tests for the Hermes gateway client (client.py) — no real network."""

import io
import json
import urllib.error

import pytest
from hermes.client import GatewayClient, GatewayError


class _FakeResp:
    def __init__(self, payload):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_complete_sends_auth_and_autonomy_and_returns_content(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResp(
            {"choices": [{"message": {"role": "assistant", "content": "PHASE: x"}}]}
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = GatewayClient("http://127.0.0.1:8081", "tok", model="strategy", autonomy_level="L1")
    out = client.complete([{"role": "user", "content": "hi"}], max_tokens=64)

    assert out == "PHASE: x"
    assert captured["url"].endswith("/v1/chat/completions")
    # Header keys are capitalized by urllib; check case-insensitively.
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers["authorization"] == "Bearer tok"
    assert headers["x-autonomy-level"] == "L1"
    assert captured["body"]["model"] == "strategy"
    assert captured["body"]["autonomy_level"] == "L1"
    assert captured["body"]["max_tokens"] == 64


def test_complete_raises_gateway_error_on_http_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 403, "Forbidden", {}, io.BytesIO(b'{"error":"autonomy_exceeded"}')
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = GatewayClient("http://127.0.0.1:8081", "tok")
    with pytest.raises(GatewayError) as exc:
        client.complete([{"role": "user", "content": "hi"}])
    assert "403" in str(exc.value)


def test_complete_raises_on_unreachable_gateway(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = GatewayClient("http://127.0.0.1:8081", "tok")
    with pytest.raises(GatewayError) as exc:
        client.complete([{"role": "user", "content": "hi"}])
    assert "cannot reach gateway" in str(exc.value)


def test_complete_raises_on_bad_shape(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: _FakeResp({"oops": 1}))
    client = GatewayClient("http://127.0.0.1:8081", "tok")
    with pytest.raises(GatewayError):
        client.complete([{"role": "user", "content": "hi"}])


def test_rejects_non_http_scheme():
    # Guards against file:/ or custom schemes reaching urlopen.
    with pytest.raises(ValueError):
        GatewayClient("file:///etc/passwd", "tok")
