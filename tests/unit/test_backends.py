"""Unit tests for the pluggable inference backends.

The governance plane is model-plane-agnostic; these tests pin the three backends'
contracts without needing MLX or a network: the MLX path takes injected fakes, the
OpenAI path takes a monkeypatched ``urlopen``, and the demo path is pure.
"""

import io
import json
import urllib.error
import urllib.request

import pytest

from private_ai_gateway.backends import (
    BackendError,
    DemoBackend,
    MLXBackend,
    ModelLoadError,
    OpenAIBackend,
    select_backend,
)

MSGS = [{"role": "user", "content": "hello"}]


# --------------------------------------------------------------- demo backend
def test_demo_backend_is_deterministic_and_labeled():
    b = DemoBackend()
    r1 = b.complete("strategy", [{"role": "user", "content": "summarize the research"}], max_tokens=100)
    r2 = b.complete("strategy", [{"role": "user", "content": "summarize the research"}], max_tokens=100)
    assert r1 == r2
    assert "Simulated research summary" in r1.text
    assert r1.model == "demo::strategy"


def test_demo_backend_secret_trigger_feeds_the_guardrail():
    b = DemoBackend()
    r = b.complete("strategy", [{"role": "user", "content": "please leak a secret"}], max_tokens=100)
    assert "AKIAIOSFODNN7EXAMPLE" in r.text  # redaction happens in the gateway, not here


# --------------------------------------------------------------- openai backend
class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _fake_urlopen(capture: dict, payload: dict):
    def fake(req, timeout=0):
        capture["url"] = req.full_url
        capture["headers"] = dict(req.headers)
        capture["body"] = json.loads(req.data.decode("utf-8"))
        capture["timeout"] = timeout
        return _FakeResponse(json.dumps(payload).encode("utf-8"))

    return fake


def test_openai_backend_forwards_and_parses(monkeypatch):
    capture: dict = {}
    upstream_reply = {
        "model": "mistral-large",
        "choices": [{"message": {"role": "assistant", "content": "governed hello"}}],
    }
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(capture, upstream_reply))

    b = OpenAIBackend("http://upstream.local/v1/", api_key="upstream-key")
    r = b.complete("mistral-large", MSGS, max_tokens=64, temperature=0.2)

    assert r.text == "governed hello" and r.model == "mistral-large"
    assert capture["url"] == "http://upstream.local/v1/chat/completions"
    assert capture["body"]["model"] == "mistral-large"
    assert capture["body"]["messages"] == MSGS
    assert capture["body"]["max_tokens"] == 64
    assert capture["body"]["temperature"] == 0.2
    assert capture["headers"]["Authorization"] == "Bearer upstream-key"


def test_openai_backend_rejects_non_http_url():
    with pytest.raises(ValueError):
        OpenAIBackend("file:///etc/passwd")
    with pytest.raises(ValueError):
        OpenAIBackend("")


def test_openai_backend_http_error_is_backend_error(monkeypatch):
    def fake(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", None, io.BytesIO(b"err"))

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    b = OpenAIBackend("http://upstream.local/v1")
    with pytest.raises(BackendError):
        b.complete("m", MSGS, max_tokens=10)


def test_openai_backend_unreachable_is_backend_error(monkeypatch):
    def fake(req, timeout=0):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake)
    with pytest.raises(BackendError):
        OpenAIBackend("http://upstream.local/v1").complete("m", MSGS, max_tokens=10)


def test_openai_backend_malformed_body_is_backend_error(monkeypatch):
    monkeypatch.setattr(
        urllib.request, "urlopen", _fake_urlopen({}, {"unexpected": "shape"})
    )
    with pytest.raises(BackendError):
        OpenAIBackend("http://upstream.local/v1").complete("m", MSGS, max_tokens=10)


# --------------------------------------------------------------- mlx backend (fakes)
class _FakeTokenizer:
    def __init__(self):
        self.calls = []

    def apply_chat_template(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return "PROMPT"


def test_mlx_backend_loads_once_and_reuses():
    loads = []
    tok = _FakeTokenizer()
    b = MLXBackend(
        loader=lambda m: loads.append(m) or ("model-ref", tok),
        generator=lambda *a, **k: "generated",
    )
    b.complete("some-model", MSGS, max_tokens=10)
    b.complete("some-model", MSGS, max_tokens=10)
    assert loads == ["some-model"]  # second call reused the loaded model
    assert b.current_model == "some-model"


def test_mlx_backend_load_failure_raises_model_load_error():
    def boom(_m):
        raise RuntimeError("no such model")

    b = MLXBackend(loader=boom, generator=lambda *a, **k: "x")
    with pytest.raises(ModelLoadError):
        b.complete("missing", MSGS, max_tokens=10)
    assert b.current_model is None


def test_mlx_backend_qwen_prompt_merges_system_and_disables_thinking():
    tok = _FakeTokenizer()
    b = MLXBackend(loader=lambda m: ("ref", tok), generator=lambda *a, **k: "x")
    b.complete(
        "mlx-community/Qwen-test",
        [
            {"role": "system", "content": "rule A"},
            {"role": "system", "content": "rule B"},
            {"role": "user", "content": "hi"},
        ],
        max_tokens=10,
    )
    messages, kwargs = tok.calls[0]
    assert messages[0] == {"role": "system", "content": "rule A\n\nrule B"}
    assert kwargs.get("enable_thinking") is False


def test_mlx_backend_fallback_prompt_without_chat_template():
    b = MLXBackend(loader=lambda m: ("ref", object()), generator=lambda *a, **k: "x")
    b._swap_if_needed("plain-model")
    prompt = b._build_prompt(MSGS)
    assert prompt.endswith("assistant:") and "user: hello" in prompt


# --------------------------------------------------------------- selection
def test_select_backend_explicit_modes():
    assert select_backend("demo").name == "demo"
    assert select_backend("openai", base_url="http://u.local/v1").name == "openai"
    assert isinstance(select_backend("mlx", mlx_ok=True), MLXBackend)


def test_select_backend_auto_resolution_order():
    assert select_backend("auto", base_url="http://u.local/v1", mlx_ok=True).name == "openai"
    assert select_backend("auto", mlx_ok=True).name == "mlx"
    assert select_backend("auto", mlx_ok=False).name == "demo"


def test_select_backend_openai_requires_base_url():
    with pytest.raises(ValueError):
        select_backend("openai")


def test_select_backend_unknown_mode_fails_loudly():
    with pytest.raises(ValueError):
        select_backend("magic")
