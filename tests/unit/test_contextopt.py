"""Deterministic context compression: real, reproducible token accounting.

These tests pin the honest claims — whitespace normalization is lossless, dedup removes
only exact repeated blocks, budget windowing keeps system + recent turns — so the
savings the gateway reports can be trusted rather than asserted.
"""

from private_ai_gateway import contextopt as co


def test_estimate_tokens_monotonic():
    assert co.estimate_tokens("") == 0
    assert co.estimate_tokens("a" * 8) == 2


def test_whitespace_normalization_is_lossless_in_meaning():
    messy = "hello   world\n\n\n\nfoo   bar   \n"
    clean = co.normalize_whitespace(messy)
    assert clean == "hello world\n\nfoo bar"
    # words preserved, only redundant spacing gone
    assert clean.split() == ["hello", "world", "foo", "bar"]


def test_normalization_is_linear_on_pathological_whitespace():
    # Regression for CodeQL py/polynomial-redos: a long tab run *not* followed by a
    # newline made the old `[ \t]+(\n|$)` regex quadratic. Must stay linear on
    # caller-supplied prompt text.
    import time

    hostile = ("\t" * 100_000) + "x"
    start = time.monotonic()
    out = co.normalize_whitespace(hostile)
    assert time.monotonic() - start < 1.0
    assert out == "x"


def test_compression_reports_before_and_after():
    messages = [{"role": "user", "content": "word " * 200}]
    result = co.compress_messages(messages)
    assert result.original_tokens > 0
    assert result.compressed_tokens <= result.original_tokens
    assert result.saved_pct >= 0.0
    assert result.ratio >= 1.0


def test_dedupe_removes_repeated_context_block():
    block = (
        "This is a substantial shared context block that appears verbatim in two "
        "different turns of the same conversation and should only be counted once."
    )
    messages = [
        {"role": "system", "content": block},
        {"role": "user", "content": f"{block}\n\nNow answer the question."},
    ]
    before = co.messages_tokens(messages)
    result = co.compress_messages(messages, dedupe=True)
    assert result.compressed_tokens < before
    assert any(step.startswith("deduped") for step in result.steps)
    # The unique instruction survives.
    assert "Now answer the question." in result.messages[1]["content"]


def test_short_repeats_are_not_deduped():
    # Below the 40-char threshold, repeats are kept (avoids mangling short phrases).
    messages = [
        {"role": "user", "content": "ok"},
        {"role": "user", "content": "ok"},
    ]
    result = co.compress_messages(messages)
    assert all(m["content"] == "ok" for m in result.messages)


def test_budget_windowing_keeps_system_and_recent():
    messages = [
        {"role": "system", "content": "S " * 10},
        {"role": "user", "content": "OLD " * 50},
        {"role": "assistant", "content": "MID " * 50},
        {"role": "user", "content": "NEW question " * 5},
    ]
    budget = co.messages_tokens(messages[:1]) + co.estimate_tokens(
        messages[-1]["content"]
    ) + 5
    result = co.compress_messages(messages, budget=budget)
    roles_kept = [m["role"] for m in result.messages]
    assert roles_kept[0] == "system"                 # system always kept
    assert result.messages[-1]["content"].startswith("NEW question")  # newest kept
    assert any("budget-windowed" in s for s in result.steps)
    assert result.compressed_tokens <= budget + co.messages_tokens(messages[:1])


def test_measure_mode_does_not_mutate():
    messages = [{"role": "user", "content": "hello   world   " * 20}]
    result = co.compress_messages(messages, apply=False)
    # Reports achievable savings but returns the original messages untouched.
    assert result.messages is messages
    assert result.applied is False
    assert result.compressed_tokens <= result.original_tokens


# --------------------------------------------------------- gateway integration hook
def test_gateway_measures_savings_without_mutating_by_default(monkeypatch):
    from private_ai_gateway import app as gw
    from private_ai_gateway.backends import CompletionResult

    class _Backend:
        name = "fake"
        captured = None

        def complete(self, model, messages, *, max_tokens, temperature=None):
            _Backend.captured = messages
            return CompletionResult(text="ok", model=model)

        def info(self):
            return {"mode": "fake", "current_model": None}

    backend = _Backend()
    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-token")
    monkeypatch.setattr(gw, "BACKEND", backend)
    # Default policy: measure-only (context_compress is False).
    block = "SHARED CONTEXT BLOCK that is long enough to be deduplicated across turns."
    client = gw.app.test_client()
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "strategy",
            "messages": [
                {"role": "user", "content": f"{block}\n\nfirst"},
                {"role": "user", "content": f"{block}\n\nsecond"},
            ],
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    # Measure-only: the backend still received both full copies of the block.
    sent = "\n".join(m["content"] for m in backend.captured)
    assert sent.count("SHARED CONTEXT BLOCK") == 2
    # …but the saving was counted in metrics.
    metrics = client.get("/metrics", headers={"Authorization": "Bearer test-token"})
    assert "gateway_context_tokens_saved_total" in metrics.get_data(as_text=True)


def test_gateway_applies_compression_when_policy_opts_in(monkeypatch):
    from private_ai_gateway import app as gw
    from private_ai_gateway.backends import CompletionResult

    class _Backend:
        name = "fake"
        captured = None

        def complete(self, model, messages, *, max_tokens, temperature=None):
            _Backend.captured = messages
            return CompletionResult(text="ok", model=model)

        def info(self):
            return {"mode": "fake", "current_model": None}

    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-token")
    monkeypatch.setattr(gw, "BACKEND", _Backend())
    monkeypatch.setattr(gw.POLICY, "context_compress", True)
    block = "SHARED CONTEXT BLOCK that is long enough to be deduplicated across turns."
    client = gw.app.test_client()
    r = client.post(
        "/v1/chat/completions",
        json={
            "model": "strategy",
            "messages": [
                {"role": "user", "content": f"{block}\n\nfirst"},
                {"role": "user", "content": f"{block}\n\nsecond"},
            ],
        },
        headers={"Authorization": "Bearer test-token"},
    )
    assert r.status_code == 200
    # Opt-in: the duplicated block was compressed out before hitting the backend.
    sent = "\n".join(m["content"] for m in _Backend.captured)
    assert sent.count("SHARED CONTEXT BLOCK") == 1
