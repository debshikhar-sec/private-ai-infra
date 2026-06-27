"""Unit tests for the pure request-normalization helpers."""

import pytest

pytest.importorskip("mlx", reason="MLX is only available on Apple Silicon")

from private_ai_gateway.app import (  # noqa: E402
    estimate_tokens_rough,
    normalize_content,
    normalize_messages,
    resolve_model,
)


def test_resolve_model_alias_and_passthrough():
    assert resolve_model("strategy").startswith("mlx-community/")
    assert resolve_model("") == resolve_model("strategy")  # empty -> default alias
    assert resolve_model("some/raw-model") == "some/raw-model"  # unknown -> passthrough


def test_estimate_tokens_rough():
    assert estimate_tokens_rough("") == 0
    assert estimate_tokens_rough("abcd") >= 1


def test_normalize_content_variants():
    assert normalize_content(None) == ""
    assert normalize_content("hi") == "hi"
    parts = [{"type": "text", "text": "a"}, {"text": "b"}, "c"]
    assert normalize_content(parts) == "a\nb\nc"


def test_normalize_messages_coerces_roles_and_tool():
    out = normalize_messages(
        [
            {"role": "system", "content": "s"},
            {"role": "tool", "content": "t"},
            "not-a-dict",
        ]
    )
    assert out[0] == {"role": "system", "content": "s"}
    assert out[1]["role"] == "user" and out[1]["content"].startswith("Tool result:")
    assert all(isinstance(m, dict) for m in out)


def test_normalize_messages_non_list_defaults_to_user():
    assert normalize_messages("notalist") == [{"role": "user", "content": "notalist"}]
