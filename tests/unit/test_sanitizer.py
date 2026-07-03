"""Unit tests for the gateway output sanitizer.

The sanitizer strips visible model control / thinking / tool-call markers before
returning OpenAI-compatible content — regardless of which backend produced it.
"""

from private_ai_gateway.app import sanitize_model_output


def test_strips_think_tags():
    assert sanitize_model_output("<think>secret reasoning</think>Hello") == "Hello"


def test_removes_control_tokens():
    assert sanitize_model_output("<|start|>Hi<|end|>") == "Hi"


def test_blocks_fake_tool_calls_with_safe_fallback():
    out = sanitize_model_output('<tool_call>{"name": "rm"}</tool_call>')
    assert "cannot call tools" in out.lower()


def test_plain_text_passthrough():
    assert sanitize_model_output("just text") == "just text"
