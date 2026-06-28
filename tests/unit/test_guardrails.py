"""Unit tests for the output egress guardrails (pure logic, runs everywhere)."""

from private_ai_gateway.guardrails import Guardrails

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"


def test_off_is_passthrough():
    g = Guardrails("off")
    res = g.scan(f"here is a key {AWS_KEY}")
    assert not res.fired
    assert AWS_KEY in res.text


def test_clean_text_untouched():
    g = Guardrails("redact")
    res = g.scan("The quarterly strategy memo has no secrets in it.")
    assert not res.fired
    assert res.text == "The quarterly strategy memo has no secrets in it."


def test_redact_replaces_aws_key():
    g = Guardrails("redact")
    res = g.scan(f"credential: {AWS_KEY} end")
    assert res.fired
    assert "aws_access_key_id" in res.triggered
    assert AWS_KEY not in res.text
    assert "[REDACTED:aws_access_key_id]" in res.text


def test_redact_handles_multiple_kinds():
    g = Guardrails("redact")
    res = g.scan(f"{AWS_KEY} and {OPENAI_KEY} and {PRIVATE_KEY}")
    assert {"aws_access_key_id", "openai_key", "private_key_block"} <= set(res.triggered)
    assert AWS_KEY not in res.text
    assert OPENAI_KEY not in res.text
    assert "BEGIN RSA PRIVATE KEY" not in res.text


def test_block_withholds_whole_response():
    g = Guardrails("block")
    res = g.scan(f"sensitive {AWS_KEY} payload")
    assert res.fired
    assert AWS_KEY not in res.text
    assert "withheld" in res.text.lower()


def test_invalid_action_falls_back_to_off():
    g = Guardrails("nonsense")
    assert g.action == "off"
    assert not g.scan(AWS_KEY).fired
