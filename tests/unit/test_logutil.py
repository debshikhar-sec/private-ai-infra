"""Log-record hygiene: attacker-influenced values cannot forge or split a log line.

Pins the CWE-117 defense — every value interpolated into an audit line is run through
`log_safe`, so an embedded CR/LF can never smuggle a second, forged event onto its own
line in the JSONL/plaintext audit trail.
"""

from private_ai_gateway.logutil import log_safe


def test_newlines_are_neutralized():
    forged = "gpt-4\nAUTH_SUCCESS | principal=admin"
    out = log_safe(forged)
    assert "\n" not in out and "\r" not in out
    # The forged content survives as text on the *same* line — it cannot start a new one.
    assert "AUTH_SUCCESS" in out


def test_carriage_return_and_control_chars_stripped():
    assert "\r" not in log_safe("a\r\nb")
    assert log_safe("a\x00b\x1bc") == "a b c"


def test_tab_is_preserved():
    # Tab is a legitimate separator and carries no line-forging risk.
    assert log_safe("a\tb") == "a\tb"


def test_non_string_is_coerced():
    assert log_safe(42) == "42"
    assert log_safe(["x", "y"]) == "['x', 'y']"


def test_benign_value_is_unchanged():
    assert log_safe("strategy-v2") == "strategy-v2"
