"""Log-record hygiene: neutralize attacker-influenced values before they are logged.

Any value that originates from a request — a model name, a URL path, a tool name, a
remote address, or upstream error text — must never be written verbatim into a log
line. An embedded CR/LF lets a caller forge or split an audit record, smuggling a fake
event onto its own line (CWE-117, log injection). Every audit line in this gateway is
one event; `log_safe` preserves that contract by collapsing CR, LF, and other C0/C1
control characters to a single space before the value reaches the logger.

Call it around the *interpolated* value, not the whole message:

    logger.warning(f"AUTH_FAILURE | path={log_safe(request.path)}")
"""

from __future__ import annotations

import re

# C0/C1 control chars *except* tab (\x09) — CR (\x0d) and LF (\x0a) are handled by the
# explicit str.replace below so static analyzers recognize the newline sanitization.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def log_safe(value: object) -> str:
    """Return ``value`` as a string with line breaks and control chars neutralized."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    return _CONTROL.sub(" ", text)
