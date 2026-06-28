"""Minimal gateway client: Hermes talks to the control plane as its own principal.

Hermes authenticates with the ``hermes`` principal's key, not a shared admin token,
and declares its autonomy level on every call. The gateway therefore enforces what
Hermes may do (model allowlist, token cap, rate limit, **autonomy ceiling L1**) the
same way it would for any other component — the planner has no special privilege.

Standard library only (``urllib``); no ``requests`` dependency.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class GatewayError(RuntimeError):
    """Raised when the gateway returns a non-2xx response."""


class GatewayClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        model: str = "strategy",
        autonomy_level: str = "L1",
        timeout: float = 600.0,
    ):
        scheme = urllib.parse.urlparse(base_url).scheme
        if scheme not in ("http", "https"):
            raise ValueError(f"base_url must be http(s), got scheme {scheme!r}")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.model = model
        self.autonomy_level = autonomy_level
        self.timeout = timeout

    def complete(self, messages: list[dict], *, max_tokens: int | None = None) -> str:
        """POST a chat completion and return the assistant's text content."""
        body: dict = {
            "model": self.model,
            "messages": messages,
            # Declared in the body as well as the header so either path the gateway
            # reads enforces the same ceiling.
            "autonomy_level": self.autonomy_level,
        }
        if max_tokens is not None:
            body["max_tokens"] = max_tokens

        req = urllib.request.Request(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "X-Autonomy-Level": self.autonomy_level,
            },
        )
        try:
            # Scheme is constrained to http(s) in __init__, so B310 (file:/custom
            # schemes) does not apply here.
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise GatewayError(f"gateway returned {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise GatewayError(f"cannot reach gateway at {self.base_url}: {exc}") from exc

        try:
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise GatewayError(f"unexpected gateway response shape: {payload!r}") from exc
