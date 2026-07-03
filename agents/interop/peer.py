"""AgentPeer — how one governed agent understands and works with another.

The client half of the delegation protocol (see ``private_ai_gateway/delegation.py``).
An agent uses its *own* principal token; what it may route or execute is decided by
the gateway against policy, not by anything in this file. The transport is injectable
(``send``) so the same worker code runs over real HTTP or an in-process Flask test
client — which is how the offline orchestration demo and the unit tests stay
deterministic while exercising the true enforcement path.

Peer *understanding* is card-based: :meth:`AgentPeer.find_peer` matches a required
skill against the policy-derived A2A agent directory and prefers the **least
privileged** peer whose enforced autonomy ceiling still suffices — discovery itself
follows least-privilege, and nothing is hardcoded to an agent's name.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class PeerError(RuntimeError):
    """A gateway refusal (or transport failure) seen by an agent."""

    def __init__(self, message: str, *, code: str = "", status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status


def _http_sender(base_url: str, token: str, timeout: float):
    """Default transport: stdlib urllib against a running gateway."""
    scheme = urllib.parse.urlparse(base_url).scheme
    if scheme not in ("http", "https"):
        raise ValueError(f"base_url must be http(s), got scheme {scheme!r}")
    root = base_url.rstrip("/")

    def send(method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"{root}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        try:
            # Scheme constrained to http(s) above, so B310 does not apply.
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                raw = resp.read().decode("utf-8")
                status = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            status = exc.code
        except urllib.error.URLError as exc:
            raise PeerError(f"cannot reach gateway at {root}: {exc}") from exc
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw
        return status, payload

    return send


class AgentPeer:
    """One agent's governed view of its peers.

    ``send(method, path, body) -> (status, payload)`` is the only I/O seam; pass a
    wrapper around a Flask test client to run fully in-process.
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        *,
        send=None,
        timeout: float = 30.0,
    ):
        if send is None:
            if not base_url or not token:
                raise ValueError("provide either send= or base_url + token")
            send = _http_sender(base_url, token, timeout)
        self._send = send

    # -- plumbing ---------------------------------------------------------------

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        status, payload = self._send(method, path, body)
        if status >= 400:
            err = (payload.get("error") or {}) if isinstance(payload, dict) else {}
            raise PeerError(
                err.get("message") or f"gateway returned {status}",
                code=err.get("code", ""),
                status=status,
            )
        return payload if isinstance(payload, dict) else {"raw": payload}

    # -- discovery: how agents understand each other ----------------------------

    def discover(self) -> dict:
        """The A2A agent directory: policy-derived cards plus the chain-depth bound."""
        return self._call("GET", "/a2a/agents")

    def find_peer(
        self, skill: str, *, min_level: int = 0, exclude: tuple[str, ...] = ()
    ) -> dict | None:
        """The least-privileged peer whose card offers ``skill`` at >= ``min_level``.

        Matching runs on enforced facts (granted skills, autonomy ceiling), so a
        delegation decision made here is the same decision the gateway will enforce.
        """
        candidates = []
        for card in self.discover().get("agents", []):
            if card.get("name") in exclude:
                continue
            skills = {s.get("id") for s in card.get("skills", [])}
            ceiling = (card.get("x-governance") or {}).get("autonomy_ceiling")
            if skill in skills and (ceiling is None or ceiling >= min_level):
                candidates.append((ceiling if ceiling is not None else 99, card))
        if not candidates:
            return None
        return min(candidates, key=lambda pair: pair[0])[1]

    # -- delegation lifecycle -----------------------------------------------------

    def delegate(
        self,
        skill: str,
        delegatee: str,
        *,
        level: int,
        task: str = "",
        parent: str | None = None,
    ) -> dict:
        body: dict = {
            "skill": skill,
            "delegatee": delegatee,
            "autonomy_level": f"L{level}",
            "task": task,
        }
        if parent:
            body["parent_task"] = parent
        return self._call("POST", "/a2a/tasks", body)

    def inbox(self, *, status: str = "submitted") -> list[dict]:
        """Tasks currently delegated *to* this agent."""
        query = f"?status={urllib.parse.quote(status)}" if status else ""
        return self._call("GET", f"/a2a/tasks{query}").get("tasks", [])

    def outbox(self, *, status: str = "") -> list[dict]:
        """Tasks this agent has delegated to others."""
        query = "?role=delegator"
        if status:
            query += f"&status={urllib.parse.quote(status)}"
        return self._call("GET", f"/a2a/tasks{query}").get("tasks", [])

    def get_task(self, task_id: str) -> dict:
        """A delegation plus its custody chain (participants and auditors only)."""
        return self._call("GET", f"/a2a/tasks/{urllib.parse.quote(task_id)}")

    def report(
        self, task_id: str, status: str, *, result: str = "", verdict: str = ""
    ) -> dict:
        return self._call(
            "POST",
            f"/a2a/tasks/{urllib.parse.quote(task_id)}/result",
            {"status": status, "result": result, "verdict": verdict},
        )

    # -- evidence & telemetry ------------------------------------------------------

    def whoami(self) -> dict:
        return self._call("GET", "/v1/whoami")

    def decisions(self, *, limit: int = 200) -> list[dict]:
        """The decision audit tail (requires the ``can_read_audit`` grant)."""
        return self._call("GET", f"/v1/decisions?limit={int(limit)}").get("decisions", [])

    def metrics_text(self) -> str:
        """Raw Prometheus exposition text from /metrics."""
        status, payload = self._send("GET", "/metrics", None)
        if status >= 400:
            raise PeerError(f"metrics fetch failed with {status}", status=status)
        return payload if isinstance(payload, str) else json.dumps(payload)

    def complete(self, model: str, content: str, *, max_tokens: int = 512) -> str:
        """A governed chat completion under this agent's own principal."""
        payload = self._call(
            "POST",
            "/v1/chat/completions",
            {
                "model": model,
                "messages": [{"role": "user", "content": content}],
                "max_tokens": max_tokens,
            },
        )
        try:
            return payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise PeerError(f"unexpected completion shape: {payload!r}") from exc
