"""Server side of the Governed Chat Console.

Bridges the gateway's HTTP surface to the phased :class:`hermes.session.GovernedSession`
orchestration. The orchestration agents (``interop``/``hermes``/``opencode_sandbox``/
``openclaw``) live *outside* the pip package — they are the clients of the plane, not part
of it — so this module loads them lazily and degrades with a clear message when they are
not importable or when the demo plane that owns their principals is not installed.

The chat drives the *real* loop: every sub-call the session makes goes back through the
same Flask app (an in-process test client), so each step is authenticated, autonomy-capped,
and audited exactly like any other request. Authority to *apply* stays with the human — the
apply step refuses unless the caller supplies an approval.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


class OrchestrationUnavailable(RuntimeError):
    """The agents or the demo plane needed to orchestrate are not present."""


def _ensure_agents_on_path() -> None:
    """Make ``interop``/``hermes``/… importable, or raise a clear error.

    Tries the import first; on failure, adds the repo's ``agents/`` directory (from
    ``PRIVATE_AI_AGENTS_PATH``, the CWD, or inferred from this file's location) to
    ``sys.path`` and retries once.
    """
    try:
        import hermes.session  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    candidates = []
    env = os.environ.get("PRIVATE_AI_AGENTS_PATH")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.cwd() / "agents")
    # src/private_ai_gateway/orchestration.py -> <repo>/agents
    candidates.append(Path(__file__).resolve().parents[2] / "agents")

    for cand in candidates:
        if (cand / "hermes" / "session.py").exists():
            sys.path.insert(0, str(cand))
            try:
                import hermes.session  # noqa: F401
                return
            except ModuleNotFoundError:
                continue

    raise OrchestrationUnavailable(
        "orchestration agents are not importable; run from the repo or set "
        "PRIVATE_AI_AGENTS_PATH to its agents/ directory"
    )


def _demo_tokens(gw) -> dict[str, str]:
    """The demo principals' tokens, only if the demo plane owns them on this app."""
    from private_ai_gateway.demo import TOKENS

    identify = getattr(gw, "POLICY", None)
    if identify is None or identify.identify(TOKENS.get("hermes", "")) is None:
        raise OrchestrationUnavailable(
            "the Governed Chat Console runs on the demo plane; start it with "
            "`private-ai-gateway demo`"
        )
    return TOKENS


def _build_peers(gw, tokens: dict[str, str]) -> dict:
    """One in-process AgentPeer per principal, all hitting this same governed app."""
    from interop import AgentPeer

    client = gw.app.test_client()

    def factory(token: str):
        def send(method: str, path: str, body: dict | None = None):
            resp = getattr(client, method.lower())(
                path, headers={"Authorization": f"Bearer {token}"}, json=body
            )
            payload = resp.get_json(silent=True)
            if payload is None:
                payload = resp.get_data(as_text=True)
            return resp.status_code, payload

        return send

    return {name: AgentPeer(send=factory(tok)) for name, tok in tokens.items()}


VALID_PHASES = ("plan", "execute", "probe")


def run_phase(
    gw, objective: str, phase: str, *, approver: str = "", reason: str = ""
) -> dict:
    """Run one governed-orchestration phase and return its structured transcript.

    Raises :class:`OrchestrationUnavailable` (agents/demo-plane missing) or ``ValueError``
    (unknown phase / empty objective).
    """
    if phase not in VALID_PHASES:
        raise ValueError(f"unknown phase {phase!r}; expected one of {VALID_PHASES}")
    if not (objective or "").strip():
        raise ValueError("objective must not be empty")

    _ensure_agents_on_path()
    from hermes.session import GovernedSession

    tokens = _demo_tokens(gw)
    peers = _build_peers(gw, tokens)
    session = GovernedSession(peers, objective)

    if phase == "plan":
        return session.plan()
    if phase == "execute":
        return session.execute(approver, reason)
    return session.probe()
