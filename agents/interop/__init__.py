"""Shared agent-interop client: discovery, delegation, and task lifecycle.

Every agent (Hermes, OpenCode, OpenClaw) talks to its peers *through the gateway*,
never directly: discovery reads policy-derived agent cards, delegation is a governed
hand-off with attenuated authority, and results flow back on the same audited surface.
"""

from interop.peer import AgentPeer, PeerError

__all__ = ["AgentPeer", "PeerError"]
