"""Policy-as-code: identity and authorization for the gateway.

A *governance plane* needs externalized, auditable policy rather than logic baked
into the request handler. This module loads principals (API-key identities) from a
TOML policy file and answers two questions for each request:

  1. Identity  — which principal does this bearer token belong to?
  2. Authority — is that principal allowed to use the requested model, and under
                 what output-token cap?

API keys are never stored in plaintext: the policy file holds the SHA-256 hash of
each key, and the gateway hashes the presented token to look up the principal. If
no policy file exists, the gateway falls back to single-principal mode using
``PRIVATE_AI_AUTH_TOKEN`` (see app.py), which keeps local development zero-config.

TOML is parsed with the standard-library ``tomllib`` (Python 3.11+), so this adds
no runtime dependency.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass

from private_ai_gateway import autonomy as autonomy_mod


@dataclass(frozen=True)
class Principal:
    """An authenticated identity and what it is permitted to do."""

    name: str
    allowed_models: frozenset[str]
    max_output_tokens: int | None = None
    requests_per_minute: int | None = None
    max_autonomy_level: int | None = None
    # Capability grants for the agentic surfaces. A2A delegation is scoped to
    # ``allowed_skills`` and MCP tool calls to ``allowed_tools`` — the same
    # allowlist-with-wildcard model as ``allowed_models``. Empty means "none granted".
    allowed_skills: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] = frozenset()
    # Governance-plane introspection: reading the decision audit reveals every
    # principal's allow/deny history, so it is its own grant — deny by default.
    can_read_audit: bool = False

    def may_use(self, alias: str) -> bool:
        """True if this principal may call the given model alias."""
        return "*" in self.allowed_models or alias in self.allowed_models

    def may_use_skill(self, skill: str) -> bool:
        """True if this principal may be delegated the given A2A skill."""
        return "*" in self.allowed_skills or skill in self.allowed_skills

    def may_use_tool(self, tool: str) -> bool:
        """True if this principal may invoke the given MCP tool."""
        return "*" in self.allowed_tools or tool in self.allowed_tools


def hash_token(token: str) -> str:
    """Return the lowercase hex SHA-256 of a bearer token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Policy:
    """A set of principals indexed by the SHA-256 hash of their API key."""

    def __init__(
        self,
        principals_by_hash: dict[str, Principal],
        *,
        default_requests_per_minute: int = 0,
        guardrail_action: str = "off",
        default_max_autonomy_level: int | None = None,
        model_routes: dict[str, str] | None = None,
        default_model_alias: str | None = None,
        max_delegation_depth: int = 3,
    ):
        self._by_hash = dict(principals_by_hash)
        self.default_requests_per_minute = int(default_requests_per_minute)
        self.guardrail_action = guardrail_action
        self.default_max_autonomy_level = default_max_autonomy_level
        # Model routing is policy too: the ``[models]`` table maps stable aliases to
        # backend model ids, so switching model planes never rewrites client configs.
        self.model_routes = dict(model_routes or {})
        self.default_model_alias = default_model_alias
        # How many links a delegation chain may grow (1 = no sub-delegation).
        self.max_delegation_depth = int(max_delegation_depth)

    @property
    def principal_count(self) -> int:
        return len(self._by_hash)

    @classmethod
    def load(cls, path: str) -> "Policy":
        """Load policy from a TOML file; return an empty policy if absent.

        Malformed principal entries are skipped rather than crashing the gateway —
        a single bad policy line should not take the whole control plane down. The
        optional ``[ratelimit]`` and ``[guardrails]`` tables tune cross-cutting
        controls.
        """
        try:
            with open(path, "rb") as fh:
                raw = tomllib.load(fh)
        except FileNotFoundError:
            return cls({})

        principals: dict[str, Principal] = {}
        for entry in raw.get("principals", []):
            try:
                key_hash = str(entry["key_sha256"]).strip().lower()
                if not key_hash:
                    continue
                cap = entry.get("max_output_tokens")
                rpm = entry.get("requests_per_minute")
                autonomy = entry.get("max_autonomy_level")
                principals[key_hash] = Principal(
                    name=str(entry.get("name", "unnamed")),
                    allowed_models=frozenset(entry.get("allowed_models", [])),
                    max_output_tokens=int(cap) if cap is not None else None,
                    requests_per_minute=int(rpm) if rpm is not None else None,
                    max_autonomy_level=autonomy_mod.parse_level(autonomy),
                    allowed_skills=frozenset(entry.get("allowed_skills", [])),
                    allowed_tools=frozenset(entry.get("allowed_tools", [])),
                    can_read_audit=bool(entry.get("can_read_audit", False)),
                )
            except (KeyError, TypeError, ValueError):
                continue

        ratelimit = raw.get("ratelimit", {}) or {}
        try:
            default_rpm = int(ratelimit.get("default_requests_per_minute", 0))
        except (TypeError, ValueError):
            default_rpm = 0

        guardrails = raw.get("guardrails", {}) or {}
        action = str(guardrails.get("action", "off")).strip().lower()
        if action not in ("off", "redact", "block"):
            action = "off"

        autonomy_tbl = raw.get("autonomy", {}) or {}
        default_autonomy = autonomy_mod.parse_level(autonomy_tbl.get("default_max_level"))

        delegation_tbl = raw.get("delegation", {}) or {}
        try:
            max_depth = int(delegation_tbl.get("max_depth", 3))
        except (TypeError, ValueError):
            max_depth = 3
        max_depth = max(1, max_depth)

        models_tbl = raw.get("models", {}) or {}
        routes_raw = models_tbl.get("routes", {}) or {}
        model_routes = {
            str(alias): str(target)
            for alias, target in routes_raw.items()
            if str(alias).strip() and str(target).strip()
        }
        default_alias = str(models_tbl.get("default_alias", "")).strip() or None

        return cls(
            principals,
            default_requests_per_minute=default_rpm,
            guardrail_action=action,
            default_max_autonomy_level=default_autonomy,
            model_routes=model_routes,
            default_model_alias=default_alias,
            max_delegation_depth=max_depth,
        )

    def identify(self, bearer_token: str) -> Principal | None:
        """Return the principal for a bearer token, or None if unknown."""
        if not bearer_token:
            return None
        return self._by_hash.get(hash_token(bearer_token))

    def find_principal(self, name: str) -> Principal | None:
        """Look up a principal by name (for delegation targets and the agent directory)."""
        for principal in self._by_hash.values():
            if principal.name == name:
                return principal
        return None

    def principals(self) -> list[Principal]:
        """All configured principals, sorted by name (policy-derived, no key material)."""
        return sorted(self._by_hash.values(), key=lambda p: p.name)
