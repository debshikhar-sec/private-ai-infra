"""Canonical plan hashing — the authority-binding digest for durable approvals.

Pure, deterministic, dependency-free implementation of
``docs/canonical-plan-hashing.md``. Given the authority-bearing fields of a plan, it
produces a byte-exact canonical JSON form and a ``sha256:<64-hex>`` digest that an
approval binds to and that ``apply`` recomputes before any mutation. Same semantic plan →
identical bytes → identical digest, on any machine.

This module intentionally does *nothing* else: no run_id, no approval store, no wiring.
It is the linchpin the rest of the approval design trusts, so it stands alone and is
verified in isolation (``tests/unit/test_canonical.py``).

Scope of the canonical object and the normalization rules are fixed by the spec; the
version constants below pin them. A plan that disagrees on either version fails closed.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass

# The version of *this normalization procedure*. Bumping it is a breaking change to the
# byte form; an approval minted under one version is never reinterpreted under another.
CANONICALIZATION_VERSION = 1

# The versions of the *field set / semantics* this module understands.
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})

# Constraints are policy/system-derived from this allowlist — never arbitrary model text.
# Each key maps to its required Python type. Adding an authority-bearing constraint here
# is a schema change and requires a ``plan_schema_version`` bump.
ALLOWED_CONSTRAINTS: dict[str, type] = {
    "no_commit": bool,
    "sandbox_only": bool,
    "max_files": int,
}


class CanonicalizationError(ValueError):
    """The plan cannot be canonicalized under the pinned versions/rules — fail closed."""


# --------------------------------------------------------------------------- helpers
def _nfc(value: str) -> str:
    """NFC-normalize an opaque identifier string, preserving case verbatim."""
    if not isinstance(value, str):
        raise CanonicalizationError(f"expected string, got {type(value).__name__}")
    return unicodedata.normalize("NFC", value)


def _as_int(value) -> int:
    """Coerce an autonomy/level/depth value to an int; reject bools and junk."""
    if type(value) is bool:  # bool is an int subclass — never accept it as a level
        raise CanonicalizationError("boolean is not a valid integer field")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in ("L", "l"):
            s = s[1:]
        try:
            return int(s)
        except ValueError as exc:
            raise CanonicalizationError(f"not an integer: {value!r}") from exc
    raise CanonicalizationError(f"not an integer: {value!r}")


def _normalize_objective(raw: str) -> str:
    """Lossless whitespace/Unicode normalization of the goal text — no paraphrasing.

    NFC, map any Unicode whitespace to a single space, drop control/format chars
    (incl. zero-width), collapse runs of spaces, trim. Word content is preserved.
    """
    if not isinstance(raw, str):
        raise CanonicalizationError("objective must be a string")
    s = unicodedata.normalize("NFC", raw)
    s = "".join(" " if ch.isspace() else ch for ch in s)
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf"))
    s = re.sub(r" +", " ", s).strip()
    return s


def _normalize_rel_path(raw: str, *, resource_root_id: str) -> str:
    """Normalize one resource path relative to the declared root; fail closed on escape.

    Resolves ``.``/``..``, normalizes separators to ``/``, drops empties and trailing
    slash. A ``..`` that would climb above the root is a canonicalization error, not a
    silent pass. Glob segments are preserved literally.
    """
    if not isinstance(raw, str):
        raise CanonicalizationError("target_resources entries must be strings")
    s = unicodedata.normalize("NFC", raw).strip().replace("\\", "/")
    segments: list[str] = []
    for seg in s.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not segments:
                raise CanonicalizationError(
                    f"path escapes resource_root_id {resource_root_id!r}: {raw!r}"
                )
            segments.pop()
            continue
        segments.append(seg)
    if not segments:
        raise CanonicalizationError(f"empty path after normalization: {raw!r}")
    return "/".join(segments)


def _normalize_constraints(constraints) -> dict:
    """Validate constraints against the allowlist; reject unknown keys / wrong types."""
    if constraints is None:
        return {}
    if not isinstance(constraints, dict):
        raise CanonicalizationError("constraints must be an object")
    out: dict[str, object] = {}
    for key, val in constraints.items():
        if key not in ALLOWED_CONSTRAINTS:
            raise CanonicalizationError(f"constraint not allowlisted: {key!r}")
        expected = ALLOWED_CONSTRAINTS[key]
        if expected is bool:
            if type(val) is not bool:
                raise CanonicalizationError(f"constraint {key!r} must be bool")
        elif expected is int:
            if type(val) is not int:  # excludes bool (type is bool, not int)
                raise CanonicalizationError(f"constraint {key!r} must be int")
        out[key] = val
    return out


def _normalize_delegation(delegation) -> dict | None:
    """Normalize the delegation sub-object (or None). The chain order is significant."""
    if delegation is None:
        return None
    if not isinstance(delegation, dict):
        raise CanonicalizationError("delegation must be an object or null")
    required = {"delegation_id", "parent_task_id", "delegation_chain", "depth"}
    if set(delegation) != required:
        raise CanonicalizationError(
            f"delegation keys must be exactly {sorted(required)}"
        )
    chain_in = delegation["delegation_chain"]
    if not isinstance(chain_in, list) or not chain_in:
        raise CanonicalizationError("delegation_chain must be a non-empty list")
    hop_keys = {"delegator", "delegatee", "skill", "granted_level"}
    chain_out = []
    for hop in chain_in:
        if not isinstance(hop, dict) or set(hop) != hop_keys:
            raise CanonicalizationError(
                f"each delegation_chain hop must have keys {sorted(hop_keys)}"
            )
        chain_out.append(
            {
                "delegator": _nfc(hop["delegator"]),
                "delegatee": _nfc(hop["delegatee"]),
                "skill": _nfc(hop["skill"]).lower(),
                "granted_level": _as_int(hop["granted_level"]),
            }
        )
    parent = delegation["parent_task_id"]
    return {
        "delegation_id": _nfc(delegation["delegation_id"]),
        "parent_task_id": None if parent is None else _nfc(parent),
        "delegation_chain": chain_out,
        "depth": _as_int(delegation["depth"]),
    }


# --------------------------------------------------------------------------- result
@dataclass(frozen=True)
class CanonicalPlan:
    """The normalized canonical mapping plus its serialization and digest."""

    mapping: dict

    @property
    def canonical_json(self) -> str:
        """The byte-exact canonical JSON string (sorted keys, compact, UTF-8)."""
        return json.dumps(
            self.mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    @property
    def canonical_bytes(self) -> bytes:
        return self.canonical_json.encode("utf-8")

    @property
    def digest(self) -> str:
        """``sha256:`` + 64 lowercase hex over the canonical bytes."""
        return "sha256:" + hashlib.sha256(self.canonical_bytes).hexdigest()


# --------------------------------------------------------------------------- entry point
def canonicalize(
    *,
    canonicalization_version: int,
    plan_schema_version: int,
    objective: str,
    principal_id: str,
    executor: str,
    skill: str,
    task_class: str,
    requested_autonomy,
    effective_autonomy,
    policy_version: str,
    policy_hash: str,
    resource_root_id: str,
    target_resources,
    environment: str,
    delegation=None,
    constraints=None,
    data_sensitivity=None,
) -> CanonicalPlan:
    """Build the canonical plan from its authority-bearing fields, or fail closed.

    Keyword-only and closed over exactly the fields in the hashing spec: an unsupported
    field is a ``TypeError`` (secrets/tokens cannot enter the canonical bytes through an
    unknown field), and a version the running code does not support raises.
    """
    if canonicalization_version != CANONICALIZATION_VERSION:
        raise CanonicalizationError(
            f"unsupported canonicalization_version {canonicalization_version!r} "
            f"(this build: {CANONICALIZATION_VERSION})"
        )
    if plan_schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise CanonicalizationError(
            f"unsupported plan_schema_version {plan_schema_version!r} "
            f"(supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)})"
        )
    if not isinstance(target_resources, (list, tuple, set, frozenset)):
        raise CanonicalizationError("target_resources must be a list")

    normalized_targets = sorted(
        {_normalize_rel_path(p, resource_root_id=resource_root_id) for p in target_resources}
    )

    mapping = {
        "canonicalization_version": canonicalization_version,
        "plan_schema_version": plan_schema_version,
        "objective_normalized": _normalize_objective(objective),
        "principal_id": _nfc(principal_id),
        "executor": _nfc(executor),
        "skill": _nfc(skill).lower(),
        "task_class": _nfc(task_class).lower(),
        "requested_autonomy": _as_int(requested_autonomy),
        "effective_autonomy": _as_int(effective_autonomy),
        "policy_version": _nfc(policy_version),
        "policy_hash": _nfc(policy_hash),
        "resource_root_id": _nfc(resource_root_id),
        "target_resources": normalized_targets,
        "delegation": _normalize_delegation(delegation),
        "constraints": _normalize_constraints(constraints),
        "environment": _nfc(environment).lower(),
        "data_sensitivity": None if data_sensitivity is None else _nfc(data_sensitivity).lower(),
    }
    return CanonicalPlan(mapping)
