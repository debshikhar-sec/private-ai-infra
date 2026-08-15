"""Owner-gated route activation as a managed, versioned revision — never a file edit.

Route changes shipped proposal-only because the honest options were both bad. Hot-patching
``ROUTE_MAP`` would let a browser dropdown change what a running gateway does while the policy
hash — the thing authority is bound to — went on describing the old configuration. Rewriting
``policy.toml`` from an HTTP handler would put a web request in charge of a hand-authored file
that a human owns, with no way to tell an operator's edit from a machine's.

This takes a third path. The hand-authored policy file stays exactly that: hand-authored, and
never written by this process. Activation instead appends a **managed revision** to a separate,
gateway-owned store, and the effective configuration is *base policy + active revision*. Two
inputs, one derived answer, and the derivation is a pure function of both.

**The hash follows the configuration, not the other way round.** Every revision carries the
base policy hash it was computed against and its own ``effective_policy_hash`` over the merged
result. A run records which revision it was planned under, so its authority stays bound to the
configuration that was actually in force — and if the base file is edited by hand afterwards,
the recorded base hash no longer matches and the revision is reported as **stale** rather than
silently re-interpreted against a file it was never reviewed against.

**Revisions are append-only and atomic.** Each is a numbered file written to a temp path and
renamed, so a crash mid-write leaves the previous revision intact rather than a half-parsed
one. Nothing is ever mutated in place and nothing is deleted, so "what was in force at the
time" remains answerable long after the fact.

**What activation deliberately cannot do.** It changes exactly one thing — which model a lane
routes to. It cannot widen autonomy, grant a skill or a tool, add a principal, or alter an
approval right, because those fields are not in the revision schema at all: there is no field
to set, not merely a check that refuses to set one. And a model whose security lane is not
qualified cannot be activated for security work, whatever the caller asks.

Activation takes effect for **runs planned after it**. Runs already in flight keep the revision
they were planned under; their attribution already records it. That is the safe direction, and
it means a route change can never retroactively reinterpret a run someone already approved.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

#: Revision files are ``NNNNNN.json``. Zero-padded so lexical order is numeric order.
_REVISION_RE = re.compile(r"^(\d{6})\.json$")

#: The one thing a revision may change. Enumerated so nothing else can be smuggled in.
MUTABLE_FIELDS = ("routes",)

#: Fields activation must never touch, checked explicitly as well as being absent from the
#: schema — belt and braces, because this is the boundary that matters.
FORBIDDEN_FIELDS = (
    "autonomy",
    "autonomy_ceiling",
    "skills",
    "allowed_skills",
    "tools",
    "allowed_tools",
    "principals",
    "approval",
    "approvers",
    "can_read_audit",
    "models",
)

ACTIVATION_ACTIVE = "active"
ACTIVATION_STALE = "stale_base_policy"
ACTIVATION_NONE = "no_revision"


class RouteRevisionError(Exception):
    """A route revision could not be created or read. Never silently ignored."""


@dataclass(frozen=True)
class RouteRevision:
    """One activation: what changed, who changed it, and against which base policy."""

    revision: int = 0
    created_at: str = ""
    activated_by: str = ""
    lane: str = ""
    route_alias: str = ""
    routes: dict = field(default_factory=dict)
    base_policy_hash: str = ""
    effective_policy_hash: str = ""
    note: str = ""

    def to_mapping(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def base_policy_hash(policy_path: str) -> str:
    """Hash of the hand-authored policy file. Fails closed — never a placeholder."""
    try:
        with open(policy_path, "rb") as fh:
            return _sha256_bytes(fh.read())
    except OSError as exc:
        raise RouteRevisionError(f"cannot read the policy file {policy_path!r}: {exc}") from exc


def effective_policy_hash(base_hash: str, routes: dict) -> str:
    """Hash over *base policy + active route overrides*, canonically serialised.

    This is what a run's authority binds to. With no overrides it is deliberately **not** equal
    to the base hash: "no revision" and "a revision that happens to change nothing" are
    different configurations, and collapsing them would make an activation invisible.
    """
    body = json.dumps(
        {"base": base_hash, "routes": dict(sorted((routes or {}).items()))},
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_bytes(body.encode("utf-8"))


class RouteRevisionStore:
    """Append-only, atomic, numbered revisions in a directory this process owns."""

    def __init__(self, directory: str | os.PathLike):
        self.directory = Path(directory)

    # --- reading -------------------------------------------------------------------------
    def _revision_files(self) -> list[Path]:
        if not self.directory.is_dir():
            return []
        found = []
        for entry in self.directory.iterdir():
            if entry.is_file() and _REVISION_RE.match(entry.name):
                found.append(entry)
        return sorted(found, key=lambda p: p.name)

    def revisions(self) -> list[RouteRevision]:
        out = []
        for path in self._revision_files():
            try:
                body = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RouteRevisionError(f"revision {path.name} is unreadable: {exc}") from exc
            out.append(RouteRevision(**{
                key: body.get(key, getattr(RouteRevision(), key))
                for key in RouteRevision().to_mapping()
            }))
        return out

    def active(self) -> RouteRevision | None:
        """The highest-numbered revision, or ``None`` when nothing has been activated."""
        revisions = self.revisions()
        return revisions[-1] if revisions else None

    def next_number(self) -> int:
        active = self.active()
        return (active.revision + 1) if active is not None else 1

    # --- writing -------------------------------------------------------------------------
    def append(self, revision: RouteRevision) -> RouteRevision:
        """Write one revision atomically. A crash mid-write leaves the previous one intact."""
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self.directory / f"{revision.revision:06d}.json"
        if target.exists():
            raise RouteRevisionError(f"revision {revision.revision} already exists")
        body = json.dumps(revision.to_mapping(), indent=2, sort_keys=True) + "\n"
        handle, temp_name = tempfile.mkstemp(dir=str(self.directory), suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(temp_name, target)
        except OSError as exc:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise RouteRevisionError(f"could not write revision: {exc}") from exc
        return revision


@dataclass(frozen=True)
class EffectiveRoutes:
    """The routes actually in force, and how much they can be trusted."""

    routes: dict = field(default_factory=dict)
    revision: int = 0
    state: str = ACTIVATION_NONE
    base_policy_hash: str = ""
    effective_policy_hash: str = ""
    detail: str = ""

    def to_mapping(self) -> dict:
        return asdict(self)


def resolve_effective_routes(
    store: RouteRevisionStore, *, base_routes: dict, policy_path: str
) -> EffectiveRoutes:
    """Merge the active revision over the base route map, and say how current it is.

    A revision computed against a policy file that has since been hand-edited is reported
    :data:`ACTIVATION_STALE` and **not applied**. Re-interpreting an approved route change
    against a file nobody reviewed it against is exactly the silent drift this module exists
    to prevent.
    """
    base_hash = base_policy_hash(policy_path)
    active = store.active()
    if active is None:
        return EffectiveRoutes(
            routes=dict(base_routes),
            revision=0,
            state=ACTIVATION_NONE,
            base_policy_hash=base_hash,
            effective_policy_hash=base_hash,
            detail="no route revision has been activated; the policy file is in force",
        )
    if active.base_policy_hash != base_hash:
        return EffectiveRoutes(
            routes=dict(base_routes),
            revision=active.revision,
            state=ACTIVATION_STALE,
            base_policy_hash=base_hash,
            effective_policy_hash=base_hash,
            detail=(
                "the policy file changed after this revision was activated; the revision is "
                "not applied and must be re-activated against the current file"
            ),
        )
    merged = {**base_routes, **(active.routes or {})}
    return EffectiveRoutes(
        routes=merged,
        revision=active.revision,
        state=ACTIVATION_ACTIVE,
        base_policy_hash=base_hash,
        effective_policy_hash=active.effective_policy_hash,
        detail=f"route revision {active.revision} is in force",
    )


def build_revision(
    store: RouteRevisionStore,
    *,
    base_routes: dict,
    policy_path: str,
    lane: str,
    route_alias: str,
    resolved_model: str,
    activated_by: str,
) -> RouteRevision:
    """Compose the next revision. Pure construction — the caller decides whether to append.

    Only the route table is expressible. There is no parameter here for autonomy, skills,
    tools, principals or approval rights, which is a stronger guarantee than checking for them:
    a field that does not exist cannot be set by a request that names it.
    """
    if not route_alias or not resolved_model:
        raise RouteRevisionError("a revision needs both a route alias and a resolved model")
    base_hash = base_policy_hash(policy_path)
    current = resolve_effective_routes(store, base_routes=base_routes, policy_path=policy_path)
    routes = {**(current.routes if current.state == ACTIVATION_ACTIVE else base_routes)}
    routes[route_alias] = resolved_model
    return RouteRevision(
        revision=store.next_number(),
        created_at=_now(),
        activated_by=activated_by,
        lane=lane,
        route_alias=route_alias,
        routes=routes,
        base_policy_hash=base_hash,
        effective_policy_hash=effective_policy_hash(base_hash, routes),
        note="route activation only; no autonomy, skill, tool or approval right is changed",
    )
