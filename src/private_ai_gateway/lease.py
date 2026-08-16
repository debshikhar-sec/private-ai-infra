"""A *prospective* earned-autonomy lease: what one would have to bind, and what would refuse it.

This module is a specification with an executable conscience. It defines the object a first
earned-autonomy lease would be, defines every condition that refuses one, and can answer
``WOULD_GRANT`` / ``WOULD_REFUSE`` for a proposed change — and it is wired to **nothing**.

The distinction it exists to hold:

* :mod:`eligibility` asks *"is this build, in general, in a state where a lease could be
  considered?"* — a standing question about history and qualification.
* This module asks *"would **this specific change**, right now, fall inside **that specific
  lease**?"* — a per-change question about scope, and a much narrower one.

A lease is not a permission level and not a role. It is a **binding**: one principal, one
exact model build, one lane, one policy revision, one path set, one expiry. Change any of
those and it is a different lease, which is the only reason a bounded grant is bounded at all.
A lease for model A does not apply to model B; a lease for ``GENERATED_METRICS_REFRESH`` does
not apply to source engineering, however similar the diff looks.

**Nothing here grants anything, and the gap is structural rather than promised.** There is no
issue path that produces an *active* lease, no store, no endpoint that mints one, and no
authorization module imports this file — a test asserts the last of those by walking the AST.
``would_grant`` returns a sentence about a hypothetical. Turning it into a decision would
require writing the code that consumes it, which is deliberately the next train's problem and
not this one's.

Why bother, then. Because the honest way to find out whether a bounded lease is *possible* is
to write down exactly what it would have to bind and then run the real corpus through it. If
the answer is "nothing qualifies", that is a result — and it is a far more useful result than
discovering the same thing after the authority plumbing is already in place.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from private_ai_gateway import lanes, task_risk

# --- posture -------------------------------------------------------------------------------
#: Repeated in every rendered result. A reader who sees only one field should see this one.
POSTURE = "PROSPECTIVE / SHADOW — no lease is issued, held, or consumed"

WOULD_GRANT = "WOULD_GRANT"
WOULD_REFUSE = "WOULD_REFUSE"

# --- lifecycle -------------------------------------------------------------------------------
# The states a real lease would move through, declared now so the next train inherits a
# vocabulary rather than inventing one. Nothing in this module transitions between them; the
# ladder exists to be tested against, and to make the missing edges obvious.
S_PROPOSED = "PROPOSED"
S_OWNER_GRANTED = "OWNER_GRANTED"
S_ACTIVE = "ACTIVE"
S_REVOKED = "REVOKED"
S_EXPIRED = "EXPIRED"

STATES = (S_PROPOSED, S_OWNER_GRANTED, S_ACTIVE, S_REVOKED, S_EXPIRED)

#: The only transitions that may ever exist. Note what is absent: nothing reaches
#: ``OWNER_GRANTED`` except from ``PROPOSED``, nothing returns from ``REVOKED`` or
#: ``EXPIRED``, and no state transitions to itself with wider scope — a renewal is a new
#: lease proposed from scratch, never an extension of a running one.
ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    S_PROPOSED: (S_OWNER_GRANTED, S_REVOKED, S_EXPIRED),
    S_OWNER_GRANTED: (S_ACTIVE, S_REVOKED, S_EXPIRED),
    S_ACTIVE: (S_REVOKED, S_EXPIRED),
    S_REVOKED: (),
    S_EXPIRED: (),
}

#: Transitions only an owner may cause. A model proposing its own lease is allowed — that is
#: just a request — but nothing it does may move the lease forward from there.
OWNER_ONLY_TRANSITIONS = ((S_PROPOSED, S_OWNER_GRANTED), (S_ACTIVE, S_REVOKED))

#: The longest a first lease may run. Short on purpose: the cost of a too-short lease is that
#: someone re-issues it, and the cost of a too-long one is an unattended grant nobody
#: remembers making.
MAX_LEASE_SECONDS = 3600

# --- refusal codes ------------------------------------------------------------------------
R_FINGERPRINT = "model_fingerprint_differs"
R_POLICY = "policy_revision_differs"
R_LANE = "lane_differs"
R_PATH_OUTSIDE = "path_outside_lease"
R_PROTECTED = "protected_surface_touched"
R_RISK_CLASS = "risk_class_above_lane"
R_QUALIFICATION_MISSING = "qualification_artifact_missing"
R_QUALIFICATION_STALE = "qualification_artifact_does_not_match_build"
R_EVIDENCE = "runtime_evidence_failed_verification"
R_DIRTY = "unresolved_dirty_run"
R_NOT_CONTAINED = "workspace_not_contained"
R_NO_ROLLBACK = "rollback_unavailable"
R_EXPIRED = "lease_expired"
R_REVOKED = "lease_revoked"
R_DIFF_TOO_LARGE = "diff_exceeds_lease_scope"
R_FILES_TOO_MANY = "file_count_exceeds_lease_scope"
R_HISTORY = "insufficient_attributable_history"
R_TOOLS = "tool_requested_outside_lease"
R_NETWORK = "network_requested_outside_lease"


@dataclass(frozen=True)
class Refusal:
    """One independently sufficient reason a lease would not cover a change."""

    code: str
    detail: str


@dataclass(frozen=True)
class LeaseSubject:
    """Everything a lease binds. Every field is part of the identity, not metadata.

    ``digest`` covers all of it, so two leases differing in any single bound value are
    different objects with different digests — there is no field a caller can vary while
    claiming to hold "the same" lease.
    """

    principal: str
    model_fingerprint: str
    lane_id: str
    policy_hash: str
    policy_revision: str = ""
    allowed_paths: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    max_files: int = 0
    max_changed_lines: int = 0
    expires_at: str = ""
    evidence_required: tuple[str, ...] = ()
    rollback_required: bool = True
    qualification_artifact: str = ""
    qualification_corpus_version: str = ""
    min_attributable_runs: int = 0
    network: str = "none"

    @property
    def digest(self) -> str:
        body = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()

    def to_mapping(self) -> dict:
        body = asdict(self)
        body["digest"] = self.digest
        body["posture"] = POSTURE
        body["grants"] = "nothing"
        return body


@dataclass(frozen=True)
class ShadowDecision:
    """What a lease *would* answer, and why. Never an authorization."""

    decision: str = WOULD_REFUSE
    lease_digest: str = ""
    refusals: tuple[Refusal, ...] = field(default=())
    considered: tuple[str, ...] = field(default=())

    @property
    def would_grant(self) -> bool:
        return self.decision == WOULD_GRANT and not self.refusals

    def to_mapping(self) -> dict:
        return {
            "decision": self.decision,
            "posture": POSTURE,
            "lease_digest": self.lease_digest,
            "refusals": [{"code": r.code, "detail": r.detail} for r in self.refusals],
            "considered": list(self.considered),
            "grants": "nothing",
            "consumed_by": "nothing",
            "note": (
                "A hypothetical answer about a hypothetical lease. Execution remains "
                "human-gated; no authorization path reads this."
            ),
        }


def propose(
    *,
    principal: str,
    model_fingerprint: str,
    lane_id: str,
    policy_hash: str,
    policy_revision: str = "",
    qualification_artifact: str = "",
    qualification_corpus_version: str = "",
    min_attributable_runs: int = 20,
    lifetime_seconds: int = MAX_LEASE_SECONDS,
    now: datetime | None = None,
) -> LeaseSubject:
    """Build the lease a lane *would* imply. Proposing is not requesting and not holding.

    Scope is taken from the lane specification rather than from the caller: a proposal cannot
    ask for more paths, more files, more lines, or a tool, because there is no parameter for
    any of those. Narrow by construction — the same reason the route-revision schema has no
    field for autonomy.
    """
    spec = lanes.spec_for(lane_id)
    if spec is None:
        raise ValueError(f"no such lane: {lane_id!r}")
    moment = now or datetime.now(timezone.utc)
    lifetime = max(60, min(int(lifetime_seconds), MAX_LEASE_SECONDS))
    return LeaseSubject(
        principal=principal,
        model_fingerprint=model_fingerprint,
        lane_id=spec.lane_id,
        policy_hash=policy_hash,
        policy_revision=policy_revision,
        allowed_paths=tuple(spec.allowed_paths),
        tools=tuple(spec.tools),
        max_files=spec.max_files,
        max_changed_lines=spec.max_changed_lines,
        expires_at=(moment + timedelta(seconds=lifetime)).isoformat(timespec="seconds"),
        evidence_required=("candidate_attributed", "execute_validated", "apply_result"),
        rollback_required=spec.rollback_required,
        qualification_artifact=qualification_artifact,
        qualification_corpus_version=qualification_corpus_version,
        min_attributable_runs=min_attributable_runs,
        network=spec.network,
    )


def would_grant(
    lease: LeaseSubject,
    *,
    model_fingerprint: str,
    lane_id: str,
    policy_hash: str,
    policy_revision: str = "",
    declared_files=(),
    changed_lines: int = 0,
    objective: str = "",
    content: str = "",
    qualification_artifact: str = "",
    attributable_runs: int = 0,
    evidence_verified: bool = True,
    dirty_runs: int = 0,
    workspace_contained: bool = True,
    rollback_available: bool = True,
    tools_requested=(),
    network_requested: str = "none",
    state: str = S_ACTIVE,
    now: datetime | None = None,
) -> ShadowDecision:
    """Would this lease cover this change? Every refusal is collected, none short-circuits.

    Collecting all of them is not thoroughness for its own sake. A caller who fixes the first
    refusal and retries would otherwise discover the next one by trying again, which turns a
    boundary into a search problem. The full list is also the honest answer to "how far away
    is this from being allowed" — usually much further than the first veto suggests.

    There is no weighting and no score: **any** refusal refuses. A perfect history cannot
    offset a protected surface, in exactly the way a strong engineering measurement cannot
    offset 0/14 on security.
    """
    refusals: list[Refusal] = []
    considered: list[str] = []

    def check(name, ok, code, detail):
        considered.append(name)
        if not ok:
            refusals.append(Refusal(code, detail))

    # --- identity: is this even the same lease's subject? ---
    check(
        "model_fingerprint",
        bool(model_fingerprint) and model_fingerprint == lease.model_fingerprint,
        R_FINGERPRINT,
        f"lease binds {lease.model_fingerprint[:19]}…, run reports "
        f"{(model_fingerprint or 'nothing')[:19]}…",
    )
    check("lane", lane_id == lease.lane_id, R_LANE,
          f"lease binds {lease.lane_id}, change declares {lane_id or 'no lane'}")
    check("policy_hash", policy_hash == lease.policy_hash, R_POLICY,
          "the effective policy differs from the one the lease was written against")
    check("policy_revision", policy_revision == lease.policy_revision, R_POLICY,
          "the active route revision differs from the one the lease was written against")

    # --- state ---
    considered.append("state")
    if state == S_REVOKED:
        refusals.append(Refusal(R_REVOKED, "the lease has been revoked"))
    elif state == S_EXPIRED:
        refusals.append(Refusal(R_EXPIRED, "the lease has expired"))
    elif state != S_ACTIVE:
        refusals.append(Refusal(R_REVOKED, f"the lease is {state}, not {S_ACTIVE}"))

    considered.append("expiry")
    moment = now or datetime.now(timezone.utc)
    try:
        if lease.expires_at and datetime.fromisoformat(lease.expires_at) <= moment:
            refusals.append(Refusal(R_EXPIRED, f"expired at {lease.expires_at}"))
    except ValueError:
        refusals.append(Refusal(R_EXPIRED, "the lease carries an unreadable expiry"))

    # --- scope ---
    files = [str(f) for f in (declared_files or ())]
    outside = sorted(f for f in files if f not in lease.allowed_paths)
    check("declared_paths", not outside, R_PATH_OUTSIDE, f"outside the lease: {outside}")
    check("file_count", len(files) <= lease.max_files, R_FILES_TOO_MANY,
          f"{len(files)} files, lease allows {lease.max_files}")
    check("diff_size", changed_lines <= lease.max_changed_lines, R_DIFF_TOO_LARGE,
          f"{changed_lines} changed lines, lease allows {lease.max_changed_lines}")
    check("tools", not list(tools_requested), R_TOOLS,
          f"lease grants no tools; requested {list(tools_requested)}")
    check("network", network_requested == lease.network, R_NETWORK,
          f"lease allows network {lease.network!r}, requested {network_requested!r}")

    # --- the risk gate, run independently of everything above ---
    considered.append("risk_class")
    risk = task_risk.classify(
        declared_files=files, content=content, objective=objective
    )
    if risk.risk_class == task_risk.RISK_PROTECTED_SECURITY:
        refusals.append(Refusal(
            R_PROTECTED, f"protected surfaces: {', '.join(risk.surfaces) or 'unnamed'}"
        ))
    elif risk.risk_class != task_risk.RISK_LOW_ENGINEERING:
        refusals.append(Refusal(R_RISK_CLASS, f"classified {risk.risk_class}"))

    # --- the evidence a lease would rest on ---
    check("qualification", bool(lease.qualification_artifact), R_QUALIFICATION_MISSING,
          "the lease names no qualification artifact")
    check(
        "qualification_match",
        qualification_artifact == lease.qualification_artifact,
        R_QUALIFICATION_STALE,
        "the qualification artifact on file is not the one the lease was written against",
    )
    check("attributable_history", attributable_runs >= lease.min_attributable_runs,
          R_HISTORY,
          f"{attributable_runs} attributable runs, lease requires "
          f"{lease.min_attributable_runs}")
    check("evidence", evidence_verified, R_EVIDENCE, "the signed evidence did not verify")
    check("dirty_runs", dirty_runs == 0, R_DIRTY, f"{dirty_runs} unresolved dirty run(s)")
    check("containment", workspace_contained, R_NOT_CONTAINED,
          "the workspace is not confined")
    check("rollback", rollback_available or not lease.rollback_required, R_NO_ROLLBACK,
          "the lease requires rollback and none is available")

    return ShadowDecision(
        decision=WOULD_REFUSE if refusals else WOULD_GRANT,
        lease_digest=lease.digest,
        refusals=tuple(refusals),
        considered=tuple(considered),
    )


def transition_allowed(current: str, target: str, *, actor: str) -> tuple[bool, str]:
    """Whether a lifecycle move is permissible, and who may cause it.

    Written before any code that transitions anything, so the next train inherits the rules
    rather than deriving them from whatever the first implementation happened to do.
    """
    if current not in STATES:
        return False, f"unknown state {current!r}"
    if target not in STATES:
        return False, f"unknown target {target!r}"
    if target not in ALLOWED_TRANSITIONS[current]:
        return False, f"{current} -> {target} is not a permitted transition"
    if (current, target) in OWNER_ONLY_TRANSITIONS and actor != "owner":
        return False, f"{current} -> {target} is owner-only; actor was {actor!r}"
    return True, "permitted"


def crash_semantics() -> dict:
    """What a crash means at each point, decided before the authority code exists.

    The 7B.1 reservation ordering was designed this way and it is the reason a crash there
    leaves a classifiable state instead of a silent one. The same discipline applies here: a
    lease that is issued but whose issuance record did not durably land must resolve to *not
    issued*, and a lease whose expiry cannot be read must resolve to *expired*.
    """
    return {
        "issued_but_not_durable": {
            "resolves_to": S_PROPOSED,
            "why": "an unrecorded grant is not a grant; the owner can re-issue deliberately",
        },
        "durable_but_not_acknowledged": {
            "resolves_to": S_OWNER_GRANTED,
            "why": "the authority exists; only its activation is unknown, and activation is "
                   "the cheap half to repeat",
        },
        "active_at_crash": {
            "resolves_to": S_EXPIRED,
            "why": "a lease surviving a restart is an unattended grant nobody re-decided; "
                   "expiring costs one re-issue and is the fail-safe direction",
        },
        "unreadable_expiry": {
            "resolves_to": S_EXPIRED,
            "why": "an expiry that cannot be read is not a bound",
        },
    }
