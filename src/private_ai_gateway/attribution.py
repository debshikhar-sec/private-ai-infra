"""Which model actually generated this candidate — recorded when it did, not asked later.

The trust history could describe *what* a run did but never *who* produced the candidate.
Nothing in the signed chain named a model, so runtime facts could not be attributed to a
model build, and the ledger reported those dimensions as ``not_recorded`` rather than guess.
This module closes that gap, and the whole design turns on one hazard.

**The hazard: attribution by lookup.** The obvious implementation asks "which model is routed
to this lane?" at the moment evidence is written. That answer is correct only if the route has
not changed since the candidate was produced — and the route is a config value a human edits.
Re-point ``engineering`` at a new build after a plan and before its execute, and every run
still in flight would be credited to a model that never saw them. Worse, it fails in the
flattering direction: a fresh, unmeasured build inherits the record of the one it replaced.

So attribution is **captured at generation time and read back, never recomputed**. When the
plan phase produces a candidate, the gateway resolves the serving model's identity itself and
appends a signed :data:`CANDIDATE_ATTRIBUTED_RECORD_TYPE` record bound to that ``run_id``. At
execute time the server *resolves that record* — it does not consult the route map — and
carries the attribution into ``execute_validated`` alongside a signed ref back to it. A route
change between the two points cannot move the attribution, because the attribution was already
written down and signed.

**The caller supplies none of it.** Every field is derived server-side: the route alias from
the phase that ran, the resolved model from the gateway's own route map at generation time,
the revision and quantization from the local model cache, the policy hash from the active
policy file, and the candidate digest from the proposal the server itself assembled. There is
no request field that reaches this payload, so a client cannot claim to be a better model than
it is.

**Silence stays silent.** Runs that predate this record — and runs on a deployment with no
evidence sink — resolve to :data:`MODEL_NOT_RECORDED` / :data:`POLICY_NOT_RECORDED`. They are
never backfilled from the current configuration, which would be inventing history.

Nothing here grants anything. It makes an existing fact recordable; what may be done with the
record is decided elsewhere, and no authorization module imports this one.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass

_LOG = logging.getLogger("AuditTrail")

#: The signed record type written when a candidate is generated.
CANDIDATE_ATTRIBUTED_RECORD_TYPE = "candidate_attributed"

#: Carried verbatim into evidence when the fact was never recorded. Never inferred.
MODEL_NOT_RECORDED = "model_not_recorded"
POLICY_NOT_RECORDED = "policy_not_recorded"

#: The attribution fields ``execute_validated`` carries. Kept as one tuple so the payload
#: shape and the "unrecorded" shape cannot drift apart.
ATTRIBUTION_FIELDS = (
    "route_alias",
    "model_fingerprint",
    "backend",
    "resolved_model",
    "revision",
    "quantization",
    "task_class",
    "policy_hash",
    "candidate_digest",
)


class AttributionError(Exception):
    """Attribution could not be established from server-side facts."""


@dataclass(frozen=True)
class CandidateAttribution:
    """Who generated a candidate, under what policy, and what exactly they produced.

    ``model_fingerprint`` is the registry's build fingerprint, not the route alias: two
    different builds behind one alias must never share a history. ``candidate_digest`` pins
    *what* was produced, so evidence cannot later be read as covering a different proposal.
    """

    route_alias: str = ""
    model_fingerprint: str = ""
    backend: str = ""
    resolved_model: str = ""
    revision: str = ""
    quantization: str = ""
    task_class: str = ""
    policy_hash: str = ""
    candidate_digest: str = ""

    def to_payload(self) -> dict:
        return {field: getattr(self, field) for field in ATTRIBUTION_FIELDS}


def unrecorded_attribution() -> dict:
    """The honest shape for a run whose generator was never recorded.

    Every field says so explicitly rather than being empty, because an empty string reads as
    "no model" where the truth is "we did not write it down".
    """
    return {
        "route_alias": MODEL_NOT_RECORDED,
        "model_fingerprint": MODEL_NOT_RECORDED,
        "backend": MODEL_NOT_RECORDED,
        "resolved_model": MODEL_NOT_RECORDED,
        "revision": MODEL_NOT_RECORDED,
        "quantization": MODEL_NOT_RECORDED,
        "task_class": MODEL_NOT_RECORDED,
        "policy_hash": POLICY_NOT_RECORDED,
        "candidate_digest": MODEL_NOT_RECORDED,
    }


def candidate_digest(proposal: object) -> str:
    """A stable digest of the candidate, over a canonical serialization.

    Sorted keys and separators fixed, so a re-serialization of the same proposal produces the
    same digest and evidence stays comparable across processes.
    """
    body = json.dumps(proposal, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def attribute_candidate(
    gw, *, route_alias: str, task_class: str, proposal: object, policy_hash: str
) -> CandidateAttribution:
    """Resolve, from server-side state only, which model just produced this candidate.

    Reads the gateway's own route map and backend and the local model cache. Takes no
    caller-supplied identity, and refuses rather than guessing when the alias resolves to
    nothing: an unattributable candidate must stay unattributed.
    """
    from private_ai_gateway import registry as reg

    # The routes actually in force — base policy merged with any active managed revision — so
    # a run is attributed to the model that a revision put behind the alias, not to whatever
    # the hand-authored file alone would say.
    resolver = getattr(gw, "effective_routes", None)
    route_map = getattr(gw, "ROUTE_MAP", {}) or {}
    if resolver is not None:
        try:
            route_map = getattr(resolver(), "routes", None) or route_map
        except Exception as exc:  # noqa: BLE001 — a plan must not fail over a revision read
            _LOG.warning("effective route resolution failed; using the base map: %s", exc)
    resolved = route_map.get(route_alias, "")
    if not resolved:
        raise AttributionError(f"route alias {route_alias!r} resolves to no model")

    backend = getattr(getattr(gw, "BACKEND", None), "name", "") or ""
    try:
        cache = reg.ModelCache()
    except Exception:  # noqa: BLE001 — an unreadable cache means "unknown", not a failure
        cache = None

    identity = reg.identify_model(route_alias, resolved, backend=backend, cache=cache)
    return CandidateAttribution(
        route_alias=route_alias,
        model_fingerprint=identity.fingerprint,
        backend=identity.backend,
        resolved_model=identity.resolved_model,
        revision=identity.revision,
        quantization=identity.quantization,
        task_class=task_class,
        policy_hash=policy_hash,
        candidate_digest=candidate_digest(proposal),
    )


def resolve_recorded_attribution(sink, *, run_id: str) -> dict | None:
    """Read back the attribution recorded for this run, or ``None`` if there is none.

    Deliberately a **read**, not a recomputation. The chain is re-verified first: an
    unverifiable chain yields ``None`` rather than a record that cannot be trusted, and the
    caller then treats the run as unattributed. Exactly one such record may exist per run —
    two would mean the generation point ran twice and neither can be preferred.
    """
    if sink is None or not run_id:
        return None
    try:
        from openclaw.evidence import SinkGraphReader
    except ImportError:  # pragma: no cover — agents path is ensured before use
        return None

    try:
        reader = SinkGraphReader(sink)
        if reader.chain_error:
            return None
        matches = [
            rec
            for rec in reader.records
            if rec.envelope.record_type == CANDIDATE_ATTRIBUTED_RECORD_TYPE
            and rec.envelope.run_id == run_id
        ]
    except Exception:  # noqa: BLE001 — an unreadable sink is "unrecorded", never a crash
        return None

    if len(matches) != 1:
        return None
    payload = matches[0].payload
    if not isinstance(payload, dict):
        return None
    if not payload.get("model_fingerprint"):
        return None
    return {field: payload.get(field, "") for field in ATTRIBUTION_FIELDS}


def attribution_for_evidence(sink, *, run_id: str) -> tuple[dict, bool]:
    """``(attribution_payload, was_recorded)`` for embedding in downstream evidence."""
    recorded = resolve_recorded_attribution(sink, run_id=run_id)
    if recorded is None:
        return unrecorded_attribution(), False
    return recorded, True
