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

import hashlib
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from private_ai_gateway import approvals, canonical
from private_ai_gateway.logutil import log_safe

logger = logging.getLogger("AuditTrail")


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


def _build_peers(gw, tokens: dict[str, str], run_id: str = "") -> dict:
    """One in-process AgentPeer per principal, all hitting this same governed app.

    When ``run_id`` is set, every sub-request carries it as ``X-Run-Id`` so the governed
    hop's audit record can be correlated to the run (see ``before_request``). Correlation
    only — nothing here validates it.
    """
    from interop import AgentPeer

    client = gw.app.test_client()

    def factory(token: str):
        def send(method: str, path: str, body: dict | None = None):
            headers = {"Authorization": f"Bearer {token}"}
            if run_id:
                headers["X-Run-Id"] = run_id
            resp = getattr(client, method.lower())(path, headers=headers, json=body)
            payload = resp.get_json(silent=True)
            if payload is None:
                payload = resp.get_data(as_text=True)
            return resp.status_code, payload

        return send

    return {name: AgentPeer(send=factory(tok)) for name, tok in tokens.items()}


VALID_PHASES = ("plan", "execute", "probe")

# --- D1: canonical plan assembly (metadata only; no enforcement yet) ----------
# Plan-time-deterministic, authority-bearing values. Never the random per-run sandbox
# path, never a delegation id (which only exists at execute); system/policy constants
# only, never model text. See docs/canonical-plan-hashing.md.
_RESOURCE_ROOT_ID = "opencode/review_target"
_PLAN_TASK_CLASS = "code_apply"
_PLAN_ENVIRONMENT = "demo"
_PLAN_CONSTRAINTS = {"no_commit": True, "sandbox_only": True}
_POLICY_VERSION = "policy-file-sha256"
_PLAN_PRINCIPAL = "hermes"


def _policy_hash(gw) -> str:
    """Deterministic hash of the active policy file (Policy exposes no version/hash).

    ``policy_hash`` is authority-bearing, so if the active policy file cannot be read this
    fails closed — no fallback/placeholder value is ever substituted. The caller aborts
    plan-run registration, so no misleading ``canonical_plan_hash`` is returned.
    """
    path = getattr(gw, "POLICY_PATH", "") or ""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise OrchestrationUnavailable(
            f"cannot read policy file for canonical plan hashing ({path!r}): {exc}"
        ) from exc
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _proposal_target_resources() -> list[str]:
    """Files the code.apply proposal declares — deterministic at plan and execute."""
    from opencode_sandbox import apply as act
    from opencode_sandbox.worker import DEFAULT_PROPOSAL

    return act.load_proposal(str(DEFAULT_PROPOSAL)).declared_files


def _assemble_canonical_plan(gw, objective: str, proposal: dict):
    """Build the CanonicalPlan for a proposed code.apply -> (plan, effective, ceiling)."""
    executor = proposal["executor"]
    requested = int(proposal["level"])
    principal = gw.POLICY.find_principal(executor)
    ceiling = gw.autonomy_ceiling_for(principal) if principal is not None else None
    if ceiling is None:
        ceiling = requested
    effective = min(requested, ceiling)

    plan = canonical.canonicalize(
        canonicalization_version=canonical.CANONICALIZATION_VERSION,
        plan_schema_version=1,
        objective=objective,
        principal_id=_PLAN_PRINCIPAL,
        executor=executor,
        skill=proposal["skill"],
        task_class=_PLAN_TASK_CLASS,
        requested_autonomy=requested,
        effective_autonomy=effective,
        policy_version=_POLICY_VERSION,
        policy_hash=_policy_hash(gw),
        resource_root_id=_RESOURCE_ROOT_ID,
        target_resources=_proposal_target_resources(),
        environment=_PLAN_ENVIRONMENT,
        delegation=None,
        constraints=dict(_PLAN_CONSTRAINTS),
        data_sensitivity=None,
    )
    return plan, effective, ceiling


def _register_plan_run(gw, run_id: str, objective: str, result: dict) -> None:
    """Assemble the canonical plan, register the run, and expose the hash on the result.

    Additive: sets ``canonical_plan_hash`` (and ``canonical_plan``) on ``result``. No-op if
    the plan produced no proposal or no store is present. Enforcement is a later step.
    """
    proposal = result.get("proposal")
    store = getattr(gw, "APPROVAL_STORE", None)
    if not proposal or store is None:
        return
    plan, effective, ceiling = _assemble_canonical_plan(gw, objective, proposal)
    digest = plan.digest
    store.create_run(
        run_id=run_id,
        principal_id=_PLAN_PRINCIPAL,
        canonical_plan_hash=digest,
        effective_autonomy=effective,
        policy_ceiling=ceiling,
    )
    result["canonical_plan_hash"] = digest
    result["canonical_plan"] = plan.mapping


# --- D2b: execute enforcement (approval-bound; no inline-approver authority) ----
# Execution authority no longer comes from a request-body approver string. A real apply
# requires a durable, owner-issued approval (see /v1/approvals) that binds to this run's
# run_id AND to a canonical plan hash the server *recomputes* here from deterministic,
# policy-derived inputs — never a model call, never a client-supplied hash. Validation and
# single-use consumption both complete before any delegation/mutation. See
# docs/run-id-approval-design.md and docs/canonical-plan-hashing.md.
_REFUSAL_MESSAGES = {
    approvals.REASON_APPROVAL_MISSING: "no valid approval was presented — authority was never granted",
    approvals.REASON_RUN_NOT_FOUND: "no such run — plan first to register the run",
    approvals.REASON_RUN_MISMATCH: "the approval belongs to a different run",
    approvals.REASON_HASH_MISMATCH: "the plan changed since it was approved — canonical hash mismatch",
    approvals.REASON_REPLAY: "this approval was already used (single-use)",
    approvals.REASON_REJECTED: "the owner rejected this run",
    approvals.REASON_EXPIRED: "the approval has expired",
    approvals.REASON_INVALIDATED: "the run or approval was invalidated",
    approvals.REASON_NOT_APPROVED: "the approval is not in an approved state",
    approvals.REASON_AUTONOMY_EXCEEDED: "requested autonomy exceeds the policy ceiling",
    # Step 5: raised only when REQUIRE_AUTHORIZATION_EVIDENCE is set and the signed
    # authorization record could not be recorded — a fail-closed refusal before any mutation.
    "authorization_evidence_unavailable": (
        "the authorization evidence record could not be recorded — execution denied"
    ),
}

# Step 5 / 5b — gateway authorization evidence emit -------------------------------------
# The gateway emits ONE signed authorization record into an injected, verifier-owned
# EvidenceSink at two authority points, sharing a single emit core:
#   * Step 5  — `execute_validated`: when execution authority is granted (approval validated
#     + single-use consumed) and BEFORE any mutation (orchestration._run_execute).
#   * Step 5b — `approval_decided`: when an approval decision (approve OR reject) is recorded
#     at /v1/approvals, BEFORE the approval response is returned (app.v1_approvals).
# Additive by design: with no sink configured the gateway behaves exactly as before.
# Deliberately narrow — no evidence_refs, no OpenClaw consume, no runtime fail-closed
# integration; those are later, separately-authorized increments.
REASON_EVIDENCE_UNAVAILABLE = "authorization_evidence_unavailable"
_EXECUTE_VALIDATED_RECORD_TYPE = "execute_validated"
_APPROVAL_DECIDED_RECORD_TYPE = "approval_decided"


def _emit_gateway_evidence(
    gw, *, run_id: str, approval_id: str, record_type: str, payload: dict, log_label: str
) -> bool:
    """Emit one signed gateway evidence record; return True iff the caller may proceed.

    Shared core for every gateway authorization record (``execute_validated``,
    ``approval_decided``). Reads the sink/key/key_id/require-flag injection points off ``gw``
    (the app module). The ``REQUIRE_AUTHORIZATION_EVIDENCE`` flag decides every failure
    uniformly — when False, any unavailability is best-effort (log + proceed, True); when
    True, any unavailability is fail-closed (False, so the caller refuses before the outcome
    it guards):

      * no sink configured -> require False: proceed silently (byte-identical old behavior);
        require True: deny (the authorization record cannot be recorded).
      * sink configured but key/key_id missing -> best-effort / fail-closed per the flag.
      * signing/append fails -> best-effort / fail-closed per the flag.

    Never raises to the caller: an unexpected error is contained and mapped onto the same
    require-flag policy, and the internal detail stays in the server log (never the client).
    The record binds ``run_id``/``approval_id`` in the *signing envelope* (sink convention);
    the caller-supplied ``payload`` carries only the authorization fact — the caller is
    responsible for excluding secrets, tokens, prompts, and free text.
    """
    sink = getattr(gw, "EVIDENCE_SINK", None)
    require = bool(getattr(gw, "REQUIRE_AUTHORIZATION_EVIDENCE", False))

    if sink is None:
        if require:
            # Fail closed: authorization evidence is required but no sink is configured.
            logger.warning(
                f"{log_label}_EMIT_UNAVAILABLE | run_id={log_safe(run_id)} "
                "| detail=authorization evidence required but no sink is configured"
            )
            return False
        return True  # default path: no evidence plane -> byte-identical old behavior, quiet

    def _fail(detail: str) -> bool:
        """Apply the require-flag policy to any evidence failure, in one place."""
        logger.warning(
            f"{log_label}_EMIT_FAILED | run_id={log_safe(run_id)} "
            f"| detail={log_safe(detail)}"
        )
        return not require  # proceed when best-effort; deny when evidence is required

    key = getattr(gw, "EVIDENCE_KEY", None)
    key_id = getattr(gw, "EVIDENCE_KEY_ID", "") or ""
    if not key or not key_id:
        return _fail("evidence sink configured but signing key/key_id is missing")

    try:
        from openclaw.sink import (
            EMITTER_GATEWAY,
            SCHEMA_VERSION,
            EvidenceError,
            SigningEnvelope,
            payload_digest,
            sign_envelope,
        )
    except ImportError as exc:  # pragma: no cover - agents path is ensured before emit
        return _fail(f"evidence sink module unavailable: {exc}")

    try:
        envelope = SigningEnvelope(
            schema_version=SCHEMA_VERSION,
            sink_id=sink.sink_id,
            run_id=run_id,
            approval_id=approval_id,
            emitter=EMITTER_GATEWAY,
            emitter_key_id=key_id,
            record_type=record_type,
            payload_hash=payload_digest(payload),
            ts=datetime.now(timezone.utc).isoformat(),
            nonce=uuid.uuid4().hex,
        )
        sig = sign_envelope(envelope, bytes(key))
        sink.append(envelope, payload, sig)
    except EvidenceError as exc:
        return _fail(f"evidence emit rejected: {exc}")
    except Exception as exc:  # defensive: an emit bug must never crash a governed decision
        return _fail(f"unexpected evidence emit error: {exc}")
    return True


def _emit_execute_validated(
    gw, *, run_id: str, approval_id: str, canonical_plan_hash: str
) -> bool:
    """Emit one signed ``execute_validated`` record; return True iff execution may proceed.

    Thin wrapper over :func:`_emit_gateway_evidence`. The payload carries only the
    apply-authorization fact — no secrets, tokens, or plan text.
    """
    return _emit_gateway_evidence(
        gw,
        run_id=run_id,
        approval_id=approval_id,
        record_type=_EXECUTE_VALIDATED_RECORD_TYPE,
        payload={"canonical_plan_hash": canonical_plan_hash, "validated": True},
        log_label="EXECUTE_VALIDATED",
    )


def _emit_approval_decided(
    gw, *, run_id: str, approval_id: str, decision: str, approver: str, canonical_plan_hash: str
) -> bool:
    """Emit one signed ``approval_decided`` record; return True iff the decision may stand.

    Thin wrapper over :func:`_emit_gateway_evidence`, for both approve and reject. The
    payload carries only the decision fact ``{decision, approver, canonical_plan_hash}`` —
    the free-text rejection reason is deliberately excluded from the signed record.
    """
    return _emit_gateway_evidence(
        gw,
        run_id=run_id,
        approval_id=approval_id,
        record_type=_APPROVAL_DECIDED_RECORD_TYPE,
        payload={
            "decision": decision,
            "approver": approver,
            "canonical_plan_hash": canonical_plan_hash,
        },
        log_label="APPROVAL_DECIDED",
    )


def _execute_refusal(run_id: str, reason_code: str) -> dict:
    """A governed execute refusal transcript (HTTP 200): nothing was applied.

    Same shape the Governed Chat Console renders for any execute result, so a refusal is a
    first-class governed outcome, not an error. ``refused``/``refusal_reason`` let the
    handler audit-correlate it to the run without this module touching Flask state.
    """
    message = _REFUSAL_MESSAGES.get(reason_code, "execute refused by governance")
    return {
        "phase": "execute",
        "run_id": run_id,
        "steps": [
            {
                "actor": "owner",
                "action": "the governed approval gate refuses the apply",
                "detail": message,
                "decision": "deny",
                "code": reason_code,
            }
        ],
        "chain": [],
        "verdict": "REFUSED",
        "applied": False,
        "refused": True,
        "refusal_reason": reason_code,
    }


def _recompute_execute_digest(gw, session, objective: str) -> str:
    """Reconstruct the canonical plan deterministically at execute and return its digest.

    Uses only deterministic, policy-derived inputs. The executor is *discovered* from the
    enforced directory exactly as the apply step discovers it (``find_peer`` on the granted
    skill/level) — never a model call, never a client-supplied value. Fails closed if no
    capable executor exists, so a plan that cannot be faithfully reconstructed can never be
    validated for execution.
    """
    from hermes.session import EXEC_LEVEL, EXEC_SKILL

    card = session.hermes.find_peer(EXEC_SKILL, min_level=EXEC_LEVEL, exclude=("hermes",))
    if card is None:
        raise OrchestrationUnavailable(
            "no peer offers code.apply; cannot reconstruct the plan for validation"
        )
    proposal = {
        "executor": card["name"],
        "skill": EXEC_SKILL,
        "level": EXEC_LEVEL,
        "objective": objective,
    }
    plan, _effective, _ceiling = _assemble_canonical_plan(gw, objective, proposal)
    return plan.digest


def _run_execute(gw, session, objective: str, run_id: str, approval_id: str) -> dict:
    """Authorize an apply strictly from a durable, hash-bound approval record.

    The request body's approver/reason grant nothing. Real execution requires a run_id and
    an approval_id that validate against the server-recomputed canonical hash; validation
    and single-use consumption both complete *before* ``session.execute`` (and therefore
    before any delegation/mutation). The approver handed to the apply comes from the stored
    approval, never the request.
    """
    store = getattr(gw, "APPROVAL_STORE", None)
    if store is None:
        raise OrchestrationUnavailable("approval store is not available on this plane")

    # A missing approval_id is the keystone refusal (also the old inline-approver body and
    # the "show the refusal" demo path): refuse without an audited directory reconstruction.
    if not approval_id:
        return _execute_refusal(run_id, approvals.REASON_APPROVAL_MISSING)

    # Authority-bearing: recompute the canonical hash from deterministic inputs only, before
    # any mutation. Fails closed (OrchestrationUnavailable -> 503) if it cannot be rebuilt.
    digest = _recompute_execute_digest(gw, session, objective)

    validation = store.validate_for_execute(run_id, approval_id, digest)
    if not validation.ok:
        return _execute_refusal(run_id, validation.reason)

    # Consume the single-use approval before any delegation/mutation can happen.
    store.mark_used(approval_id)
    # Step 5: now that authority is granted and consumed, emit the signed gateway
    # `execute_validated` record — BEFORE any mutation. Additive/best-effort by default; it
    # only denies here when REQUIRE_AUTHORIZATION_EVIDENCE is set and the emit fails (the
    # approval is already spent in that case — an accepted fail-closed cost for this step).
    if not _emit_execute_validated(
        gw, run_id=run_id, approval_id=approval_id, canonical_plan_hash=digest
    ):
        return _execute_refusal(run_id, REASON_EVIDENCE_UNAVAILABLE)
    # Authority comes from the stored approval, never the request body.
    return session.execute(validation.record.approver, "")


def run_phase(
    gw, objective: str, phase: str, *, approver: str = "", reason: str = "",
    run_id: str = "", approval_id: str = "",
) -> dict:
    """Run one governed-orchestration phase and return its structured transcript.

    ``run_id`` correlates the whole loop. The server mints a fresh one on ``plan`` and
    never trusts a client-supplied value there; ``probe`` echoes a caller value for
    correlation only. ``execute`` is now authority-gated: it applies only under a durable,
    hash-bound approval (``run_id`` + ``approval_id``), and the request-body
    ``approver``/``reason`` grant nothing (an old inline-approver body is a governed
    refusal). See :func:`_run_execute`.

    Raises :class:`OrchestrationUnavailable` (agents/demo-plane missing, or a plan that
    cannot be deterministically reconstructed at execute) or ``ValueError`` (unknown phase
    / empty objective).
    """
    if phase not in VALID_PHASES:
        raise ValueError(f"unknown phase {phase!r}; expected one of {VALID_PHASES}")
    if not (objective or "").strip():
        raise ValueError("objective must not be empty")

    _ensure_agents_on_path()
    from hermes.session import GovernedSession

    if phase == "plan":
        run_id = "run-" + uuid.uuid4().hex  # always fresh; ignore any client-supplied id

    tokens = _demo_tokens(gw)
    peers = _build_peers(gw, tokens, run_id)

    session = GovernedSession(peers, objective, run_id=run_id)

    if phase == "plan":
        result = session.plan()
        _register_plan_run(gw, run_id, objective, result)
        return result
    if phase == "execute":
        return _run_execute(gw, session, objective, run_id, approval_id)
    return session.probe()
