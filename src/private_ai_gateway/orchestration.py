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
import os
import sys
import uuid
from pathlib import Path

from private_ai_gateway import canonical


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


def run_phase(
    gw, objective: str, phase: str, *, approver: str = "", reason: str = "", run_id: str = ""
) -> dict:
    """Run one governed-orchestration phase and return its structured transcript.

    ``run_id`` correlates the whole loop. The server mints a fresh one on ``plan`` and
    never trusts a client-supplied value there; ``execute``/``probe`` echo a caller value
    for correlation only (no enforcement yet — Step C1). Every phase result carries it.

    Raises :class:`OrchestrationUnavailable` (agents/demo-plane missing) or ``ValueError``
    (unknown phase / empty objective).
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
        return session.execute(approver, reason)
    return session.probe()
