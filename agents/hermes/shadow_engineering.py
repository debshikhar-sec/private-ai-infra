"""Track C — the shadow-engineering harness.

Capability infrastructure with **zero additional operational authority**. It answers one
question: *could the local engineering model have written this change?* — and records the
answer. It never answers *may it be applied*, because it never asks.

The flow, end to end:

    objective
      -> governed strategy plan          (through the gateway, as a capped principal)
      -> local engineering candidate     (through the gateway, as a capped principal)
      -> strict deterministic validation (opencode_sandbox.candidate)
      -> teacher/evaluator comparison    (deterministic; no model call)
      -> evaluation trace                (local JSON; NOT governance evidence)

What this module structurally cannot do, by construction rather than by convention:

  * **No apply.** It never imports or calls the apply path, ``CodeActWorker``, or a
    ``GovernedSession``. Asserted by a source scan *and* by a filesystem-invariance test.
  * **No approval acquisition.** It never posts to ``/v1/approvals``; a candidate remains a
    candidate, and applying one still needs the existing owner-issued, hash-bound approval.
  * **No owner token.** :class:`ShadowEngineer` refuses to construct if handed one, and
    holds only the capped principals needed to plan and to generate.
  * **No mutation, commit, merge, or deployment.** It writes exactly one thing: a trace
    file, under a runtime path that is git-ignored.

Model calls go through the gateway's normal governed path, so policy, model authorization
and the autonomy ceiling all apply to the local model exactly as to any other principal.
The trace records *identity*, not permission: alias, resolved model, policy hash, principal
and declared autonomy. **The trace is not authority** — nothing reads it back to decide
anything, and it is never written to the evidence sink.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from opencode_sandbox import candidate as cand

# Traces are runtime artifacts, not repository content: local-only and git-ignored.
DEFAULT_TRACE_DIR = Path("runtime/shadow-engineering")

# Verdicts the deterministic evaluator can reach.
V_USABLE = "usable_candidate"
V_REFUSED = "refused_by_adapter"
V_OUT_OF_SCOPE = "out_of_scope"
V_NO_REFERENCE = "no_reference_supplied"
V_MATCHES_REFERENCE = "matches_reference"
V_DIFFERS_FROM_REFERENCE = "differs_from_reference"


class ShadowEngineeringError(RuntimeError):
    """The harness was asked to do something outside its mandate."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash(text: str) -> str:
    return "sha256:" + sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ModelIdentity:
    """Who generated something, in enough detail that a build swap is visible.

    ``resolved_model`` is what the gateway actually served; ``policy_hash`` covers the
    alias -> model binding, so a route change moves the hash and a trace recorded under the
    old binding can never be mistaken for one under the new.
    """

    alias: str = ""
    resolved_model: str = ""
    principal: str = ""
    declared_autonomy: str = ""


@dataclass
class EvaluationTrace:
    """One shadow evaluation. **Not** governance evidence; never written to the sink."""

    trace_id: str
    timestamp: str
    objective_hash: str
    policy_hash: str = ""
    source_commit: str = ""
    strategy_model: ModelIdentity = field(default_factory=ModelIdentity)
    engineering_model: ModelIdentity = field(default_factory=ModelIdentity)
    candidate_parse_status: str = ""
    candidate_reason_code: str = ""
    candidate_declared_files: list[str] = field(default_factory=list)
    deterministic_validation_result: str = ""
    deterministic_violations: list[str] = field(default_factory=list)
    teacher_verdict: str = ""
    teacher_reason_codes: list[str] = field(default_factory=list)
    test_result: str = "not_run"
    applied: bool = False          # invariant: always False; the harness cannot apply

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


def evaluate(objective: str, result: cand.CandidateResult, reference=None):
    """The deterministic teacher: compare a candidate against reference expectations.

    Deliberately rule-based rather than a model call, so CI is reproducible and the harness
    needs no second model to grade the first. ``reference``, when given, is the set of file
    paths a correct answer was expected to touch. Returns ``(verdict, reason_codes)``.
    """
    codes: list[str] = []
    if result.refused:
        codes.append(result.reason_code)
        return V_REFUSED, codes

    declared = set(result.declared_files)
    if reference is None:
        codes.append("no_reference")
        return V_NO_REFERENCE, codes

    expected = set(reference)
    if declared == expected:
        codes.append("scope_exact")
        return V_MATCHES_REFERENCE, codes
    if declared - expected:
        codes.append("scope_exceeds_reference")
    if expected - declared:
        codes.append("scope_incomplete")
    return V_DIFFERS_FROM_REFERENCE, codes


class ShadowEngineer:
    """Runs one shadow evaluation. Holds capped principals; never an owner token.

    ``strategy_call`` and ``engineering_call`` are callables
    ``(messages) -> (text, resolved_model)``. In production they are thin wrappers over
    :class:`hermes.client.GatewayClient`, so every call is governed; in CI they are
    deterministic stubs, so no model is ever downloaded or executed.
    """

    def __init__(
        self,
        *,
        strategy_call,
        engineering_call,
        strategy_identity: ModelIdentity,
        engineering_identity: ModelIdentity,
        owner_token: str = "",
        trace_dir=DEFAULT_TRACE_DIR,
    ):
        if owner_token:
            # The single most important line in this module: the shadow track is defined by
            # what it cannot reach, so holding owner authority is a construction error, not
            # a runtime check to be skipped under pressure.
            raise ShadowEngineeringError(
                "the shadow harness must never hold an owner token: it evaluates "
                "candidates and has no authority to execute one"
            )
        self._strategy_call = strategy_call
        self._engineering_call = engineering_call
        self._strategy_identity = strategy_identity
        self._engineering_identity = engineering_identity
        self._trace_dir = Path(trace_dir)

    # -- the flow ----------------------------------------------------------------------
    def run(
        self,
        objective: str,
        *,
        root,
        allowed_paths=None,
        reference_files=None,
        policy_hash: str = "",
        source_commit: str = "",
        write_trace: bool = True,
    ) -> EvaluationTrace:
        """Plan, generate, validate, evaluate, record. Mutates nothing under ``root``."""
        trace = EvaluationTrace(
            trace_id="shadow-" + uuid.uuid4().hex,
            timestamp=_utc_now_iso(),
            objective_hash=_hash(objective),
            policy_hash=policy_hash,
            source_commit=source_commit,
            strategy_model=self._strategy_identity,
            engineering_model=self._engineering_identity,
        )

        # 1. Governed strategy plan. Advisory context for the engineering prompt — it grants
        #    nothing and is never treated as an instruction to act.
        plan_text, strategy_model = self._strategy_call(_strategy_messages(objective))
        if strategy_model:
            trace.strategy_model = ModelIdentity(
                alias=self._strategy_identity.alias,
                resolved_model=strategy_model,
                principal=self._strategy_identity.principal,
                declared_autonomy=self._strategy_identity.declared_autonomy,
            )

        # 2. Local engineering candidate. Output is DATA; the adapter below decides whether
        #    it is even a candidate.
        raw, engineering_model = self._engineering_call(
            _engineering_messages(
                objective, plan_text, allowed_paths,
                read_scope(root, allowed_paths),
            )
        )
        if engineering_model:
            trace.engineering_model = ModelIdentity(
                alias=self._engineering_identity.alias,
                resolved_model=engineering_model,
                principal=self._engineering_identity.principal,
                declared_autonomy=self._engineering_identity.declared_autonomy,
            )

        # 3. Strict deterministic validation.
        result = cand.parse_candidate(raw, root=root, allowed_paths=allowed_paths)
        trace.candidate_parse_status = "ok" if result.ok else "refused"
        trace.candidate_reason_code = result.reason_code
        trace.candidate_declared_files = list(result.declared_files)
        trace.deterministic_validation_result = "clean" if result.ok else "refused"
        trace.deterministic_violations = list(result.violations)

        # 4. Deterministic teacher comparison.
        verdict, codes = evaluate(objective, result, reference_files)
        trace.teacher_verdict = verdict
        trace.teacher_reason_codes = codes

        # 5. Record. Raw model text is deliberately NOT stored: it is unbounded, may echo
        #    prompt content, and nothing downstream needs it.
        if write_trace:
            self.write(trace)
        return trace

    def write(self, trace: EvaluationTrace) -> Path:
        """Persist one trace under the git-ignored runtime path."""
        self._trace_dir.mkdir(parents=True, exist_ok=True)
        path = self._trace_dir / f"{trace.trace_id}.json"
        path.write_text(trace.to_json(), encoding="utf-8")
        return path


# --- prompts ---------------------------------------------------------------------------

def _strategy_messages(objective: str) -> list[dict]:
    return [
        {"role": "system", "content":
            "You are a planning assistant. Describe, in a few lines, how you would "
            "approach the objective. You are advisory only and cannot execute anything."},
        {"role": "user", "content": objective},
    ]


def read_scope(root, allowed_paths=None, *, max_bytes: int = 64 * 1024) -> dict:
    """Current contents of the in-scope files, for the engineering prompt.

    Read-only, and bounded. Without this the model is asked to emit a whole
    ``new_content`` for a file it has never seen, which does not produce an edit — it
    produces a plausible *rewrite*, silently dropping whatever the real file had. The first
    real local trial did exactly that: it dropped two public parameters and the module
    docstring while still passing every structural check, because scope and shape were
    right and only behaviour was wrong.
    """
    out: dict[str, str] = {}
    if not allowed_paths:
        return out
    base = Path(root)
    for rel in sorted(allowed_paths):
        target = base / rel
        try:
            if target.is_file() and target.stat().st_size <= max_bytes:
                out[rel] = target.read_text(encoding="utf-8")
        except OSError:
            continue                      # unreadable is simply absent context, never fatal
    return out


def _engineering_messages(
    objective: str, plan_text: str, allowed_paths=None, current_files=None
) -> list[dict]:
    scope = ""
    if allowed_paths:
        scope = "\nYou may only edit these files: " + ", ".join(sorted(allowed_paths))
    context = ""
    if current_files:
        blocks = "\n\n".join(
            f"--- {path} (current contents) ---\n{text}"
            for path, text in sorted(current_files.items())
        )
        context = (
            "\n\nThese are the CURRENT contents. Preserve everything the objective does not "
            "ask you to change — existing parameters, defaults, type annotations and "
            "docstrings must survive unless the objective says otherwise.\n\n" + blocks
        )
    return [
        {"role": "system", "content":
            "Return ONLY a JSON object, with no surrounding prose, of the form "
            '{"edits": [{"path": ..., "kind": "modify|create|delete", "new_content": ...}], '
            '"rationale": ...}. ``new_content`` must be the COMPLETE new file, encoded as a '
            'normal JSON string in double quotes with \\n for newlines and \\" for quotes. '
            "Never use Python triple-quoted strings — the output is parsed as strict JSON "
            "and anything else is discarded. You are producing a proposal for human review. "
            "You cannot run commands and you cannot apply anything." + scope},
        {"role": "user",
         "content": f"Objective: {objective}\n\nPlan notes:\n{plan_text}{context}"},
    ]


# --- CLI -------------------------------------------------------------------------------

def _gateway_calls(base_url: str, token: str, alias: str, autonomy_level: str):
    """Wrap the governed gateway client as a ``(messages) -> (text, resolved_model)`` call."""
    from hermes.client import GatewayClient

    client = GatewayClient(base_url, token, model=alias, autonomy_level=autonomy_level)

    def call(messages):
        return client.complete_with_identity(messages)

    return call


def main(argv=None) -> int:
    """``python -m hermes.shadow_engineering`` — one shadow evaluation, no apply."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="hermes.shadow_engineering",
        description="Shadow-evaluate a local engineering model. Generates a candidate "
                    "proposal and records an evaluation trace. Never applies anything.",
    )
    parser.add_argument("objective")
    parser.add_argument("--root", default=".", help="tree the candidate is validated against")
    parser.add_argument("--allow", action="append", default=None,
                        help="a file the candidate may edit (repeatable)")
    parser.add_argument("--expect", action="append", default=None,
                        help="a file a correct answer should touch (repeatable)")
    parser.add_argument("--base-url", default=os.environ.get(
        "PRIVATE_AI_BASE_URL", "http://127.0.0.1:8081"))
    parser.add_argument("--strategy-alias", default="strategy")
    parser.add_argument("--engineering-alias", default="engineering")
    parser.add_argument("--principal", default="shadow-engineer")
    parser.add_argument("--autonomy", default="L1", help="declared autonomy (suggest-only)")
    parser.add_argument("--trace-dir", default=str(DEFAULT_TRACE_DIR))
    args = parser.parse_args(argv)

    token = os.environ.get("PRIVATE_AI_SHADOW_TOKEN", "")
    if not token:
        parser.error("set PRIVATE_AI_SHADOW_TOKEN to the shadow principal's key "
                     "(never an owner token)")

    engineer = ShadowEngineer(
        strategy_call=_gateway_calls(args.base_url, token, args.strategy_alias, args.autonomy),
        engineering_call=_gateway_calls(
            args.base_url, token, args.engineering_alias, args.autonomy),
        strategy_identity=ModelIdentity(
            alias=args.strategy_alias, principal=args.principal,
            declared_autonomy=args.autonomy),
        engineering_identity=ModelIdentity(
            alias=args.engineering_alias, principal=args.principal,
            declared_autonomy=args.autonomy),
        trace_dir=args.trace_dir,
    )
    trace = engineer.run(
        args.objective, root=args.root, allowed_paths=args.allow,
        reference_files=args.expect,
    )
    print(trace.to_json())
    # A refused candidate is a normal, informative outcome — not a harness failure.
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
