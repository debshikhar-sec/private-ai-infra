"""Earned-autonomy readiness, computed in shadow. It grants nothing, and nothing reads it.

This is the first module that puts qualification, attributed runtime history, task risk and
evidence integrity in front of one question — *could this ever run unattended?* — and it
answers it **advisorily**. Nothing consumes the answer. There is no lease, no auto-approval, no
Enable button, and no code path by which a result here becomes permission.

That sounds like a strange thing to build. It exists because the alternative is worse: the
first time this reasoning gets written will be the time somebody wants to act on it, under
pressure, with the design decided in the same breath as the grant. Writing it now — inert,
tested, and deliberately unreachable from the authorization path — means the shape can be
argued about while the stakes are zero.

**Everything is a veto.** There is no scoring, no weighting, and nothing that trades a
strength against a weakness. Each condition can only produce :data:`NOT_ELIGIBLE`; the positive
outcome is simply the absence of every veto. A model with a flawless record and a protected
surface is not eligible, and no amount of good history changes that — because the reason it is
ineligible has nothing to do with its record.

**The vetoes.** Security lane not qualified. A protected surface. A task that needs review.
Too little attributable history. An evidence chain that does not verify. An unresolved dirty
run. A rollback or containment failure in the relevant history. A model fingerprint that has
changed since the history was earned — because that history belongs to the previous build, and
this is the exact confusion :mod:`private_ai_gateway.attribution` exists to prevent.

**One hypothetical lane.** Right-sized, non-security engineering candidates. Not security
review, not general review, not strategy: those are not on the table and are refused by name
rather than by omission.

**What the honest answer is today.** Nothing is eligible. The local model measured **0 of 14**
on refusing control-weakening changes, so the security-lane veto stands for every candidate;
and the risk gate finds that no source-file task in the qualification corpus is low-risk
enough to clear the protected-surface veto either. Two independent reasons, either sufficient.
That is a finding, not a configuration problem, and this module reports it rather than
smoothing it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: The only two outcomes. Deliberately not a score, not a level, and not a percentage — a
#: number here would invite a threshold, and a threshold is a grant with extra steps.
ELIGIBLE = "ELIGIBLE"
NOT_ELIGIBLE = "NOT_ELIGIBLE"

#: This result is advisory. The word is carried in the payload so it cannot be dropped by a
#: caller rendering only the outcome.
POSTURE = "SHADOW / ADVISORY"

#: The single hypothetical lane. Every other lane is refused by name below.
LANE_ENGINEERING_CANDIDATE = "engineering_candidate"

#: Minimum attributable, verified completions before history means anything at all. Not a
#: tuning knob to be lowered when it proves inconvenient — below this the sample is an
#: anecdote, which is the mistake the 2-task security corpus already taught once.
MIN_ATTRIBUTABLE_RUNS = 20

# Veto codes. Stable, machine-readable, and each one independently sufficient.
V_SECURITY_UNQUALIFIED = "security_lane_unqualified"
V_PROTECTED_SURFACE = "protected_surface"
V_REVIEW_REQUIRED = "review_required_task"
V_INSUFFICIENT_HISTORY = "insufficient_attributable_history"
V_UNATTRIBUTED_HISTORY = "history_not_attributable_to_a_model_build"
V_EVIDENCE_FAILURE = "evidence_failure"
V_DIRTY_RUN = "unresolved_dirty_run"
V_ROLLBACK_FAILURE = "rollback_failure_in_history"
V_CONTAINMENT = "containment_in_history"
V_FINGERPRINT_CHANGED = "model_fingerprint_changed"
V_LANE_NOT_OFFERED = "lane_not_offered_for_autonomy"
V_NO_QUALIFICATION = "lane_never_measured"
# nosec B105 — a veto code naming assurance verdicts, not a credential ("pass" as in PASS).
V_NON_PASS_VERDICTS = "non_pass_verdicts_in_history"  # nosec B105


@dataclass(frozen=True)
class Veto:
    """One independently sufficient reason not to be eligible."""

    code: str
    detail: str


@dataclass(frozen=True)
class EligibilityResult:
    """The advisory answer, every reason behind it, and a refusal to be mistaken for a grant."""

    outcome: str = NOT_ELIGIBLE
    lane: str = LANE_ENGINEERING_CANDIDATE
    model_fingerprint: str = ""
    policy_hash: str = ""
    vetoes: tuple[Veto, ...] = field(default=())
    considered: tuple[str, ...] = field(default=())

    @property
    def eligible(self) -> bool:
        return self.outcome == ELIGIBLE and not self.vetoes

    def to_mapping(self) -> dict:
        return {
            "outcome": self.outcome,
            "posture": POSTURE,
            "lane": self.lane,
            "model_fingerprint": self.model_fingerprint,
            "policy_hash": self.policy_hash,
            "vetoes": [{"code": v.code, "detail": v.detail} for v in self.vetoes],
            "considered": list(self.considered),
            "grants": "nothing",
            "consumed_by": "nothing",
            "note": (
                "Advisory only. No lease, no auto-approval, and no authorization path reads "
                "this result. Execution remains human-gated."
            ),
        }


def evaluate(
    *,
    lane: str = LANE_ENGINEERING_CANDIDATE,
    security_lane_state: str = "",
    lane_state: str = "",
    risk_class: str = "",
    trust_facts=None,
    model_fingerprint: str = "",
    history_fingerprint: str = "",
    policy_hash: str = "",
    evidence_verified: bool = False,
    dirty_runs: int = 0,
) -> EligibilityResult:
    """Collect every veto. The positive outcome is the absence of all of them.

    Each argument is a fact somebody else established: qualification from the registry, risk
    from the deterministic gate, history from the derived trust ledger, evidence integrity from
    the chain reader. This function decides nothing on its own and consults no model.
    """
    from private_ai_gateway import registry as reg
    from private_ai_gateway import task_risk as risk
    from private_ai_gateway import trust_ledger as tl

    vetoes: list[Veto] = []
    considered = [
        "lane_qualification",
        "security_lane_qualification",
        "task_risk_class",
        "attributed_runtime_history",
        "model_fingerprint_continuity",
        "policy_hash",
        "evidence_chain_integrity",
    ]

    def veto(code: str, detail: str) -> None:
        vetoes.append(Veto(code, detail))

    # --- the lane itself -----------------------------------------------------------------
    if lane != LANE_ENGINEERING_CANDIDATE:
        veto(
            V_LANE_NOT_OFFERED,
            f"{lane!r} is not offered for autonomy in any form; only right-sized "
            f"non-security engineering candidates are even hypothetically in scope",
        )

    # --- qualification -------------------------------------------------------------------
    if security_lane_state != reg.QUALIFIED:
        veto(
            V_SECURITY_UNQUALIFIED,
            f"the security review lane is {security_lane_state or 'NOT_EVALUATED'}; a model "
            f"that cannot be shown to refuse control-weakening changes is not a candidate "
            f"for unattended work of any kind",
        )
    if lane_state == reg.NOT_EVALUATED or not lane_state:
        veto(V_NO_QUALIFICATION, f"the {lane} lane has never been measured for this build")
    elif lane_state != reg.QUALIFIED:
        veto(V_NO_QUALIFICATION, f"the {lane} lane is {lane_state}, not QUALIFIED")

    # --- the task ------------------------------------------------------------------------
    if risk_class == risk.RISK_PROTECTED_SECURITY:
        veto(V_PROTECTED_SURFACE, "the change touches a protected surface")
    elif risk_class == risk.RISK_REVIEW_REQUIRED:
        veto(V_REVIEW_REQUIRED, "the change is not positively recognised as low-risk")
    elif risk_class != risk.RISK_LOW_ENGINEERING:
        veto(V_REVIEW_REQUIRED, f"unrecognised risk class {risk_class!r}")

    # --- evidence ------------------------------------------------------------------------
    if not evidence_verified:
        veto(V_EVIDENCE_FAILURE, "the evidence chain did not verify, so no history is usable")

    # --- attribution continuity ----------------------------------------------------------
    if not model_fingerprint or model_fingerprint == tl.NOT_RECORDED:
        veto(V_UNATTRIBUTED_HISTORY, "no model build is recorded for this candidate")
    elif history_fingerprint and history_fingerprint != model_fingerprint:
        veto(
            V_FINGERPRINT_CHANGED,
            "the runtime history was earned by a different model build; a new build starts "
            "with no history rather than inheriting one",
        )
    if not history_fingerprint or history_fingerprint == tl.NOT_RECORDED:
        veto(
            V_UNATTRIBUTED_HISTORY,
            "the runtime history cannot be attributed to a model build",
        )

    # --- the history itself ---------------------------------------------------------------
    if trust_facts is None:
        veto(V_INSUFFICIENT_HISTORY, "there is no runtime history for this key")
    else:
        verified = int(getattr(trust_facts, "verified_complete", 0))
        if verified < MIN_ATTRIBUTABLE_RUNS:
            veto(
                V_INSUFFICIENT_HISTORY,
                f"{verified} attributable verified completion(s); {MIN_ATTRIBUTABLE_RUNS} is "
                f"the minimum before a record is a record rather than an anecdote",
            )
        if int(getattr(trust_facts, "non_pass_verdicts", 0)):
            veto(V_NON_PASS_VERDICTS, "the history contains a non-PASS assurance verdict")
        if int(getattr(trust_facts, "evidence_failures", 0)):
            veto(V_EVIDENCE_FAILURE, "the history contains an evidence-verification failure")
        if int(getattr(trust_facts, "rollback_failed", 0)):
            veto(V_ROLLBACK_FAILURE, "the history contains a failed rollback")
        if int(getattr(trust_facts, "contained", 0)):
            veto(V_CONTAINMENT, "the history contains a contained workspace")
        if int(getattr(trust_facts, "dirty_executions", 0)):
            veto(V_DIRTY_RUN, "the history contains a dirty execution")

    if dirty_runs:
        veto(V_DIRTY_RUN, f"{dirty_runs} unresolved dirty run(s) exist right now")

    return EligibilityResult(
        outcome=NOT_ELIGIBLE if vetoes else ELIGIBLE,
        lane=lane,
        model_fingerprint=model_fingerprint,
        policy_hash=policy_hash,
        vetoes=tuple(vetoes),
        considered=tuple(considered),
    )
