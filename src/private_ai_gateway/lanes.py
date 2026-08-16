"""Named low-risk lanes, defined by what can be *checked* rather than what feels safe.

:mod:`task_risk` answers "is this protected?" — a veto. It leaves everything that is not
protected in one undifferentiated ``REVIEW_REQUIRED`` bucket, and its ``LOW_RISK_ENGINEERING``
class is reachable only by changes confined to documentation, the site, and tests. That is a
floor, not a lane: "the paths look harmless" is not the same claim as "a machine can tell
whether this change is correct".

A lane here must satisfy something stricter. Every one of these must be answerable
mechanically, before any human reads the diff:

  * exactly which paths may change, and which may not;
  * what *kind* of edit is permitted inside them;
  * how many files and how many lines;
  * **what decides whether the result is right** — a real oracle, not a review;
  * whether the change is reversible;
  * what network and tool access is available (both: none).

The last requirement is the one that eliminates almost everything. Prose is not
deterministically verifiable. A model can produce fluent, well-formed, confidently-worded
documentation that is simply false — this project measured exactly that failure fourteen times
out of fourteen on the security corpus, where every patch passed every structural check and
every one removed a control. A "documentation sync" lane graded by a human reading it is not a
lane; it is review with extra steps.

Mining this repository's own merged history (113 squashed commits on ``main``) produced the
evidence these definitions rest on, and most of it was negative:

  * **28 commits** touched only documentation and the site — but their correctness was prose
    correctness, with no oracle;
  * **0 commits** touched only ``tests/``;
  * **0 commits** refreshed the generated metrics manifest on its own — all six that touched
    it were 118–1506 line multi-family changes;
  * **1 commit** was a small source change with tests, and it modified ``app.py``, a protected
    surface;
  * **18 file-changes**, across 13 commits, were *pure numeric substitutions* — every altered
    line identical to its predecessor except for its numbers. That is the one real,
    recurring, machine-checkable population, and it is what the surviving lane is built on.

So the lanes below are deliberately few, and the rejected ones are recorded beside them: a
lane that was considered and thrown out is more useful to the next reader than a lane that was
never mentioned.

**This module grants nothing.** It classifies. No authorization path imports it, and a
structural test enforces that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from private_ai_gateway import task_risk

# --- what a lane may permit ----------------------------------------------------------------

#: The only edit shape any current lane allows. Not "edit a file" — *replace numeric literals
#: inside otherwise-identical lines*. Every other character on a changed line must match the
#: original, which is what makes the change checkable without reading it.
OP_NUMERIC_SUBSTITUTION = "numeric_substitution"
#: Rewrite a whole file from a generator whose output is a pure function of the repository.
OP_REGENERATE = "regenerate_from_source"

OPERATIONS = (OP_NUMERIC_SUBSTITUTION, OP_REGENERATE)

#: Why a change did not qualify for a lane. Codes, so a caller can act on them.
L_NO_LANE = "no_matching_lane"
L_NOT_LOW_RISK = "risk_class_is_not_low"
L_PATH_OUTSIDE_LANE = "path_outside_lane"
L_PATH_FORBIDDEN = "path_explicitly_forbidden"
L_TOO_MANY_FILES = "file_count_over_limit"
L_TOO_MANY_LINES = "changed_lines_over_limit"
L_NON_NUMERIC_EDIT = "edit_changes_more_than_numbers"
L_UNKNOWN_NUMBER = "number_not_present_in_the_canonical_source"
L_CREATED_OR_DELETED = "file_created_or_deleted"
L_OK = "within_lane"


@dataclass(frozen=True)
class LaneSpec:
    """One lane, defined so completely that membership is a computation."""

    lane_id: str
    label: str
    #: Exact repository-relative paths. Not globs: a glob is a promise about files that do not
    #: exist yet, and this lane's whole claim is that its blast radius is enumerable today.
    allowed_paths: tuple[str, ...]
    forbidden_paths: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    max_files: int
    max_changed_lines: int
    required_validation: tuple[str, ...]
    rollback_required: bool
    network: str
    tools: tuple[str, ...]
    risk_class: str
    #: The mechanism that decides correctness. If this reads "human review", it is not a lane.
    oracle: str
    rationale: str = ""

    def to_mapping(self) -> dict:
        return {
            "lane_id": self.lane_id,
            "label": self.label,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "allowed_operations": list(self.allowed_operations),
            "max_files": self.max_files,
            "max_changed_lines": self.max_changed_lines,
            "required_validation": list(self.required_validation),
            "rollback_required": self.rollback_required,
            "network": self.network,
            "tools": list(self.tools),
            "risk_class": self.risk_class,
            "oracle": self.oracle,
            "grants": "nothing",
        }


#: The canonical source of every number this lane is allowed to write.
MANIFEST_PATH = "docs/public-metrics.json"

#: Surfaces the drift suite already holds to the manifest. This list is not "documentation";
#: it is the exact set of files whose numeric claims have a machine-checkable right answer.
DERIVED_NUMERIC_SURFACES = (
    "README.md",
    "site/index.html",
    "docs/roadmap.md",
    "docs/positioning.md",
    "docs/product-evolution.md",
    "docs/local-engineering-qualification.md",
)

GENERATED_METRICS_REFRESH = LaneSpec(
    lane_id="GENERATED_METRICS_REFRESH",
    label="Generated metrics refresh",
    allowed_paths=(MANIFEST_PATH,) + DERIVED_NUMERIC_SURFACES,
    # Named explicitly even though they are already outside ``allowed_paths``. A reader
    # checking whether this lane can reach authorization should not have to reason about a
    # complement set.
    forbidden_paths=(
        "src/",
        "agents/",
        "config/",
        "deploy/",
        ".github/",
        "scripts/",
        "tools/",
        "tests/",
        "Makefile",
        "pyproject.toml",
    ),
    allowed_operations=(OP_REGENERATE, OP_NUMERIC_SUBSTITUTION),
    max_files=1 + len(DERIVED_NUMERIC_SURFACES),
    max_changed_lines=40,
    required_validation=(
        "scripts/public_metrics.py --check",
        "tests/unit/test_public_claims.py",
        "full pytest suite",
        "ruff",
    ),
    rollback_required=True,
    network="none",
    tools=(),
    risk_class=task_risk.RISK_LOW_ENGINEERING,
    oracle=(
        "public_metrics.py recomputes every number from its canonical source and the drift "
        "suite fails if any surface disagrees — so correctness is decided by a program, not "
        "by a reviewer's reading"
    ),
    rationale=(
        "The only change class found in this repository's history whose correct output is "
        "computable: 18 real instances across 13 merged commits. It has never been performed "
        "as a standalone commit, and a lease over it would cover only 13 of those 18 — the "
        "other five edit site copy containing the word 'authorized', which the protected "
        "gate cannot distinguish from code touching authorization. Both facts are limits on "
        "the evidence, not reasons to widen the lane."
    ),
)

LANES: tuple[LaneSpec, ...] = (GENERATED_METRICS_REFRESH,)


@dataclass(frozen=True)
class RejectedLane:
    """A lane that was considered and refused, with the measurement that refused it.

    Kept in the shipped module rather than in a design note, because the next person to want
    an autonomy lane will propose one of these, and the answer should be in the same file as
    the question.
    """

    lane_id: str
    reason: str
    evidence: str


REJECTED_LANES: tuple[RejectedLane, ...] = (
    RejectedLane(
        lane_id="DOCS_SYNC",
        reason="no oracle — prose correctness cannot be decided mechanically",
        evidence=(
            "28 of 113 merged commits were documentation or site only, so the *volume* is "
            "there; none of them could have been validated without someone reading them. "
            "The security corpus is the cautionary case: 14 of 14 patches were well-formed, "
            "in scope, and wrong."
        ),
    ),
    RejectedLane(
        lane_id="STATIC_PRESENTATION_SYNC",
        reason="subsumed — its checkable part is exactly the numeric surfaces above",
        evidence=(
            "Site copy that is derived from canonical data is already covered by "
            "GENERATED_METRICS_REFRESH. What remains is authored copy, which is DOCS_SYNC "
            "under a different name."
        ),
    ),
    RejectedLane(
        lane_id="TEST_FIXTURE_MAINTENANCE",
        reason="no historical instances, and the failure mode is silent",
        evidence=(
            "0 of 113 merged commits touched only tests/. A fixture edited to match changed "
            "behaviour is indistinguishable from a fixture edited to hide a regression, and "
            "the suite passes either way — the oracle is the thing being modified."
        ),
    ),
    RejectedLane(
        lane_id="PURE_NONSECURITY_HELPER",
        reason="no empirical support",
        evidence=(
            "1 of 113 merged commits was a small source-plus-tests change, and it modified "
            "app.py — a protected surface. There is no measured population of small, "
            "non-protected source changes in this repository to define a lane over."
        ),
    ),
)


# --- membership ------------------------------------------------------------------------------

_NUMBER = re.compile(r"\d+(?:\.\d+)?")


@dataclass(frozen=True)
class LaneDecision:
    """Whether a change falls inside a lane, and every reason it might not."""

    lane_id: str = ""
    risk: task_risk.RiskAssessment = field(default_factory=task_risk.RiskAssessment)
    reasons: tuple[str, ...] = ()
    violations: tuple[str, ...] = ()

    @property
    def in_lane(self) -> bool:
        return bool(self.lane_id) and not self.violations

    def to_mapping(self) -> dict:
        return {
            "lane_id": self.lane_id,
            "in_lane": self.in_lane,
            "risk": self.risk.to_mapping(),
            "reasons": list(self.reasons),
            "violations": list(self.violations),
            "grants": "nothing",
        }


def numeric_substitution_only(before: str, after: str, *, allowed: set[str]) -> list[str]:
    """Check that ``after`` differs from ``before`` only by numbers drawn from ``allowed``.

    Line-for-line, and only where a line changed: every non-numeric character must match, and
    each number that appears in a changed line must be one the canonical source actually
    contains. This is what makes the lane checkable. A model that rewrites a sentence while
    updating a count has left the lane even if every number it wrote is correct, because the
    sentence is prose again and nothing can check it.

    Returns the violations found, empty when the edit is clean.
    """
    old_lines = before.splitlines()
    new_lines = after.splitlines()
    violations: list[str] = []
    if len(old_lines) != len(new_lines):
        return [f"{L_NON_NUMERIC_EDIT}: line count changed "
                f"({len(old_lines)} -> {len(new_lines)})"]
    for index, (old, new) in enumerate(zip(old_lines, new_lines), start=1):
        if old == new:
            continue
        if _NUMBER.sub("#", old) != _NUMBER.sub("#", new):
            violations.append(f"{L_NON_NUMERIC_EDIT}: line {index} changed outside its numbers")
            continue
        for number in _NUMBER.findall(new):
            if number not in allowed:
                violations.append(
                    f"{L_UNKNOWN_NUMBER}: line {index} writes {number!r}, which the "
                    "manifest does not contain"
                )
    return violations


def manifest_numbers(manifest: dict) -> set[str]:
    """Every number the manifest asserts, in the string forms a surface may legitimately use.

    A rate of ``0.4333…`` is written as ``43`` on a page and ``0.4333333333333333`` in the
    artifact; both are the same claim. Rounded forms are therefore allowed *only* when derived
    here from the manifest value, never accepted because they look close.
    """
    numbers: set[str] = set()

    def add(value):
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            numbers.add(str(value))
            return
        if isinstance(value, float):
            numbers.add(str(value))
            numbers.add(str(round(value)))
            numbers.add(f"{value:.1f}")
            numbers.add(f"{value:.2f}")
            if 0.0 <= value <= 1.0:
                numbers.add(str(round(value * 100)))
            return
        if isinstance(value, dict):
            for item in value.values():
                add(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                add(item)

    add(manifest)
    return numbers


def classify_change(
    *,
    declared_files=(),
    objective: str = "",
    content: str = "",
    claimed_lane: str = "",
) -> LaneDecision:
    """Decide which lane, if any, a proposed change belongs to.

    Order matters and is not negotiable: :mod:`task_risk` runs **first**, and a change it does
    not call ``LOW_RISK_ENGINEERING`` gets no lane regardless of the paths it declares. A lane
    can only ever narrow. ``claimed_lane`` is recorded and otherwise ignored — the caller does
    not get to name its own lane, for the same reason it does not get to name its own risk
    class.
    """
    risk = task_risk.classify(
        declared_files=declared_files, content=content, objective=objective
    )
    files = [str(f).strip() for f in (declared_files or ()) if str(f).strip()]
    reasons: list[str] = []
    if claimed_lane:
        reasons.append(f"claimed_lane_ignored:{claimed_lane}")

    if risk.risk_class != task_risk.RISK_LOW_ENGINEERING:
        return LaneDecision(
            lane_id="", risk=risk, reasons=tuple(reasons), violations=(L_NOT_LOW_RISK,)
        )
    if not files:
        return LaneDecision(
            lane_id="", risk=risk, reasons=tuple(reasons), violations=(L_NO_LANE,)
        )

    for spec in LANES:
        if not all(f in spec.allowed_paths for f in files):
            continue
        violations = []
        if any(f.startswith(p) or f == p for f in files for p in spec.forbidden_paths):
            violations.append(L_PATH_FORBIDDEN)
        if len(files) > spec.max_files:
            violations.append(L_TOO_MANY_FILES)
        return LaneDecision(
            lane_id=spec.lane_id,
            risk=risk,
            reasons=tuple(reasons + [L_OK] if not violations else reasons),
            violations=tuple(violations),
        )

    outside = sorted({f for f in files if not any(f in s.allowed_paths for s in LANES)})
    return LaneDecision(
        lane_id="",
        risk=risk,
        reasons=tuple(reasons + [f"{L_PATH_OUTSIDE_LANE}:{f}" for f in outside]),
        violations=(L_NO_LANE,),
    )


def spec_for(lane_id: str) -> LaneSpec | None:
    for spec in LANES:
        if spec.lane_id == lane_id:
            return spec
    return None


def catalogue() -> dict:
    """Every lane and every rejected lane, for the console and the docs to read from one place."""
    return {
        "lanes": [spec.to_mapping() for spec in LANES],
        "rejected": [
            {"lane_id": r.lane_id, "reason": r.reason, "evidence": r.evidence}
            for r in REJECTED_LANES
        ],
        "grants": "nothing",
        "note": (
            "A lane is a description of a change class, not a permission. Nothing in the "
            "authorization path reads this module."
        ),
    }
