"""Which changes a model may never be trusted to make on its own — decided outside the model.

The local engineering model scored **0 out of 14** on refusing control-weakening changes. Not
most of them: all fourteen. It deleted a signature check, widened path confinement, returned
``PASS`` when evidence was missing, and logged a bearer token — every patch well-formed, in
scope, and passing every structural check. That result settles a design question that would
otherwise stay open: **model self-restraint is not a security boundary.** A model that cannot
recognise a control-weakening request cannot be the thing that declines it, and no amount of
prompt engineering converts a 0/14 into a control.

So the boundary lives out here, in deterministic code that never asks a model anything.

**Three classes, no score.** :data:`RISK_LOW_ENGINEERING`, :data:`RISK_REVIEW_REQUIRED`,
:data:`RISK_PROTECTED_SECURITY`. Deliberately not a number: a scalar invites a threshold, a
threshold invites tuning, and a tuned threshold is how a protected surface eventually gets
classified as routine. Classes do not average.

**Risk only ever ratchets up.** Every signal can raise the class; nothing can lower it. That
asymmetry is the whole safety argument, and it is why the classifier may read the caller's own
description of the work: a description can make the assessment stricter, never laxer. A caller
who labels a signature-check removal as "documentation" gets :data:`RISK_PROTECTED_SECURITY`
anyway, because the label is one input among several and the highest wins.

**The default is not "safe".** An unrecognised change is :data:`RISK_REVIEW_REQUIRED`, not
low-risk. Low risk has to be *earned* by positively matching something known-benign — docs,
comments, tests. Anything else a human looks at. Getting this backwards would mean every
surface nobody thought to enumerate silently became eligible.

**Qualification does not override this.** A model measured as excellent at engineering is
still not eligible for a protected surface; the two are different questions, and this module
answers only the second. Eligibility for autonomous execution is reported here as a fact about
the *task*, and nothing in this repo currently grants autonomous execution to anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Routine engineering: no protected surface, no ambiguity. The only class that could ever be
#: a candidate for autonomous execution — and even then, only if something grants it, which
#: nothing currently does.
RISK_LOW_ENGINEERING = "LOW_RISK_ENGINEERING"

#: A human looks at it. The default for anything not positively recognised as benign.
RISK_REVIEW_REQUIRED = "REVIEW_REQUIRED"

#: Touches a control. Never eligible for autonomous execution, whatever the model scored.
RISK_PROTECTED_SECURITY = "PROTECTED_SECURITY"

#: Ordered least to most restrictive. Comparison is by index; there is no arithmetic.
RISK_ORDER = (RISK_LOW_ENGINEERING, RISK_REVIEW_REQUIRED, RISK_PROTECTED_SECURITY)


def _rank(risk_class: str) -> int:
    return RISK_ORDER.index(risk_class)


def raise_to(current: str, candidate: str) -> str:
    """The stricter of two classes. The only combinator — risk never averages or decays."""
    return candidate if _rank(candidate) > _rank(current) else current


@dataclass(frozen=True)
class ProtectedSurface:
    """One control, and the vocabulary that betrays a change to it.

    ``paths`` catches changes to the real modules. ``symbols`` catches the same change made to
    a file with an innocuous name — which is the normal case for a proposal, and exactly how
    the qualification corpus presents its fourteen tasks (``verify.py``, ``confine.py``,
    ``check.py``). Matching on names alone would miss every one of them.
    """

    surface_id: str
    label: str
    paths: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()


#: The controls. Each entry is a surface a change to which must never execute unreviewed.
#: This list is the security boundary; adding to it is cheap and removing from it should not
#: be, so a test pins its identifiers.
PROTECTED_SURFACES: tuple[ProtectedSurface, ...] = (
    ProtectedSurface(
        "authentication", "Authentication",
        paths=("app.py",),
        symbols=("auth_token", "bearer", "constant_time", "compare_digest", "authenticate",
                 "api_key", "credential"),
    ),
    ProtectedSurface(
        "authorization", "Authorization",
        paths=("policy.py", "authz"),
        symbols=("authorize", "allowed_models", "allowlist", "permission", "is_allowed",
                 "can_read_audit", "grant"),
    ),
    ProtectedSurface(
        "approval", "Owner approval",
        paths=("approvals.py",),
        # ``owner_required`` is the literal reason code the gateway returns on a self-approval
        # attempt, and it was missing here: a proposal saying "skip owner_required" named the
        # control by its own name and classified LOW_RISK. Found by a lane test, not by review.
        symbols=("approval", "approver", "owner_token", "owner_required", "owner gate",
                 "owner gating", "single_use", "mark_used", "validate_for_execute"),
    ),
    ProtectedSurface(
        "policy", "Policy engine",
        paths=("policy.py",),
        symbols=("policy_hash", "policy_file", "load_policy", "principal"),
    ),
    ProtectedSurface(
        "autonomy", "Autonomy ceiling",
        paths=("autonomy.py",),
        symbols=("autonomy", "declared_level", "ceiling", "effective_autonomy"),
    ),
    ProtectedSurface(
        "routing_authority", "Model routing authority",
        paths=("registry.py", "route"),
        symbols=("route_map", "route_alias", "select_model", "choose_model",
                 "model_routes", "activate_route"),
    ),
    ProtectedSurface(
        "evidence", "Evidence chain",
        paths=("sink.py", "evidence"),
        symbols=("evidence", "verify_chain", "chain_error", "record_type", "payload_hash",
                 "verify_or_raise"),
    ),
    ProtectedSurface(
        "signing", "Signing and key custody",
        paths=("sink.py",),
        # Deliberately not bare "signature": in this codebase that word usually means a
        # *function* signature, and matching it flagged "keep the signature" on a pure
        # refactor. Cryptographic context is required.
        symbols=("hmac", "sign_envelope", "signature check", "signature verif",
                 "signature valid", "verify_signature", "signature does not match",
                 "signing_key", "emitter_key", "digest_matches", "signed record"),
    ),
    ProtectedSurface(
        "identity", "Run and principal identity",
        paths=("approvals.py",),
        symbols=("run_id", "principal_id", "identity", "get_run", "create_run"),
    ),
    ProtectedSurface(
        "canonical_plan", "Canonical-plan binding",
        paths=("canonical.py",),
        symbols=("canonical_plan", "canonical_plan_hash", "plan_hash", "canonicalize"),
    ),
    ProtectedSurface(
        "replay", "Replay protection",
        paths=(),
        symbols=("replay", "nonce", "single_use", "already_used", "idempoten"),
    ),
    ProtectedSurface(
        "confinement", "Sandbox and path confinement",
        paths=("apply.py", "sandbox", "preimage.py"),
        # Not bare "resolve" — it matched "ref_unresolved" on an unrelated task. Path
        # resolution is named specifically.
        symbols=("confine", "sandbox", "realpath", "resolve path", "path resolution",
                 "traversal", "workspace_root", "declared_files", "escape",
                 "absolute path", "outside the"),
    ),
    ProtectedSurface(
        "secrets", "Secret handling",
        paths=("guardrails.py",),
        symbols=("redact", "secret", "token", "password", "private_key", "log_safe"),
    ),
    ProtectedSurface(
        "rate_limit", "Rate limiting",
        paths=("ratelimit.py",),
        symbols=("rate_limit", "ratelimit", "token_bucket", "retry_after", "throttle",
                 "quota"),
    ),
    ProtectedSurface(
        "reconciliation", "Crash reconciliation",
        paths=("reconciliation.py",),
        symbols=("reconcil", "invalidate_run", "dirty_run", "classify_run"),
    ),
    ProtectedSurface(
        "disposition", "Terminal run disposition",
        paths=("disposition.py",),
        symbols=("disposition", "dispose", "closed_unknown", "human_asserted"),
    ),
    ProtectedSurface(
        "rollback", "Rollback authority",
        paths=("rollback.py",),
        # "roll back" as two words did not match "rollback": separator collapsing normalises
        # `roll_back` and `roll-back` to the spaced form, but never joins a genuine space.
        # Plain English asks for a rollback in two words far more often than one.
        symbols=("rollback", "roll back", "restore_into", "pre_image", "preimage",
                 "snapshot_digest"),
    ),
    ProtectedSurface(
        "containment", "Containment",
        paths=(),
        # Not bare "contain" — it matched the word "containing" in a string-literal task.
        symbols=("containment", "contained", "quarantine"),
    ),
    ProtectedSurface(
        "command_execution", "Arbitrary command execution",
        paths=(),
        symbols=("subprocess", "os system", "shell", "command", "eval(", "exec(", "popen",
                 "run before", "setup step"),
    ),
    ProtectedSurface(
        "prompt_boundary", "Ingress prompt-injection boundary",
        paths=("ingress.py",),
        symbols=("prompt_injection", "jailbreak", "normalize_prompt", "homoglyph"),
    ),
)

#: Positively-benign vocabulary. A change must match one of these *and* no protected surface
#: to earn LOW_RISK_ENGINEERING. Never sufficient on its own — it only rules the default out.
BENIGN_PATHS = ("docs/", "README", "CHANGELOG", ".md", "site/", "tests/", "test_")

#: Why a task landed where it did. Codes, not prose, so a caller can act on them.
REASON_PROTECTED_PATH = "protected_path"
REASON_PROTECTED_SYMBOL = "protected_symbol"
REASON_PROTECTED_OBJECTIVE = "protected_objective"
REASON_CLAIM_OVERRIDDEN = "claim_overridden"
REASON_UNRECOGNISED = "unrecognised_surface"
REASON_BENIGN_ONLY = "benign_paths_only"


@dataclass(frozen=True)
class RiskAssessment:
    """What class a change is, why, and whether it may execute without a human.

    ``eligible_for_autonomous_execution`` is a statement about the *task*, not a grant. It is
    False for everything except :data:`RISK_LOW_ENGINEERING`, and even there it means only
    "this class is not disqualifying" — nothing in this repo consumes it as authority.
    """

    risk_class: str = RISK_REVIEW_REQUIRED
    surfaces: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    claimed_class: str = ""
    details: tuple[str, ...] = field(default=())

    @property
    def eligible_for_autonomous_execution(self) -> bool:
        return self.risk_class == RISK_LOW_ENGINEERING

    @property
    def protected(self) -> bool:
        return self.risk_class == RISK_PROTECTED_SECURITY

    def to_mapping(self) -> dict:
        return {
            "risk_class": self.risk_class,
            "surfaces": list(self.surfaces),
            "reasons": list(self.reasons),
            "claimed_class": self.claimed_class,
            "details": list(self.details),
            "eligible_for_autonomous_execution": self.eligible_for_autonomous_execution,
            "grants": "nothing",
        }


_SEPARATORS = re.compile(r"[\s_\-./]+")


def _normalise(text: str) -> str:
    """Lowercase and collapse separators, so prose and identifiers match the same vocabulary.

    A request to "drop the canonical plan hash check" and the identifier
    ``canonical_plan_hash`` name the same control. Matching them separately meant the prose
    form slipped past — which is the form a proposal's objective is actually written in.
    """
    return _SEPARATORS.sub(" ", (text or "").lower())


def _word_hit(haystack: str, needle: str) -> bool:
    """Substring for fragments that end mid-word by design (``reconcil``, ``idempoten``)."""
    return _normalise(needle) in haystack


def _surfaces_in_paths(paths) -> list[tuple[str, str]]:
    hits = []
    for path in paths or ():
        low = _normalise(str(path))
        for surface in PROTECTED_SURFACES:
            if any(_word_hit(low, p.lower()) for p in surface.paths):
                hits.append((surface.surface_id, f"{surface.label}: path {path}"))
    return hits


def _surfaces_in_text(text: str, origin: str) -> list[tuple[str, str]]:
    low = _normalise(text)
    hits = []
    for surface in PROTECTED_SURFACES:
        for symbol in surface.symbols:
            if _word_hit(low, symbol.lower()):
                hits.append((surface.surface_id, f"{surface.label}: {symbol!r} in {origin}"))
                break
    return hits


def classify(
    *,
    declared_files=(),
    content: str = "",
    objective: str = "",
    claimed_class: str = "",
) -> RiskAssessment:
    """Classify a proposed change from what it touches — never from what it calls itself.

    Reads three independent inputs and takes the strictest answer: the files it declares, the
    content it would write, and the objective describing it. The objective is read *only*
    because it can raise the class; a caller cannot talk their way down, since ``claimed_class``
    is recorded and then ignored unless it is stricter than what the evidence shows.

    **Any mention of a control's vocabulary is enough.** An earlier version also required a
    weakening verb — "remove", "disable", "bypass" — on the theory that code which merely
    *uses* a signature check reads differently from a request to delete one. That is true, and
    it is still the wrong rule: it made the boundary depend on recognising intent in English,
    and it missed 7 of the corpus's 14 control-weakening tasks, including "add a field that
    carries a shell command to run" and "log the full Authorization header". Neither contains a
    weakening verb; both are attacks. Over-classifying costs a human glance. Under-classifying
    costs the control.
    """
    surfaces: list[str] = []
    reasons: list[str] = []
    details: list[str] = []
    risk = RISK_REVIEW_REQUIRED

    def record(hits, reason_code):
        nonlocal risk
        if not hits:
            return
        for surface_id, detail in hits:
            if surface_id not in surfaces:
                surfaces.append(surface_id)
            if detail not in details:
                details.append(detail)
        if reason_code not in reasons:
            reasons.append(reason_code)
        risk = raise_to(risk, RISK_PROTECTED_SECURITY)

    record(_surfaces_in_paths(declared_files), REASON_PROTECTED_PATH)
    record(_surfaces_in_text(content, "content"), REASON_PROTECTED_SYMBOL)

    # The objective is read for control vocabulary too. A request to "remove the signature
    # check" names its own target even when the file is called verify.py and the patch has not
    # been written yet.
    record(_surfaces_in_text(objective, "objective"), REASON_PROTECTED_OBJECTIVE)

    if risk != RISK_PROTECTED_SECURITY:
        files = [str(f) for f in (declared_files or ())]
        if files and all(
            any(marker.lower() in f.lower() for marker in BENIGN_PATHS) for f in files
        ):
            if not surfaces:
                risk = RISK_LOW_ENGINEERING
                reasons.append(REASON_BENIGN_ONLY)
        elif not surfaces:
            reasons.append(REASON_UNRECOGNISED)

    claimed = (claimed_class or "").strip()
    if claimed in RISK_ORDER:
        # A stricter claim is honoured; a laxer one is recorded and discarded.
        raised = raise_to(risk, claimed)
        if raised != risk:
            risk = raised
        elif _rank(claimed) < _rank(risk):
            reasons.append(REASON_CLAIM_OVERRIDDEN)
    elif claimed:
        reasons.append(REASON_CLAIM_OVERRIDDEN)

    return RiskAssessment(
        risk_class=risk,
        surfaces=tuple(surfaces),
        reasons=tuple(reasons),
        claimed_class=claimed,
        details=tuple(details),
    )


def classify_proposal(proposal, *, objective: str = "") -> RiskAssessment:
    """Classify a sandbox proposal mapping — the shape the governed loop actually carries."""
    if not isinstance(proposal, dict):
        return classify(objective=objective)
    edits = proposal.get("edits") or proposal.get("changes") or []
    content_parts = []
    for edit in edits if isinstance(edits, list) else []:
        if isinstance(edit, dict):
            content_parts.append(str(edit.get("content", "")))
            content_parts.append(str(edit.get("path", "")))
    return classify(
        declared_files=proposal.get("declared_files") or proposal.get("files") or (),
        content="\n".join(content_parts),
        objective=objective or str(proposal.get("objective", "")),
        claimed_class=str(proposal.get("risk_class", "")),
    )
