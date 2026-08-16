"""The prospective lease, and every way it must refuse.

A lease that only ever gets tested on the case it was designed for is a lease that has been
described, not designed. The cases below are mostly refusals, and the ones that matter are the
near-identical ones: the same change, the same lane, the same policy — one field different.

The whole value of a *binding* is that varying any single bound field produces a different
lease. If a model swap, a policy revision, or one extra file slipped through, the lease would
be a permission level wearing a narrower name.
"""

from __future__ import annotations

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from private_ai_gateway import lanes, lease, task_risk

REPO_ROOT = Path(__file__).resolve().parents[2]

FP_A = "sha256:" + "a" * 64
FP_B = "sha256:" + "b" * 64
POLICY = "sha256:" + "c" * 64
ARTIFACT = "docs/qualification/bakeoff/aaaaaaaaaaaa.json"
NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def subject():
    return lease.propose(
        principal="opencode",
        model_fingerprint=FP_A,
        lane_id=lanes.GENERATED_METRICS_REFRESH.lane_id,
        policy_hash=POLICY,
        policy_revision="rev-3",
        qualification_artifact=ARTIFACT,
        qualification_corpus_version="2.0",
        min_attributable_runs=20,
        now=NOW,
    )


def ask(subject, **over):
    base = dict(
        model_fingerprint=FP_A,
        lane_id=lanes.GENERATED_METRICS_REFRESH.lane_id,
        policy_hash=POLICY,
        policy_revision="rev-3",
        declared_files=["docs/public-metrics.json"],
        changed_lines=1,
        objective="refresh the generated metrics manifest",
        qualification_artifact=ARTIFACT,
        attributable_runs=20,
        now=NOW,
    )
    base.update(over)
    return lease.would_grant(subject, **base)


def codes(decision):
    return {r.code for r in decision.refusals}


# --- the subject binds what it says it binds ---------------------------------------------


def test_the_lease_binds_every_field_the_specification_requires(subject):
    body = subject.to_mapping()
    for required in (
        "principal", "model_fingerprint", "lane_id", "policy_hash", "policy_revision",
        "allowed_paths", "tools", "max_files", "max_changed_lines", "expires_at",
        "evidence_required", "rollback_required", "qualification_artifact",
        "min_attributable_runs",
    ):
        assert required in body, f"a lease must bind {required}"
    assert body["grants"] == "nothing"


def test_changing_any_bound_field_changes_the_digest(subject):
    """Two leases differing in one value must not be able to pass for each other."""
    import dataclasses

    baseline = subject.digest
    for field_name, value in (
        ("principal", "someone-else"),
        ("model_fingerprint", FP_B),
        ("lane_id", "OTHER_LANE"),
        ("policy_hash", "sha256:zzz"),
        ("policy_revision", "rev-4"),
        ("max_files", 99),
        ("expires_at", "2030-01-01T00:00:00+00:00"),
    ):
        assert dataclasses.replace(subject, **{field_name: value}).digest != baseline, (
            f"{field_name} does not affect the lease identity"
        )


def test_scope_comes_from_the_lane_not_from_the_caller(subject):
    spec = lanes.GENERATED_METRICS_REFRESH
    assert subject.allowed_paths == tuple(spec.allowed_paths)
    assert subject.max_files == spec.max_files
    assert subject.tools == ()
    assert subject.network == "none"


def test_a_lease_cannot_be_proposed_for_a_lane_that_does_not_exist():
    with pytest.raises(ValueError):
        lease.propose(
            principal="opencode", model_fingerprint=FP_A, lane_id="MADE_UP",
            policy_hash=POLICY,
        )


def test_a_lease_lifetime_is_capped_however_long_is_asked_for():
    long_lease = lease.propose(
        principal="opencode", model_fingerprint=FP_A,
        lane_id=lanes.GENERATED_METRICS_REFRESH.lane_id, policy_hash=POLICY,
        lifetime_seconds=10 ** 9, now=NOW,
    )
    expiry = datetime.fromisoformat(long_lease.expires_at)
    assert expiry - NOW <= timedelta(seconds=lease.MAX_LEASE_SECONDS)


# --- the positive case, so the refusals mean something ---------------------------------------


def test_the_intended_change_would_grant(subject):
    decision = ask(subject)
    assert decision.would_grant, decision.refusals
    assert decision.decision == lease.WOULD_GRANT
    assert decision.lease_digest == subject.digest


def test_even_a_grant_says_it_grants_nothing(subject):
    body = ask(subject).to_mapping()
    assert body["grants"] == "nothing"
    assert body["consumed_by"] == "nothing"
    assert "PROSPECTIVE" in body["posture"]


# --- one field at a time ------------------------------------------------------------------


def test_a_model_swap_refuses(subject):
    assert lease.R_FINGERPRINT in codes(ask(subject, model_fingerprint=FP_B))


def test_an_absent_fingerprint_refuses(subject):
    assert lease.R_FINGERPRINT in codes(ask(subject, model_fingerprint=""))


def test_a_policy_hash_change_refuses(subject):
    assert lease.R_POLICY in codes(ask(subject, policy_hash="sha256:different"))


def test_a_route_revision_change_refuses(subject):
    """Activating a new route revision must not silently extend a running lease."""
    assert lease.R_POLICY in codes(ask(subject, policy_revision="rev-4"))


def test_a_different_lane_refuses(subject):
    assert lease.R_LANE in codes(ask(subject, lane_id="SOMETHING_ELSE"))


def test_one_extra_file_outside_the_lease_refuses(subject):
    decision = ask(subject, declared_files=[
        "docs/public-metrics.json", "src/private_ai_gateway/approvals.py",
    ])
    assert lease.R_PATH_OUTSIDE in codes(decision)


def test_scope_expansion_within_allowed_paths_still_hits_the_file_cap(subject):
    decision = ask(subject, declared_files=list(subject.allowed_paths) * 2)
    assert lease.R_FILES_TOO_MANY in codes(decision)


def test_an_oversized_diff_refuses(subject):
    assert lease.R_DIFF_TOO_LARGE in codes(ask(subject, changed_lines=5000))


def test_requesting_a_tool_refuses(subject):
    assert lease.R_TOOLS in codes(ask(subject, tools_requested=["shell"]))


def test_requesting_network_refuses(subject):
    assert lease.R_NETWORK in codes(ask(subject, network_requested="egress"))


def test_a_missing_qualification_artifact_refuses(subject):
    assert lease.R_QUALIFICATION_STALE in codes(ask(subject, qualification_artifact=""))


def test_a_qualification_from_a_different_run_refuses(subject):
    assert lease.R_QUALIFICATION_STALE in codes(
        ask(subject, qualification_artifact="docs/qualification/bakeoff/other.json")
    )


def test_short_history_refuses(subject):
    assert lease.R_HISTORY in codes(ask(subject, attributable_runs=19))


def test_failed_evidence_refuses(subject):
    assert lease.R_EVIDENCE in codes(ask(subject, evidence_verified=False))


def test_a_dirty_run_refuses(subject):
    assert lease.R_DIRTY in codes(ask(subject, dirty_runs=1))


def test_an_uncontained_workspace_refuses(subject):
    assert lease.R_NOT_CONTAINED in codes(ask(subject, workspace_contained=False))


def test_missing_rollback_refuses_when_the_lease_requires_it(subject):
    assert lease.R_NO_ROLLBACK in codes(ask(subject, rollback_available=False))


def test_an_expired_lease_refuses(subject):
    later = NOW + timedelta(seconds=lease.MAX_LEASE_SECONDS + 60)
    assert lease.R_EXPIRED in codes(ask(subject, now=later))


def test_a_revoked_lease_refuses(subject):
    assert lease.R_REVOKED in codes(ask(subject, state=lease.S_REVOKED))


def test_a_lease_that_is_only_granted_not_active_refuses(subject):
    assert lease.R_REVOKED in codes(ask(subject, state=lease.S_OWNER_GRANTED))


# --- the security boundary, unchanged by any of the above --------------------------------------


def _refusal_tasks():
    from hermes.qualification_corpus import CORPUS, KIND_REFUSE

    return [t for t in CORPUS if t.kind == KIND_REFUSE]


@pytest.mark.parametrize("task", _refusal_tasks(), ids=lambda t: t.task_id)
def test_every_security_task_would_be_refused(subject, task):
    decision = ask(subject, declared_files=list(task.allowed_paths), objective=task.objective)
    assert not decision.would_grant
    assert {lease.R_PROTECTED, lease.R_PATH_OUTSIDE} & codes(decision)


def test_a_protected_change_inside_an_allowed_path_is_still_refused(subject):
    """Every identity field matches and the path is in the lease. The content is not."""
    decision = ask(
        subject,
        declared_files=["README.md"],
        content="def approve(self): return True  # bypass owner_required",
    )
    assert lease.R_PROTECTED in codes(decision)


def test_no_amount_of_history_offsets_a_protected_surface(subject):
    decision = ask(
        subject, attributable_runs=10_000, evidence_verified=True, dirty_runs=0,
        objective="remove the signature check from evidence verification",
    )
    assert not decision.would_grant
    assert lease.R_PROTECTED in codes(decision)


def test_refusals_are_collected_not_short_circuited(subject):
    """A caller must not be able to discover the boundary one veto at a time."""
    decision = ask(
        subject, model_fingerprint=FP_B, policy_hash="sha256:x", attributable_runs=0,
        evidence_verified=False, dirty_runs=2, tools_requested=["shell"],
    )
    assert len(decision.refusals) >= 6


# --- the lifecycle -----------------------------------------------------------------------------


@pytest.mark.parametrize("state", lease.STATES)
def test_every_state_declares_its_permitted_transitions(state):
    assert state in lease.ALLOWED_TRANSITIONS


def test_terminal_states_are_terminal():
    assert lease.ALLOWED_TRANSITIONS[lease.S_REVOKED] == ()
    assert lease.ALLOWED_TRANSITIONS[lease.S_EXPIRED] == ()


def test_a_model_cannot_grant_its_own_proposed_lease():
    ok, why = lease.transition_allowed(lease.S_PROPOSED, lease.S_OWNER_GRANTED, actor="model")
    assert not ok and "owner-only" in why


def test_an_owner_can_grant_a_proposed_lease():
    ok, _ = lease.transition_allowed(lease.S_PROPOSED, lease.S_OWNER_GRANTED, actor="owner")
    assert ok


def test_a_lease_cannot_be_renewed_by_returning_to_an_earlier_state():
    for target in (lease.S_PROPOSED, lease.S_OWNER_GRANTED):
        ok, _ = lease.transition_allowed(lease.S_ACTIVE, target, actor="owner")
        assert not ok, "a renewal must be a new lease, never an extension of a running one"


def test_a_revoked_lease_cannot_be_reactivated():
    ok, _ = lease.transition_allowed(lease.S_REVOKED, lease.S_ACTIVE, actor="owner")
    assert not ok


def test_activation_does_not_require_the_owner_but_granting_does():
    """Activation is mechanical; the decision was the grant."""
    ok, _ = lease.transition_allowed(lease.S_OWNER_GRANTED, lease.S_ACTIVE, actor="gateway")
    assert ok


def test_crash_semantics_fail_towards_no_authority():
    semantics = lease.crash_semantics()
    assert semantics["issued_but_not_durable"]["resolves_to"] == lease.S_PROPOSED
    assert semantics["active_at_crash"]["resolves_to"] == lease.S_EXPIRED
    assert semantics["unreadable_expiry"]["resolves_to"] == lease.S_EXPIRED
    for case in semantics.values():
        assert case["why"], "a crash rule without a reason is a rule nobody can revisit"


# --- the firewall ---------------------------------------------------------------------------------


def test_no_authorization_module_imports_the_lease_module():
    guarded = (
        "approvals.py", "approvals_sqlite.py", "policy.py", "autonomy.py",
        "delegation.py", "tools.py", "ingress.py", "orchestration.py",
    )
    package = REPO_ROOT / "src" / "private_ai_gateway"
    for name in guarded:
        tree = ast.parse((package / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all("lease" not in a.name.split(".") for a in node.names), name
            elif isinstance(node, ast.ImportFrom):
                assert "lease" not in (node.module or "").split("."), name
                assert all(a.name != "lease" for a in node.names), name


def test_the_lease_module_issues_nothing():
    """No store, no writer, no endpoint. Proposing must stay a pure function."""
    source = (REPO_ROOT / "src" / "private_ai_gateway" / "lease.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    names = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    for forbidden in ("issue", "grant", "activate", "revoke", "LeaseStore", "save", "append"):
        assert forbidden not in names, f"lease.py defines {forbidden} — it must grant nothing"
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ("write_text", "open", "mkdir"):
            raise AssertionError("lease.py touches the filesystem")


def test_task_risk_is_consulted_and_not_reimplemented():
    """The lease must not carry its own opinion about what is protected."""
    decision_risk = task_risk.classify(objective="disable the signature check")
    assert decision_risk.risk_class == task_risk.RISK_PROTECTED_SECURITY
    source = (REPO_ROOT / "src" / "private_ai_gateway" / "lease.py").read_text(
        encoding="utf-8"
    )
    assert "task_risk.classify(" in source
    assert "PROTECTED_SURFACES" not in source


# --- the simulation over the real corpus ------------------------------------------------------


def _lane_change(entry):
    """The change a replayed commit would present to the lease."""
    import re

    changed = sum(
        1 for a, b in zip(entry.before.splitlines(), entry.after.splitlines()) if a != b
    )
    return {
        "declared_files": [entry.path],
        "changed_lines": changed,
        "objective": entry.objective,
        "content": entry.after,
        "numbers": re.findall(r"\d+(?:\.\d+)?", entry.after),
    }


def test_the_simulation_over_real_changes_records_what_it_refuses(subject):
    """Eighteen changes that actually shipped, run through the lease. Thirteen would grant.

    The five refusals are the finding. Every one of them is ``site/index.html``, and every
    one trips the *authorization* surface — because the line being edited is marketing copy
    that happens to say "a record of exactly who **authorized** what". The gate reads content
    for control vocabulary and cannot tell prose about authorization from code touching it.

    This is the documented cost of over-classification, arriving as a number instead of a
    principle: **28 % of the real, safe, already-merged changes this lane was derived from
    would still need a human.** The right response is to report it, not to shrink the
    vocabulary — a security gate that learns to ignore the word "authorize" on presentation
    surfaces is one relabelling away from ignoring it everywhere. It does mean the lane is
    narrower in practice than its path list suggests, and any lease decision has to be made
    on the thirteen, not the eighteen.
    """
    from hermes import lane_corpus

    granted, refused = [], {}
    for entry in lane_corpus.CORPUS:
        change = _lane_change(entry)
        decision = ask(
            subject,
            declared_files=change["declared_files"],
            changed_lines=change["changed_lines"],
            objective=change["objective"],
            content=change["content"],
        )
        if decision.would_grant:
            granted.append(entry.task_id)
        else:
            refused[entry.task_id] = sorted(codes(decision))

    assert len(granted) == 13
    assert len(refused) == 5
    assert all(codes == [lease.R_PROTECTED] for codes in refused.values()), refused
    assert all(
        lane_corpus.task_by_id(task_id).path == "site/index.html" for task_id in refused
    ), "the refusals are expected to be presentation copy, not a new class of change"


def test_the_simulation_is_not_vacuous(subject):
    """A simulation where everything grants proves nothing. Count the refusals too."""
    from hermes import lane_corpus
    from hermes.qualification_corpus import CORPUS as ENG
    from hermes.qualification_corpus import KIND_REFUSE

    granted = sum(
        1 for e in lane_corpus.CORPUS
        if ask(subject, declared_files=[e.path], changed_lines=1,
               objective=e.objective, content=e.after).would_grant
    )
    refused = sum(
        1 for t in ENG if t.kind == KIND_REFUSE
        and not ask(subject, declared_files=list(t.allowed_paths),
                    objective=t.objective).would_grant
    )
    assert 0 < granted < len(lane_corpus.CORPUS)
    assert refused == 14
