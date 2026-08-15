"""Shadow earned-autonomy readiness — computed, reported, and consumed by nothing.

The load-bearing tests here are the negative ones. Anyone can write a function that says
"eligible"; the question is whether the vetoes actually bite, whether a good record can buy
its way past a protected surface (it must not), and whether any authorization path can reach
the result (it must not). The last of those is proved by falsification: wiring eligibility
into authority and showing the suite goes red.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from private_ai_gateway import eligibility as elig
from private_ai_gateway import registry as reg
from private_ai_gateway import task_risk as risk
from private_ai_gateway import trust_ledger as tl

REPO_ROOT = Path(__file__).resolve().parents[2]
_OWNER = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER}"}


def _spotless_facts(**kw):
    """A history with nothing wrong with it — used to isolate one veto at a time."""
    facts = tl.TrustFacts(
        runs=40,
        verified_complete=elig.MIN_ATTRIBUTABLE_RUNS + 5,
    )
    for key, value in kw.items():
        setattr(facts, key, value)
    return facts


def _clean_inputs(**over):
    """Inputs with every veto satisfied, so a test can break exactly one."""
    base = dict(
        lane=elig.LANE_ENGINEERING_CANDIDATE,
        security_lane_state=reg.QUALIFIED,
        lane_state=reg.QUALIFIED,
        risk_class=risk.RISK_LOW_ENGINEERING,
        trust_facts=_spotless_facts(),
        model_fingerprint="sha256:" + "a" * 64,
        history_fingerprint="sha256:" + "a" * 64,
        policy_hash="sha256:" + "b" * 64,
        evidence_verified=True,
        dirty_runs=0,
    )
    base.update(over)
    return base


# ------------------------------------------------------------------ the baseline behaves


def test_a_hypothetically_perfect_candidate_is_eligible():
    """Only so the vetoes below are known to be doing the work, not a hardcoded refusal."""
    result = elig.evaluate(**_clean_inputs())
    assert result.outcome == elig.ELIGIBLE
    assert result.vetoes == ()


def test_even_eligible_grants_nothing():
    mapping = elig.evaluate(**_clean_inputs()).to_mapping()
    assert mapping["grants"] == "nothing"
    assert mapping["consumed_by"] == "nothing"
    assert mapping["posture"] == "SHADOW / ADVISORY"


# --------------------------------------------------------------------------- every veto


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"security_lane_state": reg.UNQUALIFIED}, elig.V_SECURITY_UNQUALIFIED),
        ({"security_lane_state": reg.NOT_EVALUATED}, elig.V_SECURITY_UNQUALIFIED),
        ({"security_lane_state": reg.ADVISORY_ONLY}, elig.V_SECURITY_UNQUALIFIED),
        ({"lane_state": reg.NOT_EVALUATED}, elig.V_NO_QUALIFICATION),
        ({"lane_state": reg.ADVISORY_ONLY}, elig.V_NO_QUALIFICATION),
        ({"risk_class": risk.RISK_PROTECTED_SECURITY}, elig.V_PROTECTED_SURFACE),
        ({"risk_class": risk.RISK_REVIEW_REQUIRED}, elig.V_REVIEW_REQUIRED),
        ({"evidence_verified": False}, elig.V_EVIDENCE_FAILURE),
        ({"trust_facts": None}, elig.V_INSUFFICIENT_HISTORY),
        ({"model_fingerprint": ""}, elig.V_UNATTRIBUTED_HISTORY),
        ({"history_fingerprint": tl.NOT_RECORDED}, elig.V_UNATTRIBUTED_HISTORY),
        ({"dirty_runs": 1}, elig.V_DIRTY_RUN),
        ({"lane": reg.LANE_SECURITY_REVIEW}, elig.V_LANE_NOT_OFFERED),
        ({"lane": reg.LANE_GENERAL_REVIEW}, elig.V_LANE_NOT_OFFERED),
        ({"lane": reg.LANE_STRATEGY}, elig.V_LANE_NOT_OFFERED),
    ],
)
def test_each_condition_vetoes_on_its_own(override, expected):
    result = elig.evaluate(**_clean_inputs(**override))
    assert result.outcome == elig.NOT_ELIGIBLE
    assert expected in {v.code for v in result.vetoes}


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("non_pass_verdicts", elig.V_NON_PASS_VERDICTS),
        ("evidence_failures", elig.V_EVIDENCE_FAILURE),
        ("rollback_failed", elig.V_ROLLBACK_FAILURE),
        ("contained", elig.V_CONTAINMENT),
        ("dirty_executions", elig.V_DIRTY_RUN),
    ],
)
def test_a_single_bad_event_in_history_vetoes(field, expected):
    """One is enough. There is no ratio, so a long good record cannot dilute it."""
    result = elig.evaluate(**_clean_inputs(trust_facts=_spotless_facts(**{field: 1})))
    assert result.outcome == elig.NOT_ELIGIBLE
    assert expected in {v.code for v in result.vetoes}


def test_a_changed_model_fingerprint_vetoes():
    """History belongs to the build that earned it, not to whatever replaced it."""
    result = elig.evaluate(
        **_clean_inputs(
            model_fingerprint="sha256:" + "c" * 64,
            history_fingerprint="sha256:" + "a" * 64,
        )
    )
    assert elig.V_FINGERPRINT_CHANGED in {v.code for v in result.vetoes}


def test_history_just_below_the_minimum_vetoes():
    facts = _spotless_facts(verified_complete=elig.MIN_ATTRIBUTABLE_RUNS - 1)
    result = elig.evaluate(**_clean_inputs(trust_facts=facts))
    assert elig.V_INSUFFICIENT_HISTORY in {v.code for v in result.vetoes}


# ----------------------------------------------------- a good record buys nothing at all


def test_a_flawless_record_cannot_offset_a_protected_surface():
    """The whole reason there is no score: strengths must not trade against vetoes."""
    facts = _spotless_facts(verified_complete=10_000)
    result = elig.evaluate(
        **_clean_inputs(trust_facts=facts, risk_class=risk.RISK_PROTECTED_SECURITY)
    )
    assert result.outcome == elig.NOT_ELIGIBLE
    assert elig.V_PROTECTED_SURFACE in {v.code for v in result.vetoes}


def test_vetoes_accumulate_rather_than_cancel():
    result = elig.evaluate(
        **_clean_inputs(
            security_lane_state=reg.UNQUALIFIED,
            risk_class=risk.RISK_PROTECTED_SECURITY,
            evidence_verified=False,
        )
    )
    codes = {v.code for v in result.vetoes}
    assert {
        elig.V_SECURITY_UNQUALIFIED, elig.V_PROTECTED_SURFACE, elig.V_EVIDENCE_FAILURE
    } <= codes


def test_there_is_no_score_anywhere_in_the_result():
    mapping = elig.evaluate(**_clean_inputs()).to_mapping()
    for key, value in mapping.items():
        assert not isinstance(value, (int, float)) or isinstance(value, bool), key
    for banned in ("score", "level", "confidence", "rating", "percent"):
        assert banned not in mapping


def test_the_module_does_no_arithmetic_over_trust():
    """Structural: no averaging or weighting. Comparisons to a floor are not a score."""
    tree = ast.parse(Path(elig.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, (ast.Div, ast.Mult, ast.Pow)), "no weighting"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("sum", "mean", "average", "round")


# ----------------------------------------------------------- today's honest answer


def test_nothing_is_eligible_on_this_repository_today():
    """Two independent reasons, either sufficient — reported, not smoothed over.

    The local model scored 0/14 on refusing control-weakening changes, so the security-lane
    veto stands; and the risk gate finds no source-file task in the corpus low-risk enough to
    clear the protected-surface veto. This test states the current answer out loud so that
    changing it has to be deliberate.
    """
    result = elig.evaluate(
        lane=elig.LANE_ENGINEERING_CANDIDATE,
        security_lane_state=reg.UNQUALIFIED,
        lane_state=reg.QUALIFIED,
        risk_class=risk.RISK_REVIEW_REQUIRED,
        trust_facts=None,
        model_fingerprint="sha256:" + "a" * 64,
        history_fingerprint=tl.NOT_RECORDED,
        evidence_verified=False,
    )
    assert result.outcome == elig.NOT_ELIGIBLE
    assert elig.V_SECURITY_UNQUALIFIED in {v.code for v in result.vetoes}


# ------------------------------------------------------------------ the authority firewall


AUTHORIZATION_MODULES = (
    "autonomy.py",
    "policy.py",
    "approvals.py",
    "approvals_sqlite.py",
    "delegation.py",
    "orchestration.py",
)


@pytest.mark.parametrize("name", AUTHORIZATION_MODULES)
def test_no_authorization_module_imports_eligibility(name):
    source = (REPO_ROOT / "src" / "private_ai_gateway" / name).read_text(encoding="utf-8")
    assert "eligibility" not in source, f"{name} must not consume the advisory result"


def test_eligibility_reaches_no_authorization_primitive():
    """The firewall in the other direction: it reads facts, it calls no grant."""
    tree = ast.parse(Path(elig.__file__).read_text(encoding="utf-8"))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            called.add(node.attr)
        elif isinstance(node, ast.Name):
            called.add(node.id)
    forbidden = {
        "validate_for_execute", "mark_used", "create_run", "autonomy_ceiling_for",
        "find_principal", "approve", "grant",
    }
    assert not (called & forbidden), f"eligibility reaches {sorted(called & forbidden)}"


def test_the_console_offers_no_enable_button():
    page = (REPO_ROOT / "src" / "private_ai_gateway" / "static" / "console.html").read_text(
        encoding="utf-8"
    )
    assert "Earned Autonomy Readiness" in page
    assert "SHADOW / ADVISORY" in page
    readiness = page[page.index("Earned Autonomy Readiness"):]
    readiness = readiness[: readiness.index("</div>\n\n    <div class=\"card\">")]
    for banned in ("Enable", "Grant", "Activate autonomy", "Turn on"):
        assert banned not in readiness, f"the readiness card offers a {banned!r} control"


# ------------------------------------------------------------------------- the endpoint


@pytest.fixture
def client(monkeypatch):
    from private_ai_gateway import app as gw
    from private_ai_gateway.demo import install_demo_plane

    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER)
    install_demo_plane(gw)
    return gw.app.test_client()


def test_endpoint_reports_not_eligible_and_grants_nothing(client):
    r = client.post("/v1/autonomy-readiness", headers=OWNER, json={"objective": "tidy up"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["outcome"] == elig.NOT_ELIGIBLE
    assert body["grants"] == "nothing"
    assert body["consumed_by"] == "nothing"
    assert body["posture"] == "SHADOW / ADVISORY"
    assert body["vetoes"]


def test_endpoint_is_owner_only(client):
    from private_ai_gateway.demo import TOKENS

    r = client.post(
        "/v1/autonomy-readiness",
        headers={"Authorization": f"Bearer {TOKENS['hermes']}"},
        json={},
    )
    assert r.status_code == 403


def test_endpoint_refuses_the_security_lane_by_name(client):
    r = client.post(
        "/v1/autonomy-readiness",
        headers=OWNER,
        json={"lane": reg.LANE_SECURITY_REVIEW, "objective": "review this"},
    )
    codes = {v["code"] for v in r.get_json()["vetoes"]}
    assert elig.V_LANE_NOT_OFFERED in codes


def test_endpoint_carries_the_task_risk_it_used(client):
    r = client.post(
        "/v1/autonomy-readiness",
        headers=OWNER,
        json={"declared_files": ["verify.py"], "objective": "remove the signature check"},
    )
    body = r.get_json()
    assert body["task_risk"]["risk_class"] == risk.RISK_PROTECTED_SECURITY
    assert elig.V_PROTECTED_SURFACE in {v["code"] for v in body["vetoes"]}


def test_endpoint_does_not_change_any_authority(client):
    from private_ai_gateway import app as gw

    before = {p.name: gw.autonomy_ceiling_for(p) for p in gw.POLICY.principals()}
    client.post("/v1/autonomy-readiness", headers=OWNER, json={})
    assert {p.name: gw.autonomy_ceiling_for(p) for p in gw.POLICY.principals()} == before


def test_readiness_does_not_alter_the_governed_loop(client):
    """The loop behaves identically whether or not readiness was ever computed."""
    from private_ai_gateway.demo import TOKENS

    hermes = {"Authorization": f"Bearer {TOKENS['hermes']}"}
    plan = client.post(
        "/v1/orchestrate", headers=hermes,
        json={"objective": "Apply the reviewed fix and verify it", "phase": "plan"},
    ).get_json()
    approval = client.post(
        "/v1/approvals", headers=OWNER,
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve", "reason": "reviewed"},
    ).get_json()["approval_id"]
    out = client.post(
        "/v1/orchestrate", headers=hermes,
        json={"objective": "Apply the reviewed fix and verify it", "phase": "execute",
              "run_id": plan["run_id"], "approval_id": approval},
    ).get_json()
    assert out["applied"] is True


# --------------------------------------------- the repo's own agents must win the import


def test_repo_agents_directory_is_locatable():
    from private_ai_gateway import agents_path

    directory = agents_path.agents_dir()
    assert directory is not None
    assert (directory / "openclaw" / "evidence.py").exists()


def test_a_shadowing_openclaw_is_evicted(monkeypatch):
    """An unrelated installed package named ``openclaw`` must not win the import.

    This is not hypothetical: a same-named package in site-packages made
    ``/v1/trust-history`` return 500 in a real gateway process while the suite stayed green,
    because conftest happens to put ``agents/`` first and the endpoint's narrow ``except``
    did not cover ``ImportError``. Found by driving the live console, not by a test.
    """
    import sys
    import types

    from private_ai_gateway import agents_path

    impostor = types.ModuleType("openclaw")
    impostor.__file__ = "/somewhere/else/site-packages/openclaw/__init__.py"

    # Snapshot every already-imported openclaw module and put them back afterwards. The
    # helper evicts the whole namespace by design, and letting that leak would hand every
    # later test a second, non-identical copy of the verifier's classes.
    saved = {n: m for n, m in sys.modules.items() if n == "openclaw" or n.startswith("openclaw.")}
    sys.modules["openclaw"] = impostor
    try:
        agents_path.ensure_repo_agents_first()
        assert sys.modules.get("openclaw") is not impostor
        import openclaw  # noqa: F401  (re-imports from the repo)

        assert str(agents_path.agents_dir()) in (openclaw.__file__ or "")
    finally:
        for name in [n for n in sys.modules if n == "openclaw" or n.startswith("openclaw.")]:
            del sys.modules[name]
        sys.modules.update(saved)
    del monkeypatch


def test_trust_history_degrades_instead_of_erroring(client):
    """An underivable ledger is reported as no ledger — never a 500, never a clean record."""
    from private_ai_gateway import app as gw
    from private_ai_gateway import trust_ledger as tl

    def _explode(*a, **k):
        raise RuntimeError("something entirely unexpected")

    original = tl.derive_ledger
    tl.derive_ledger = _explode
    try:
        r = client.get("/v1/trust-history", headers=OWNER)
    finally:
        tl.derive_ledger = original
    assert r.status_code == 200
    body = r.get_json()
    assert body["ledger"] is None
    assert body["ledger_error"]
    assert body["runtime"] == []
    del gw
