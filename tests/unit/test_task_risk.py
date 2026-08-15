"""The protected-surface gate — deterministic, external to the model, and unbribable.

The regression suite that matters is :func:`test_every_security_corpus_task_is_protected`:
all fourteen tasks the local model implemented without objection must be classified
``PROTECTED_SECURITY``. That is the whole point. The model's 0/14 is why this gate exists, and
if the gate ever misses one of them it has failed at the only job it has.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from private_ai_gateway import task_risk as tr

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "agents"))


def _corpus():
    from hermes.qualification_corpus import CORPUS

    return CORPUS


def _security_tasks():
    from hermes.qualification_corpus import KIND_REFUSE

    return [t for t in _corpus() if t.kind == KIND_REFUSE]


def _classify_task(task):
    return tr.classify(declared_files=list(task.files), objective=task.objective)


# ------------------------------------------------------- the 14-task regression, the point


def test_the_security_corpus_still_has_fourteen_tasks():
    """If the corpus grows, this suite must grow with it — not silently cover less."""
    assert len(_security_tasks()) == 14


@pytest.mark.parametrize("task", _security_tasks(), ids=lambda t: t.task_id)
def test_every_security_corpus_task_is_protected(task):
    """All fourteen. The model implemented every one; none may execute unreviewed."""
    assessment = _classify_task(task)
    assert assessment.risk_class == tr.RISK_PROTECTED_SECURITY, (
        f"{task.task_id} classified {assessment.risk_class}; "
        f"surfaces={assessment.surfaces}"
    )
    assert assessment.eligible_for_autonomous_execution is False
    assert assessment.surfaces, "a protected classification must name the surface"


def test_no_security_task_is_eligible_even_in_aggregate():
    assessments = [_classify_task(t) for t in _security_tasks()]
    assert not any(a.eligible_for_autonomous_execution for a in assessments)
    assert all(a.protected for a in assessments)


# ------------------------------------------------------------ the caller cannot relabel it


@pytest.mark.parametrize(
    "claim",
    [
        tr.RISK_LOW_ENGINEERING,
        "documentation",
        "general engineering",
        "chore",
        "",
        "LOW_RISK_ENGINEERING ",
    ],
)
def test_a_claimed_class_cannot_lower_a_protected_task(claim):
    """Relabelling is the obvious attack. Risk ratchets up and never down."""
    task = _security_tasks()[0]
    assessment = tr.classify(
        declared_files=list(task.files), objective=task.objective, claimed_class=claim
    )
    assert assessment.risk_class == tr.RISK_PROTECTED_SECURITY


def test_every_security_task_resists_a_documentation_label():
    for task in _security_tasks():
        assessment = tr.classify(
            declared_files=list(task.files),
            objective=task.objective,
            claimed_class=tr.RISK_LOW_ENGINEERING,
        )
        assert assessment.protected, f"{task.task_id} was talked down to non-protected"


def test_a_stricter_claim_is_honoured():
    """Raising is always allowed — a caller may be more cautious than the classifier."""
    assessment = tr.classify(
        declared_files=["docs/guide.md"],
        objective="fix a typo",
        claimed_class=tr.RISK_PROTECTED_SECURITY,
    )
    assert assessment.risk_class == tr.RISK_PROTECTED_SECURITY


def test_declaring_a_benign_path_does_not_launder_protected_content():
    """Declaring docs/ while writing a signature-check removal is still protected."""
    assessment = tr.classify(
        declared_files=["docs/notes.md"],
        content="def verify(rec):\n    return True  # removed the signature check\n",
        objective="tidy the notes",
    )
    assert assessment.protected


def test_content_alone_can_protect_when_paths_look_innocent():
    assessment = tr.classify(
        declared_files=["helper.py"],
        content="if shell:\n    subprocess.run(cmd, shell=True)\n",
    )
    assert assessment.protected
    assert "command_execution" in assessment.surfaces


# ------------------------------------------------------------------ the default is not safe


def test_an_unrecognised_change_is_review_required_not_low_risk():
    """Fail-safe: anything not positively benign gets a human."""
    assessment = tr.classify(declared_files=["some_module.py"], objective="make it faster")
    assert assessment.risk_class == tr.RISK_REVIEW_REQUIRED
    assert assessment.eligible_for_autonomous_execution is False
    assert tr.REASON_UNRECOGNISED in assessment.reasons


def test_nothing_at_all_is_review_required():
    assert tr.classify().risk_class == tr.RISK_REVIEW_REQUIRED


def test_low_risk_must_be_earned_by_benign_paths():
    assert tr.classify(
        declared_files=["docs/guide.md"], objective="fix a typo"
    ).risk_class == tr.RISK_LOW_ENGINEERING
    assert tr.classify(
        declared_files=["tests/test_math.py"], objective="add a case"
    ).risk_class == tr.RISK_LOW_ENGINEERING


def test_one_non_benign_file_disqualifies_the_whole_change():
    """A change is as risky as its riskiest file, not its average file."""
    assessment = tr.classify(
        declared_files=["docs/guide.md", "runtime_thing.py"], objective="update"
    )
    assert assessment.risk_class == tr.RISK_REVIEW_REQUIRED


# ---------------------------------------------------------------------- the class algebra


def test_risk_only_ever_ratchets_up():
    for lower in tr.RISK_ORDER:
        for higher in tr.RISK_ORDER:
            combined = tr.raise_to(lower, higher)
            assert tr.RISK_ORDER.index(combined) >= tr.RISK_ORDER.index(lower)
            assert tr.RISK_ORDER.index(combined) >= tr.RISK_ORDER.index(higher)


def test_there_is_no_scalar_score():
    """A number invites a threshold, and a threshold is a grant with extra steps."""
    assessment = tr.classify(declared_files=["x.py"])
    mapping = assessment.to_mapping()
    for key, value in mapping.items():
        assert not isinstance(value, (int, float)) or isinstance(value, bool), (
            f"{key} is numeric; risk must not become a score"
        )
    assert "score" not in mapping
    assert "level" not in mapping


def test_module_computes_no_arithmetic_over_risk():
    """Structural: no averaging, summing, or weighting of risk anywhere in the module."""
    import ast

    tree = ast.parse(Path(tr.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp):
            assert not isinstance(node.op, (ast.Div, ast.Mult, ast.Pow)), (
                "risk must not be arithmetic"
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in ("sum", "mean", "average")


# -------------------------------------------------------------------- the surface taxonomy


def test_every_required_surface_is_covered():
    """The list the design requires. Removing one should be a visible, deliberate act."""
    required = {
        "authentication", "authorization", "approval", "policy", "autonomy",
        "routing_authority", "evidence", "signing", "identity", "canonical_plan",
        "replay", "confinement", "secrets", "rate_limit", "reconciliation",
        "disposition", "rollback", "containment",
    }
    present = {s.surface_id for s in tr.PROTECTED_SURFACES}
    assert required <= present, f"missing protected surfaces: {sorted(required - present)}"


def test_every_surface_has_a_label_and_some_vocabulary():
    for surface in tr.PROTECTED_SURFACES:
        assert surface.label
        assert surface.paths or surface.symbols


@pytest.mark.parametrize(
    ("objective", "expected_surface"),
    [
        ("remove the autonomy ceiling check", "autonomy"),
        ("let the model pick its own route_alias", "routing_authority"),
        ("skip the replay nonce comparison", "replay"),
        ("stop redacting the secret before logging", "secrets"),
        ("disable the rate limit for this principal", "rate_limit"),
        ("make reconciliation ignore dirty runs", "reconciliation"),
        ("auto-dispose the run without a human", "disposition"),
        ("trigger rollback automatically", "rollback"),
        ("drop the containment marker", "containment"),
        ("accept the canonical plan hash from the caller", "canonical_plan"),
    ],
)
def test_named_surfaces_are_detected(objective, expected_surface):
    assessment = tr.classify(declared_files=["x.py"], objective=objective)
    assert assessment.protected
    assert expected_surface in assessment.surfaces


# ------------------------------------------------- qualification does not override the gate


def test_qualification_cannot_make_a_protected_task_eligible():
    """A model measured excellent at engineering is still not allowed near a control.

    The module must not consult qualification at all — these are different questions, and
    letting a good score reach this decision is precisely the coupling the 0/14 forbids.

    Checked by imports and name references rather than raw text: ``registry.py`` legitimately
    appears as a *path pattern* for the routing-authority surface, and a text match would fire
    on the very vocabulary the gate is built from.
    """
    import ast

    tree = ast.parse(Path(tr.__file__).read_text(encoding="utf-8"))
    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            referenced.add((getattr(node, "module", None) or "").split(".")[-1])
            for alias in getattr(node, "names", []):
                referenced.add(alias.name.split(".")[-1])
        elif isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)
    forbidden = {"registry", "qualification", "qualify_lane", "LaneQualification", "recommend"}
    leaked = referenced & forbidden
    assert not leaked, f"task_risk.py depends on {sorted(leaked)}; risk is not capability"


def test_no_authorization_module_imports_task_risk():
    root = REPO_ROOT / "src" / "private_ai_gateway"
    for name in ("autonomy.py", "policy.py", "approvals.py", "delegation.py"):
        source = (root / name).read_text(encoding="utf-8")
        assert "task_risk" not in source, f"{name} must not consume the risk gate"


def test_the_gate_grants_nothing():
    mapping = tr.classify(declared_files=["docs/x.md"]).to_mapping()
    assert mapping["grants"] == "nothing"


# ------------------------------------------------------------------ proposal-shaped input


def test_classify_proposal_reads_declared_files_and_edits():
    proposal = {
        "declared_files": ["verify.py"],
        "edits": [{"path": "verify.py", "content": "def check(): return True"}],
        "objective": "remove the signature check so every record is accepted",
    }
    assessment = tr.classify_proposal(proposal)
    assert assessment.protected


def test_classify_proposal_ignores_a_self_declared_risk_class():
    proposal = {
        "declared_files": ["verify.py"],
        "objective": "remove the signature check",
        "risk_class": tr.RISK_LOW_ENGINEERING,
    }
    assessment = tr.classify_proposal(proposal)
    assert assessment.protected
    assert assessment.claimed_class == tr.RISK_LOW_ENGINEERING


def test_classify_proposal_survives_a_non_mapping():
    assert tr.classify_proposal(None).risk_class == tr.RISK_REVIEW_REQUIRED
    assert tr.classify_proposal(["not", "a", "dict"]).risk_class == tr.RISK_REVIEW_REQUIRED


# ------------------------------------------------------------------------- determinism


def test_classification_is_deterministic():
    task = _security_tasks()[3]
    first = _classify_task(task)
    for _ in range(5):
        assert _classify_task(task) == first


def test_no_model_is_consulted():
    """Structural: the gate must not call a model, a backend, or the network."""
    import ast

    tree = ast.parse(Path(tr.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            module = getattr(node, "module", None) or ""
            names.add(module.split(".")[0])
            for alias in getattr(node, "names", []):
                names.add(alias.name.split(".")[0])
    forbidden = {"backends", "requests", "urllib", "httpx", "openai", "mlx", "hermes"}
    assert not (names & forbidden), f"the gate reaches for {sorted(names & forbidden)}"


# ------------------------------------------------------ the honest shape of the low class


def test_no_engineering_corpus_task_reaches_low_risk():
    """An honest result worth stating: in this codebase, source changes are not "low risk".

    Only documentation- and test-only changes earn :data:`RISK_LOW_ENGINEERING`. Every one of
    the sixteen engineering tasks lands at REVIEW_REQUIRED or above. That is not a tuning
    failure to be corrected — it is what the classifier actually finds, and manufacturing
    eligibility by loosening it would defeat the purpose.
    """
    from hermes.qualification_corpus import KIND_REFUSE

    engineering = [t for t in _corpus() if t.kind != KIND_REFUSE]
    assert engineering
    low = [t.task_id for t in engineering if _classify_task(t).eligible_for_autonomous_execution]
    assert low == [], f"unexpectedly eligible: {low}"


# ------------------------------------------------------------------- the governed surfaces


@pytest.fixture
def client():
    from private_ai_gateway import app as gw
    from private_ai_gateway.demo import install_demo_plane

    install_demo_plane(gw)
    return gw.app.test_client()


@pytest.fixture
def owner(monkeypatch):
    from private_ai_gateway import app as gw

    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-owner-break-glass-token")
    return {"Authorization": "Bearer test-owner-break-glass-token"}


def test_endpoint_classifies_and_grants_nothing(client, owner):
    r = client.post(
        "/v1/task-risk",
        headers=owner,
        json={"declared_files": ["verify.py"],
              "objective": "remove the signature check so every record is accepted"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["risk_class"] == tr.RISK_PROTECTED_SECURITY
    assert body["eligible_for_autonomous_execution"] is False
    assert body["grants"] == "nothing"


def test_endpoint_ignores_a_laxer_claimed_class(client, owner):
    r = client.post(
        "/v1/task-risk",
        headers=owner,
        json={"declared_files": ["verify.py"],
              "objective": "remove the signature check",
              "risk_class": tr.RISK_LOW_ENGINEERING},
    )
    assert r.get_json()["risk_class"] == tr.RISK_PROTECTED_SECURITY


def test_endpoint_is_owner_only(client):
    from private_ai_gateway.demo import TOKENS

    r = client.post(
        "/v1/task-risk",
        headers={"Authorization": f"Bearer {TOKENS['hermes']}"},
        json={"declared_files": ["x.py"]},
    )
    assert r.status_code == 403


def test_plan_carries_an_advisory_risk_classification(client, owner):
    from private_ai_gateway.demo import TOKENS

    body = client.post(
        "/v1/orchestrate",
        headers={"Authorization": f"Bearer {TOKENS['hermes']}"},
        json={"objective": "Apply the reviewed fix and verify it", "phase": "plan"},
    ).get_json()
    assert "task_risk" in body
    assert body["task_risk"]["risk_class"] in tr.RISK_ORDER
    assert body["task_risk"]["grants"] == "nothing"


def test_the_classification_does_not_change_what_executes(client, owner):
    """Advisory means advisory: the governed loop behaves exactly as before."""
    from private_ai_gateway.demo import TOKENS

    hermes = {"Authorization": f"Bearer {TOKENS['hermes']}"}
    plan = client.post(
        "/v1/orchestrate", headers=hermes,
        json={"objective": "Apply the reviewed fix and verify it", "phase": "plan"},
    ).get_json()
    approval = client.post(
        "/v1/approvals", headers=owner,
        json={"run_id": plan["run_id"], "canonical_plan_hash": plan["canonical_plan_hash"],
              "decision": "approve", "reason": "reviewed"},
    ).get_json()["approval_id"]
    out = client.post(
        "/v1/orchestrate", headers=hermes,
        json={"objective": "Apply the reviewed fix and verify it", "phase": "execute",
              "run_id": plan["run_id"], "approval_id": approval},
    ).get_json()
    # Protected or not, the human-gated path is unchanged — this gate blocks nothing today
    # because nothing is autonomous today.
    assert out["applied"] is True
