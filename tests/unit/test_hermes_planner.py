"""Unit tests for Hermes prompt composition and plan parsing (planner.py)."""

from hermes import planner

SAMPLE_PLAN = """\
PHASE: Phase 4 — copied-sandbox refresh
CURRENT READ: OpenCode review sandbox is implemented and isolation-verified.
SAFE NEXT ACTION: Refresh the copied sandbox from current docs, then re-run a review.
AUTONOMY LEVEL: L2
DO NOT DO YET: Do not enable OpenClaw or any L4+ automation.
COMMANDS OR SCRIPT: bash agents/opencode_sandbox/run_review.sh examples/review_target
VALIDATION: ISOLATION_RESULT=PASS and sandbox manifests unchanged.
EXPECTED RESULT: A review report with no out-of-sandbox writes.
IF IT FAILS: Stop and inspect the before/after manifests diff.
APPROVAL REQUIRED: none
NEXT OWNER ACTION: Review the report, then approve the next gate.
"""


def test_summarize_state_empty():
    out = planner.summarize_state({})
    assert "first planning cycle" in out.lower()


def test_summarize_state_renders_components_and_phases():
    state = {
        "current_gate": "g",
        "components": {"hermes": {"role": "planner", "status": "implemented", "autonomy_ceiling": "L1"}},
        "phases": [{"name": "p1", "status": "PASS"}],
        "restrictions": ["no git push"],
    }
    out = planner.summarize_state(state)
    assert "Current gate: g" in out
    assert "hermes" in out and "L1" in out
    assert "p1: PASS" in out
    assert "no git push" in out


def test_summarize_state_surfaces_assurance_verdict_and_failing_controls():
    state = {
        "assurance": {
            "verdict": "FAIL",
            "generated_at": "2026-06-29T00:00:00Z",
            "counts": {"pass": 5, "fail": 1, "inconclusive": 1},
            "failed_controls": [
                {"control_id": "AC-AUTONOMY-CEILING", "title": "Autonomy ceiling was never exceeded"}
            ],
        }
    }
    out = planner.summarize_state(state)
    assert "Last assurance verification (OpenClaw): FAIL" in out
    assert "remediate before any new work" in out
    assert "AC-AUTONOMY-CEILING" in out


def test_summarize_state_pass_assurance_lists_no_failing_controls():
    state = {"assurance": {"verdict": "PASS", "counts": {"pass": 7, "fail": 0, "inconclusive": 0}}}
    out = planner.summarize_state(state)
    assert "PASS" in out
    assert "Failing controls" not in out


def test_build_messages_structure():
    msgs = planner.build_messages("CONTRACT", {"current_gate": "g"}, "  do the thing  ")
    assert msgs[0]["role"] == "system" and "CONTRACT" in msgs[0]["content"]
    assert "Current gate: g" in msgs[0]["content"]
    assert msgs[1] == {"role": "user", "content": "do the thing"}


def test_parse_plan_extracts_all_sections():
    plan = planner.parse_plan(SAMPLE_PLAN)
    assert plan.get("PHASE").startswith("Phase 4")
    assert plan.autonomy_level == "L2"
    assert plan.safe_next_action.startswith("Refresh the copied sandbox")
    assert plan.next_owner_action.startswith("Review the report")


def test_parse_plan_approval_none_is_not_required():
    plan = planner.parse_plan(SAMPLE_PLAN)
    assert plan.requires_approval is False


def test_parse_plan_approval_present_is_required():
    text = SAMPLE_PLAN.replace(
        "APPROVAL REQUIRED: none",
        "APPROVAL REQUIRED: editing gateway/app.py — affects the request path",
    )
    plan = planner.parse_plan(text)
    assert plan.requires_approval is True


def test_parse_plan_missing_approval_section_defaults_to_required():
    # A plan that omits the approval section entirely is treated conservatively.
    text = "PHASE: x\nSAFE NEXT ACTION: y\n"
    plan = planner.parse_plan(text)
    assert plan.requires_approval is True


def test_parse_plan_ignores_preamble_before_first_label():
    text = "Sure, here is my plan:\n\n" + SAMPLE_PLAN
    plan = planner.parse_plan(text)
    assert plan.get("PHASE").startswith("Phase 4")


def test_parse_plan_default_autonomy_when_absent():
    plan = planner.parse_plan("PHASE: x\n")
    assert plan.autonomy_level == "L1"


def test_to_run_entry_kwargs_round_trips_into_run_entry():
    plan = planner.parse_plan(SAMPLE_PLAN)
    kwargs = plan.to_run_entry_kwargs("my objective")
    assert kwargs["goal"] == "my objective"
    assert kwargs["autonomy_level"] == "L2"
    assert kwargs["approval_required"] == "none"
    assert any("PHASE" in r for r in kwargs["results"])


def test_state_after_plan_is_non_mutating():
    state = {"current_gate": "g"}
    plan = planner.parse_plan(SAMPLE_PLAN)
    new = planner.state_after_plan(state, plan, "obj")
    assert state == {"current_gate": "g"}  # original untouched
    assert new["last_objective"] == "obj"
    assert new["last_autonomy_level"] == "L2"
