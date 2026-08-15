"""Public claims are part of the product, so they get tests like everything else.

Every number on the README, the site, and the current-state docs drifted at least once, for
one reason: it was typed by hand and nothing checked it again. These tests close that loop.
They hold the public surfaces to `scripts/public_metrics.py` — which derives each fact from
its one canonical source — and they refuse a small set of specific superseded strings that
have already appeared once and must not reappear.

Two deliberate limits keep this from becoming brittle:

  * **History is exempt.** `CHANGELOG.md` and the dated design records describe what was true
    when written. A test that forbids a superseded string *everywhere* would force us to
    falsify the historical record to keep the suite green, which is the opposite of the point.
    Only the surfaces in :data:`CURRENT_STATE_SURFACES` — the ones that claim to describe the
    system *now* — are policed.
  * **Rounding is a policy, not a drift.** Project-native surfaces carry the exact figure;
    external career surfaces carry a stable rounded threshold. Both are checked against the
    same derived value, so the two can differ only in the documented direction.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import public_metrics as pm  # noqa: E402

README = REPO_ROOT / "README.md"
SITE = REPO_ROOT / "site" / "index.html"
ROADMAP = REPO_ROOT / "docs" / "roadmap.md"
POSITIONING = REPO_ROOT / "docs" / "positioning.md"
PRODUCT_EVOLUTION = REPO_ROOT / "docs" / "product-evolution.md"
QUALIFICATION_DOC = REPO_ROOT / "docs" / "local-engineering-qualification.md"

#: Surfaces that claim to describe the system as it is *now*. History lives elsewhere.
CURRENT_STATE_SURFACES = (
    README,
    SITE,
    ROADMAP,
    POSITIONING,
    PRODUCT_EVOLUTION,
    QUALIFICATION_DOC,
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def manifest() -> dict:
    return pm.load()


# --------------------------------------------------------------------- the manifest itself


def test_manifest_matches_the_code_it_describes(manifest):
    """Every cheaply-derivable fact is re-derived here, so the manifest cannot go stale.

    The test count and coverage are excluded on purpose: obtaining them means running the
    suite, and running the suite inside the suite proves nothing worth the minutes.
    """
    derived = pm.build(include_suite=False, previous=manifest)
    for key in (
        "adversarial_evals",
        "enforced_controls",
        "ci_platforms",
        "openclaw_controls",
        "media",
    ):
        assert manifest[key] == derived[key], (
            f"{key} drifted from its canonical source; run scripts/public_metrics.py --write"
        )
    assert manifest["qualification"] == derived["qualification"]


def test_manifest_records_the_suite_facts(manifest):
    assert isinstance(manifest["tests"], int) and manifest["tests"] > 0
    assert 0 < manifest["coverage_pct"] <= 100
    assert manifest["coverage_display_pct"] == round(manifest["coverage_pct"])


def test_manifest_test_count_matches_this_session(manifest, request):
    """Adding a test without refreshing the manifest is itself drift — catch it here.

    Every other fact is re-derived cheaply; the test count is the one that would otherwise go
    stale silently, because the surfaces would still agree with a manifest nobody updated.
    pytest already knows how many cases it collected, so no second run is needed — but the
    number is only meaningful for a *whole-suite* session. A filtered or single-file run
    collects fewer by definition and is skipped rather than failed.
    """
    session = request.session
    config = session.config
    # A bare `pytest` run resolves to the configured testpaths, so those count as whole-suite;
    # anything else on the command line means a narrowed selection.
    whole_suite_args = {"", str(REPO_ROOT), *config.getini("testpaths")}
    filtered = bool(
        config.getoption("-k", default="")
        or config.getoption("-m", default="")
        or config.getoption("--last-failed", default=False)
        or [arg for arg in config.args if arg not in whole_suite_args]
    )
    if filtered or session.testsfailed:
        pytest.skip("not a whole-suite session; the collected count is not comparable")
    assert session.testscollected == manifest["tests"], (
        f"the suite has {session.testscollected} tests but the manifest says "
        f"{manifest['tests']}; run: python scripts/public_metrics.py --write"
    )


def test_namespaces_are_named_separately(manifest):
    """`14` is both an enforced-control count and a security-task count. Never one metric."""
    assert manifest["enforced_controls"] == 14
    assert manifest["qualification"]["tasks_security"] == 14
    assert "enforced_controls" in manifest["namespaces"]
    assert "qualification_security_tasks" in manifest["namespaces"]


# --------------------------------------------------------------------------- the site stats


def test_site_stat_block_matches_the_manifest(manifest):
    text = _text(SITE)
    stats = dict(
        re.findall(r'data-count="([\d]+)"[^>]*>[^<]*</div><div class="lbl">([^<]*)', text)
    )
    by_label = {label.strip(): int(count) for count, label in stats.items()}
    assert by_label.get("tests") == manifest["tests"]
    assert by_label.get("adversarial evals") == manifest["adversarial_evals"]
    assert by_label.get("enforced controls") == manifest["enforced_controls"]
    assert by_label.get("platforms, same suite") == manifest["ci_platforms"]


def test_site_coverage_stat_is_the_rounded_derived_value(manifest):
    text = _text(SITE)
    match = re.search(r'data-count="(\d+)" data-suffix="%"', text)
    assert match, "the site no longer carries a coverage stat"
    assert int(match.group(1)) == manifest["coverage_display_pct"]


def test_site_prose_test_count_matches_the_stat(manifest):
    """The hero stat and the body copy have disagreed before."""
    text = _text(SITE)
    assert f"{manifest['tests']} tests" in text


def test_no_superseded_test_count_survives_on_a_current_surface(manifest):
    """Every count this project has ever published, refused except the current one."""
    superseded = (568, 612, 681, 810, 831, 846, 869, 944, 981, 1013, 1050, 1081, 1129, 1165, 1193)
    for path in CURRENT_STATE_SURFACES:
        text = _text(path)
        for count in superseded:
            if count == manifest["tests"]:
                continue
            assert not re.search(rf"\b{count}\+? tests\b", text), (
                f"{path.name} still claims {count} tests; current is {manifest['tests']}"
            )


# ------------------------------------------------------------------- qualification numbers


def test_site_qualification_numbers_come_from_the_artifact(manifest):
    q = manifest["qualification"]
    text = _text(SITE)
    assert f"{q['tasks_total']}-task corpus" in text
    assert f"{q['structural_valid_pct']}% first-pass structural" in text
    assert f"{q['tests_pass_pct']}% tests pass" in text
    assert f"{q['api_preserved_pct']}% public API preserved" in text
    assert f"{q['zero_edit_pct']}%" in text
    assert (
        f"{q['security_refusal_correct']} of {q['security_refusal_total']}" in text
    ), "the site must state the security-refusal result with its denominator"


def test_qualification_doc_matches_the_artifact(manifest):
    q = manifest["qualification"]
    text = _text(QUALIFICATION_DOC)
    assert f"{q['security_refusal_correct']} of {q['security_refusal_total']}" in text or (
        f"{q['security_refusal_correct']} / {q['security_refusal_total']}" in text
    )
    assert f"({q['zero_edit_numerator']}/{q['tasks_total']})" in text


def test_superseded_qualification_claims_are_gone(manifest):
    """The v1 corpus reported 18 tasks, 72 % zero-edit, and 0/2 security. All superseded."""
    forbidden = (
        (r"18[- ]task", "the corpus is 30 tasks since v2.0"),
        (r"\b72\s*%", "72 % zero-edit was the v1 engineering-only denominator"),
        (r"\b0\s*/\s*2\b", "the security result is 0/14 since corpus v2.0"),
    )
    for path in CURRENT_STATE_SURFACES:
        text = _text(path)
        for pattern, why in forbidden:
            assert not re.search(pattern, text), f"{path.name}: {why}"


def test_zero_edit_denominator_is_labelled_wherever_it_appears(manifest):
    """`43 %` and `72 %` measured different populations. The denominator must travel with it.

    A bare percentage invites the reader to compare it with the old one, which is exactly the
    mistake that makes an honest downward revision look like a regression.
    """
    q = manifest["qualification"]
    for path in (SITE, QUALIFICATION_DOC, ROADMAP):
        text = _text(path)
        if f"{q['zero_edit_pct']}%" not in text and f"{q['zero_edit_pct']} %" not in text:
            continue
        window = text[max(0, text.find(f"{q['zero_edit_pct']}") - 400) :][:900]
        assert re.search(r"whole|all \d+|across the corpus|/\s*30|30[- ]task", window), (
            f"{path.name} shows the zero-edit rate without naming its denominator"
        )


# ------------------------------------------------------------------ shipped is not "future"


#: Each entry is a shipped capability plus a regex that would only match if a current-state
#: surface still filed it under future work. Verified against the code that implements it.
SHIPPED_NOT_FUTURE = (
    ("trust ledger", r"[Tt]rust ledger[^.]{0,120}\b(remain|are|is)\b[^.]{0,40}future"),
    ("durable storage", r"[Dd]urable storage[^.]{0,120}\b(remain|are|is)\b[^.]{0,40}future"),
    (
        "crash reconciliation",
        r"reconciliation[^.]{0,120}\b(remain|are|is)\b[^.]{0,40}future",
    ),
    (
        "append-first reservation",
        r"[Aa]ppend-first[^.]{0,200}\bare explicitly future\b",
    ),
)


@pytest.mark.parametrize(("capability", "pattern"), SHIPPED_NOT_FUTURE)
def test_shipped_capability_is_not_described_as_future(capability, pattern):
    for path in CURRENT_STATE_SURFACES:
        text = _text(path)
        match = re.search(pattern, text)
        assert match is None, (
            f"{path.name} still describes {capability!r} as future: {match.group(0)[:120]!r}"
        )


def test_shipped_capabilities_actually_exist():
    """The guard above is only honest if these modules are really here."""
    for rel in (
        "src/private_ai_gateway/trust_ledger.py",
        "src/private_ai_gateway/reconciliation.py",
        "src/private_ai_gateway/disposition.py",
        "src/private_ai_gateway/rollback.py",
        "src/private_ai_gateway/registry.py",
        "agents/opencode_sandbox/preimage.py",
        "agents/opencode_sandbox/rollback.py",
    ):
        assert (REPO_ROOT / rel).exists(), f"{rel} is claimed shipped but is missing"


# --------------------------------------------------------------------------- honest limits


#: Limitations that must survive every rewrite. Making the narrative more impressive by
#: quietly dropping one of these is the failure mode this test exists to catch.
PRESERVED_LIMITATIONS = (
    (README, "tamper-evident, not non-repudiation"),
    (README, "no apply, commit, merge, or deploy authority"),
    (SITE, "tamper-evident"),
    (ROADMAP, "sandbox-confined"),
)


@pytest.mark.parametrize(("path", "phrase"), PRESERVED_LIMITATIONS)
def test_honest_limitation_is_still_stated(path, phrase):
    assert phrase in _text(path), f"{path.name} no longer states: {phrase!r}"


def test_no_surface_claims_earned_autonomy_is_granted():
    """Nothing in this repo grants autonomy on measured trust. Saying so would be a lie."""
    forbidden = re.compile(
        r"earned autonomy is (now )?(live|enabled|granted)|autonomy is earned automatically",
        re.IGNORECASE,
    )
    for path in CURRENT_STATE_SURFACES:
        assert not forbidden.search(_text(path)), f"{path.name} overstates earned autonomy"


# ------------------------------------------------------------------------ external sourcing


def test_market_statistics_carry_a_source(manifest):
    """A percentage about the outside world needs a citation on the same page.

    Two figures on this page were previously attributed to a survey that does not contain
    them. Any bare external percentage is treated as unsupported until it is linked.
    """
    del manifest
    for path in (POSITIONING, PRODUCT_EVOLUTION):
        text = _text(path)
        assert "## Sources" in text, f"{path.name} has no Sources section"
        sources = text[text.index("## Sources") :]
        assert sources.count("http") >= 5, f"{path.name} lists too few primary sources"
        assert re.search(r"Last validated: \d{4}-\d{2}-\d{2}", text), (
            f"{path.name} has no validation date"
        )


def test_retracted_statistics_do_not_reappear():
    """These three were checked against their own cited primary sources and were not in them."""
    retracted = (
        (r"900\+? practitioners", "the cited CSA note is not a 900-practitioner survey"),
        (r"93\s*%[^.]{0,80}unscoped", "the cited source contains no 93 % unscoped-key figure"),
        (r"74\s*%[^.]{0,80}more access", "no source supports the 74 % over-access figure"),
        (r"99\s*%[^.]{0,80}deny rule", "no source supports the 99 % zero-deny-rule figure"),
    )
    for path in CURRENT_STATE_SURFACES:
        text = _text(path)
        # A retraction has to be able to name what it retracts, or the record of the
        # correction cannot be written down. Claims live above "## Sources"; the citation
        # apparatus below it — including retraction notes — is exempt.
        body = text.split("## Sources")[0]
        for pattern, why in retracted:
            assert not re.search(pattern, body, re.IGNORECASE), f"{path.name}: {why}"


# ------------------------------------------------------------------------------ media facts


def test_tour_frame_count_matches_the_claim():
    """The tour scrubs one real captured frame per step — no step without a file, and none spare.

    Frames are named by ``data-frame`` on each step and assembled by ``app.js``, so the check
    is against the step list rather than against literal ``src`` strings.
    """
    on_disk = {p.stem for p in (REPO_ROOT / "site" / "assets" / "tour").glob("*.webp")}
    referenced = set(re.findall(r'data-frame="([^"]+)"', _text(SITE)))
    assert referenced == on_disk, (
        f"tour frames differ: only on disk {sorted(on_disk - referenced)}, "
        f"only referenced {sorted(referenced - on_disk)}"
    )


def test_video_duration_claims_match_the_files(manifest):
    """"31-second video" is a claim about a file, so it is checked against the file."""
    text = _text(SITE)
    for name, seconds in manifest["media"]["video_seconds"].items():
        if name not in text:
            continue
        assert f"{seconds}-second" in text, (
            f"{name} is {seconds}s but the site does not say so"
        )


def test_every_referenced_site_asset_exists():
    text = _text(SITE)
    for rel in set(re.findall(r'(?:src|href)="(assets/[^"]+)"', text)):
        assert (REPO_ROOT / "site" / rel).exists(), f"site references missing asset {rel}"


def test_openclaw_control_count_is_not_conflated(manifest):
    """OpenClaw's assurance controls are a different set from the gateway's enforced controls."""
    counts = manifest["openclaw_controls"]
    assert counts["baseline"] != manifest["enforced_controls"]
    assert counts["with_signed_evidence"] >= counts["baseline"]


def test_qualification_artifact_carries_no_host_identifiers():
    """The published artifact is a public file. It must stay privacy-minimal."""
    raw = _text(pm.QUALIFICATION_ARTIFACT)
    for pattern in (r"/Users/", r"/home/", r"[0-9A-F]{8}-[0-9A-F]{4}-", r"\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b"):
        assert not re.search(pattern, raw), f"published artifact leaks {pattern!r}"
    art = json.loads(raw)
    assert set(art["host"]) <= {
        "architecture",
        "backends_available",
        "platform",
        "total_memory_gb",
    }
