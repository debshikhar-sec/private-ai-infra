#!/usr/bin/env python3
"""Derive every mechanically-checkable public claim from its canonical source.

Public numbers drifted for one boring reason: they were typed into prose by hand, and prose
has no test. This module gives each such number exactly one canonical source, derives it, and
writes a manifest (:data:`MANIFEST_PATH`) that the drift tests in
``tests/unit/test_public_claims.py`` hold the README, the site, and the docs against.

**What is and is not derived here.** Most facts are cheap and live: the eval-case list, the
assurance-control list, the CI matrix, the control table, the qualification artifact. Those
are re-derived on every test run, so a surface can never silently disagree with the code.
Two facts are *not* cheap — the test count and the coverage percentage — because obtaining
them means running the suite. Documentation must never do that, so they are refreshed by
``--write`` (which shells out to pytest deliberately) and thereafter read from the manifest.
The drift tests still hold every public surface to the manifest; they simply do not re-run
pytest inside pytest to prove the number.

**Named denominators.** Several of these numbers are the same integer with entirely different
meanings — there are 14 enforced runtime controls *and* 14 security-refusal qualification
tasks, and they have nothing to do with each other. Every key here is therefore explicit
about what it counts, and :data:`NAMESPACES` records the distinction so a future edit that
collapses them fails a test rather than a reader.

Usage::

    python scripts/public_metrics.py            # print the derived manifest
    python scripts/public_metrics.py --write    # refresh docs/public-metrics.json (runs pytest)
    python scripts/public_metrics.py --check    # exit nonzero if the manifest is stale
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess  # nosec B404 — fixed argv, no shell, used only under --write
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "public-metrics.json"
QUALIFICATION_ARTIFACT = (
    REPO_ROOT / "docs" / "qualification" / "local-engineering-qualification.json"
)
README_PATH = REPO_ROOT / "README.md"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# Metrics that are the same integer with different meanings. Conflating any two of these is
# the single most likely way for an honest surface to become a dishonest one.
NAMESPACES = (
    "enforced_controls",  # runtime controls the gateway enforces (README proof table)
    "adversarial_evals",  # attack cases in evals.cases.ALL_CASES
    "openclaw_controls_baseline",  # assurance checks OpenClaw always runs
    "qualification_tasks_total",  # tasks in the local-model qualification corpus
    "qualification_security_tasks",  # the security-refusal subset of that corpus
    "tests",  # pytest cases
    "ci_platforms",  # OS legs in the CI matrix
)


def _src_path() -> None:
    for rel in ("src", "agents"):
        path = str(REPO_ROOT / rel)
        if path not in sys.path:
            sys.path.insert(0, path)


def adversarial_eval_count() -> int:
    """Canonical source: ``evals.cases.ALL_CASES`` — the registered case list, not filenames."""
    _src_path()
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from evals.cases import ALL_CASES

    return len(ALL_CASES)


def openclaw_control_counts() -> dict:
    """Canonical source: ``openclaw.checks``.

    Two numbers, deliberately: ``ALL_CHECKS`` is what every assurance run executes, and the
    signed-evidence path adds gated controls. Publishing only the larger one would overstate
    what a default run proves.
    """
    _src_path()
    from openclaw import checks

    gated = [
        name
        for name in ("check_apply_evidence_chain", "check_evidence_graph_linkage")
        if hasattr(checks, name)
    ]
    return {
        "baseline": len(checks.ALL_CHECKS),
        "with_signed_evidence": len(checks.ALL_CHECKS) + len(gated),
    }


def enforced_control_count() -> int:
    """Canonical source: the README control table — one row per control, header excluded.

    The site's "enforced controls" stat is held to *this* number rather than keeping its own,
    so the headline figure cannot drift away from the table that substantiates it.
    """
    text = README_PATH.read_text(encoding="utf-8")
    marker = "| Control | Attack it repels | Enforced in | Proven by |"
    start = text.index(marker)
    rows = 0
    for line in text[start:].splitlines()[2:]:  # skip header + separator
        if not line.startswith("|"):
            break
        rows += 1
    return rows


def ci_platform_count() -> int:
    """Canonical source: the ``test`` job's matrix in the CI workflow."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    block = text[text.index("    strategy:") :]
    return len(re.findall(r"^\s+- os: \S+", block, flags=re.MULTILINE))


def qualification_facts() -> dict:
    """Canonical source: the published qualification artifact, never prose.

    Rates are carried as counts *and* as the rounded whole-percent the public surfaces show,
    so a surface is checked against a derived value rather than against a typed one.
    """
    art = json.loads(QUALIFICATION_ARTIFACT.read_text(encoding="utf-8"))
    s = art["summary"]
    total = s["total"]
    security_total = s["security_refusal_total"]
    engineering_total = total - security_total

    def pct(rate: float) -> int:
        return round(rate * 100)

    return {
        "corpus_version": art["corpus_version"],
        "corpus_digest": art["corpus_digest"],
        "tasks_total": total,
        "tasks_engineering": engineering_total,
        "tasks_security": security_total,
        "structural_valid_pct": pct(s["structural_valid_rate"]),
        "tests_pass_pct": pct(s["tests_pass_rate"]),
        "lint_pass_pct": pct(s["lint_pass_rate"]),
        "api_preserved_pct": pct(s["api_preserved_rate"]),
        "zero_edit_pct": pct(s["zero_edit_rate"]),
        "zero_edit_numerator": s["by_outcome"].get("accepted", 0),
        "security_refusal_correct": s["security_refusal_correct"],
        "security_refusal_total": security_total,
        "model_short_fingerprint": art["model"]["short_fingerprint"],
        "model_resolved": art["model"]["resolved_model"],
        "generated_at": art["generated_at"],
        "source_commit": art["source_commit"],
    }


def _mp4_duration_seconds(path: Path) -> float:
    """Read a duration straight out of the MP4 ``mvhd`` box.

    Deliberately dependency-free: a media claim that can only be checked when ffprobe happens
    to be installed is a claim CI will quietly stop checking.
    """
    data = path.read_bytes()
    idx = data.find(b"mvhd")
    if idx < 0:
        raise ValueError(f"{path.name}: no mvhd box")
    body = data[idx + 4 :]
    version = body[0]
    if version == 1:
        timescale = int.from_bytes(body[20:24], "big")
        duration = int.from_bytes(body[24:32], "big")
    else:
        timescale = int.from_bytes(body[12:16], "big")
        duration = int.from_bytes(body[16:20], "big")
    if not timescale:
        raise ValueError(f"{path.name}: zero timescale")
    return duration / timescale


def media_facts() -> dict:
    """Canonical source: the media files themselves."""
    site_assets = REPO_ROOT / "site" / "assets"
    videos = {}
    for path in sorted(site_assets.glob("*.mp4")):
        videos[path.name] = round(_mp4_duration_seconds(path))
    return {
        "tour_frames": len(list((site_assets / "tour").glob("*.webp"))),
        "video_seconds": videos,
    }


def _collected_test_count() -> int:
    """Count cases by collecting them, not by parsing a pass tally.

    The suite contains a test that asserts this very number, so deriving it from "N passed"
    is circular: while the manifest is stale that test fails, the tally drops by one, and the
    refreshed manifest is wrong by one in the other direction. Collection is independent of
    outcomes and therefore has a fixed point.
    """
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell
        # No extra ``-q``: pyproject already sets it, and a second one collapses the output to
        # per-file counts with no total line to read.
        [sys.executable, "-m", "pytest", "--collect-only", "--no-cov"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(r"^(\d+) tests collected", proc.stdout, flags=re.MULTILINE)
    if not match:
        match = re.search(r"(\d+) tests? collected", proc.stdout)
    if not match:
        sys.stderr.write(proc.stdout[-3000:])
        raise SystemExit("could not count collected tests; manifest not written")
    return int(match.group(1))


def _run_suite() -> dict:
    """Run the CI coverage command and parse the two facts only it can produce."""
    proc = subprocess.run(  # nosec B603 — fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pytest",
            "--cov=private_ai_gateway",
            "--cov=hermes",
            "--cov=openclaw",
            "--cov=opencode_sandbox",
            "--cov=interop",
            "--cov=evals",
            "--cov-report=term",
            # Not a gate here — it is what makes pytest-cov print the *exact* total, which is
            # the number CI reports. Without it only the rounded TOTAL row is available.
            "--cov-fail-under=85",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    out = proc.stdout
    cov = re.search(r"Total coverage: ([\d.]+)%", out) or re.search(
        r"^TOTAL\s+\d+\s+\d+\s+(\d+)%", out, flags=re.MULTILINE
    )
    if not cov:
        sys.stderr.write(out[-3000:])
        raise SystemExit("could not parse coverage; manifest not written")
    return {"tests": _collected_test_count(), "coverage_pct": float(cov.group(1))}


def build(include_suite: bool = False, previous: dict | None = None) -> dict:
    """Assemble the manifest. Suite facts are carried forward unless refreshed."""
    suite = (
        _run_suite()
        if include_suite
        else {
            "tests": (previous or {}).get("tests"),
            "coverage_pct": (previous or {}).get("coverage_pct"),
        }
    )
    return {
        "_comment": (
            "Generated by scripts/public_metrics.py. Every public numeric claim is held to "
            "this file by tests/unit/test_public_claims.py. Do not hand-edit."
        ),
        "namespaces": list(NAMESPACES),
        "tests": suite["tests"],
        "coverage_pct": suite["coverage_pct"],
        "coverage_display_pct": (
            round(suite["coverage_pct"]) if suite["coverage_pct"] is not None else None
        ),
        "adversarial_evals": adversarial_eval_count(),
        "enforced_controls": enforced_control_count(),
        "openclaw_controls": openclaw_control_counts(),
        "ci_platforms": ci_platform_count(),
        "qualification": qualification_facts(),
        "media": media_facts(),
    }


def load() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="refresh the manifest (runs pytest)")
    ap.add_argument("--check", action="store_true", help="fail if the manifest is stale")
    args = ap.parse_args(argv)

    previous = load() if MANIFEST_PATH.exists() else None
    manifest = build(include_suite=args.write, previous=previous)

    if args.write:
        MANIFEST_PATH.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"wrote {MANIFEST_PATH.relative_to(REPO_ROOT)}")
        return 0

    if args.check:
        if previous is None:
            print("manifest missing", file=sys.stderr)
            return 1
        drift = {
            k: (previous.get(k), manifest[k])
            for k in manifest
            if k not in ("_comment", "tests", "coverage_pct", "coverage_display_pct")
            and previous.get(k) != manifest[k]
        }
        if drift:
            for key, (was, now) in drift.items():
                print(f"STALE {key}: manifest={was!r} derived={now!r}", file=sys.stderr)
            return 1
        print("manifest is current")
        return 0

    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
