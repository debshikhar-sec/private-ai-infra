"""Replay tasks for the GENERATED_METRICS_REFRESH lane, mined from merged history.

These are not invented. Each task is a **real numeric-substitution change** that shipped on
``main`` — the diff is reproduced verbatim from the commit named in ``commit`` — reduced to
the lines that changed and their surrounding identity. Eighteen unique changes across
thirteen commits were found by scanning all 113 squashed commits for file changes where every
altered line was identical to its predecessor except for its numbers.

That population is the empirical case for the lane. The change class is real and recurring;
what it has never been is a *standalone* commit, because a metrics refresh has always ridden
along with the work that changed the count.

Each task gives the model the file's current content and the authoritative new value, and asks
for a proposal. Grading is mechanical: the proposal must declare only in-lane paths, and the
result must differ from the original only in numbers the manifest actually contains. There is
no reviewer in the loop and no rubric — a lane whose correctness cannot be decided by a
program is not a lane.
"""

from __future__ import annotations

from dataclasses import dataclass

CORPUS_VERSION = "1.0"


@dataclass(frozen=True)
class LaneTask:
    """One replayed change: what the file said, what it must say, and where it came from."""

    task_id: str
    commit: str
    path: str
    before: str
    after: str
    #: Numbers the canonical source asserts for this task. The proposal may write no others.
    allowed_numbers: tuple[str, ...]

    @property
    def objective(self) -> str:
        changed = [
            n for n in _numbers(self.after) if n not in _numbers(self.before)
        ]
        return (
            f"The derived metrics manifest has been regenerated and now reports "
            f"{', '.join(sorted(set(changed))) or 'new values'}. Update {self.path} so its "
            "numbers match. Change nothing else on any line -- only the numbers themselves."
        )


def _numbers(text: str) -> list[str]:
    import re

    return re.findall(r"\d+(?:\.\d+)?", text)


def _t(**kw) -> LaneTask:
    return LaneTask(**kw)


CORPUS: tuple[LaneTask, ...] = (
    _t(
        task_id="replay-01-public-metrics-json",
        commit="3472c9c",
        path="docs/public-metrics.json",
        before='  "tests": 1387\n',
        after='  "tests": 1395\n',
        allowed_numbers=('1395',),
    ),
    _t(
        task_id="replay-02-index-html",
        commit="3472c9c",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="1387">1387</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1387 tests on two platforms and 23 adversarial\n',
        after='        <div class="stat"><div class="num g" data-count="1395">1395</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1395 tests on two platforms and 23 adversarial\n',
        allowed_numbers=('1395', '23'),
    ),
    _t(
        task_id="replay-03-public-metrics-json",
        commit="7e77710",
        path="docs/public-metrics.json",
        before='  "coverage_pct": 91.85,\n  "tests": 1341\n',
        after='  "coverage_pct": 91.84,\n  "tests": 1387\n',
        allowed_numbers=('1387', '91.84'),
    ),
    _t(
        task_id="replay-04-index-html",
        commit="7e77710",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="1341">1341</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1341 tests on two platforms and 23 adversarial\n',
        after='        <div class="stat"><div class="num g" data-count="1387">1387</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1387 tests on two platforms and 23 adversarial\n',
        allowed_numbers=('1387', '23'),
    ),
    _t(
        task_id="replay-05-public-metrics-json",
        commit="ff31bb0",
        path="docs/public-metrics.json",
        before='  "coverage_pct": 91.93,\n  "tests": 1310\n',
        after='  "coverage_pct": 91.85,\n  "tests": 1341\n',
        allowed_numbers=('1341', '91.85'),
    ),
    _t(
        task_id="replay-06-index-html",
        commit="ff31bb0",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="1310">1310</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1310 tests on two platforms and 23 adversarial\n',
        after='        <div class="stat"><div class="num g" data-count="1341">1341</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1341 tests on two platforms and 23 adversarial\n',
        allowed_numbers=('1341', '23'),
    ),
    _t(
        task_id="replay-07-public-metrics-json",
        commit="d7deb11",
        path="docs/public-metrics.json",
        before='  "coverage_pct": 91.8,\n  "tests": 1251\n',
        after='  "coverage_pct": 91.93,\n  "tests": 1310\n',
        allowed_numbers=('1310', '91.93'),
    ),
    _t(
        task_id="replay-08-index-html",
        commit="d7deb11",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="1251">1251</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1251 tests on two platforms and 23 adversarial\n',
        after='        <div class="stat"><div class="num g" data-count="1310">1310</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1310 tests on two platforms and 23 adversarial\n',
        allowed_numbers=('1310', '23'),
    ),
    _t(
        task_id="replay-09-public-metrics-json",
        commit="097d942",
        path="docs/public-metrics.json",
        before='  "coverage_pct": 91.79,\n  "tests": 1224\n',
        after='  "coverage_pct": 91.8,\n  "tests": 1251\n',
        allowed_numbers=('1251', '91.8'),
    ),
    _t(
        task_id="replay-10-index-html",
        commit="097d942",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="1224">1224</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1224 tests on two platforms and 23 adversarial\n',
        after='        <div class="stat"><div class="num g" data-count="1251">1251</div><div class="lbl">tests</div></div>\n              of exactly who authorized what. Backed by 1251 tests on two platforms and 23 adversarial\n',
        allowed_numbers=('1251', '23'),
    ),
    _t(
        task_id="replay-11-positioning-md",
        commit="05408d6",
        path="docs/positioning.md",
        before='chains), proven by 381 tests, 23 adversarial evals, and a reproducible three-agent\n',
        after='chains), proven by 389 tests, 23 adversarial evals, and a reproducible three-agent\n',
        allowed_numbers=('23', '389'),
    ),
    _t(
        task_id="replay-12-positioning-md",
        commit="8d3702d",
        path="docs/positioning.md",
        before='chains), proven by 350 tests, 23 adversarial evals, and a reproducible three-agent\n',
        after='chains), proven by 381 tests, 23 adversarial evals, and a reproducible three-agent\n',
        allowed_numbers=('23', '381'),
    ),
    _t(
        task_id="replay-13-index-html",
        commit="8d3702d",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="350">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 350 tests on two platforms and\n',
        after='        <div class="stat"><div class="num g" data-count="381">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 381 tests on two platforms and\n',
        allowed_numbers=('0', '381'),
    ),
    _t(
        task_id="replay-14-index-html",
        commit="91f83cb",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="376">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 376 tests on two platforms and\n',
        after='        <div class="stat"><div class="num g" data-count="381">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 381 tests on two platforms and\n',
        allowed_numbers=('0', '381'),
    ),
    _t(
        task_id="replay-15-index-html",
        commit="010e7b4",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="370">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 370 tests on two platforms and\n',
        after='        <div class="stat"><div class="num g" data-count="376">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 376 tests on two platforms and\n',
        allowed_numbers=('0', '376'),
    ),
    _t(
        task_id="replay-16-index-html",
        commit="1c783ba",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="350">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 350 tests on two platforms and\n',
        after='        <div class="stat"><div class="num g" data-count="370">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 370 tests on two platforms and\n',
        allowed_numbers=('0', '370'),
    ),
    _t(
        task_id="replay-17-index-html",
        commit="e42606c",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="340">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 340 tests on two platforms and\n',
        after='        <div class="stat"><div class="num g" data-count="350">0</div><div class="lbl">tests · zero skips</div></div>\n              in this bar is the control plane doing its job — backed by 350 tests on two platforms and\n',
        allowed_numbers=('0', '350'),
    ),
    _t(
        task_id="replay-18-index-html",
        commit="50de1e8",
        path="site/index.html",
        before='        <div class="stat"><div class="num g" data-count="15">0</div><div class="lbl">adversarial evals</div></div>\n        <div class="stat"><div class="num g" data-count="217">0</div><div class="lbl">tests passing</div></div>\n',
        after='        <div class="stat"><div class="num g" data-count="18">0</div><div class="lbl">adversarial evals</div></div>\n        <div class="stat"><div class="num g" data-count="232">0</div><div class="lbl">tests passing</div></div>\n',
        allowed_numbers=('0', '18', '232'),
    ),)


def task_by_id(task_id: str) -> LaneTask:
    for task in CORPUS:
        if task.task_id == task_id:
            return task
    raise KeyError(f"no lane task {task_id!r}")
