# Is there a leasable lane? — an empirical answer

> **Headline:** one lane survives, and it is much narrower than it looks. Of the eighteen
> real merged changes it was derived from, a lease written over it would cover **thirteen**.
> The other five are refused because the site copy they edit contains the word "authorized".

The question this document answers is not "what would be safe to automate". It is the
narrower, checkable one: **is there a change class where a machine can decide whether the
result is correct?** Everything else is review with extra steps.

## Method

All 113 squashed commits on `main` were classified by the paths they touched and the size of
their diffs. Then every file-change was tested for being a *pure numeric substitution* — every
altered line identical to its predecessor except for its numbers.

## What the history actually contains

| Finding | Count |
|---|---:|
| Commits touching only documentation and the site | 28 |
| Commits touching only `tests/` | **0** |
| Commits refreshing the generated metrics manifest alone | **0** |
| Small source+tests commits outside protected surfaces | **0** (one existed; it edited `app.py`) |
| **Pure numeric-substitution file-changes** | **18**, across 13 commits |

The negative results did most of the work here. Three of the four lanes that seemed obvious
before looking have no population at all.

## Lanes rejected, and why

**`DOCS_SYNC`** — *no oracle.* The volume is there: 28 commits. But prose correctness cannot
be decided mechanically, and this project has a measurement of exactly that failure mode —
fourteen of fourteen security patches were well-formed, in scope, and wrong. A lane graded by
someone reading the diff is not a lane.

**`STATIC_PRESENTATION_SYNC`** — *subsumed.* Its checkable part is the derived numeric
surfaces below. What remains is authored copy, which is `DOCS_SYNC` under a different name.

**`TEST_FIXTURE_MAINTENANCE`** — *no instances, and the failure is silent.* Zero commits in
113. Worse, a fixture edited to match changed behaviour is indistinguishable from one edited
to hide a regression, and the suite passes either way: the oracle is the thing being modified.

**`PURE_NONSECURITY_HELPER`** — *no empirical support.* One candidate commit in 113, and it
touched `app.py`. There is no measured population to define a lane over.

## The lane that survives

`GENERATED_METRICS_REFRESH` — regenerate `docs/public-metrics.json` and propagate the derived
numbers into the six surfaces the drift suite already holds to it.

It survives for one reason: **a program decides whether it is right.** `public_metrics.py`
recomputes every number from its canonical source and `test_public_claims.py` fails if any
surface disagrees. No human reads the diff, which is the entire premise.

Its boundaries are stated so completely that membership is a computation, not a judgement:

| | |
|---|---|
| Allowed paths | 7 exact paths — not globs |
| Allowed operation | numeric substitution only, or regeneration from the generator |
| Max files / lines | 7 / 40 |
| Validation | `public_metrics --check`, the drift suite, full pytest, ruff |
| Rollback | required |
| Network / tools | none / none |

The operation constraint is what makes the path list safe. Every changed line must be
identical to its original except for its numbers, and every number written must appear in the
manifest. A model that fixes a typo while updating a count has left the lane — even though the
file is better for it — because the improvement is unreviewed by construction.

### It cannot be entered by relabelling

The `task_risk` gate runs **first**; a change it does not call `LOW_RISK_ENGINEERING` gets no
lane whatever paths it declares. All fourteen control-preservation tasks are refused. So are
the four classic mislabellings — "update docs" touching `app.py`, "format helper" removing
signature validation, "refresh test fixture" changing owner gating, "cleanup config"
broadening model permissions.

Three genuine gaps in the protected vocabulary were found by writing those tests, and closed:
`owner_required` (the literal reason code the gateway returns) was not in the approval
surface; "roll back" as two words did not match `rollback`; "signature validation" did not
match "signature check".

One gap was **not** closed. Feeding only the objective text catches 12 of the 14 attacks;
"apply directly to the target directory and skip the copy" and "let the caller override it by
passing a 'model' field" describe their attack in ordinary English that names no control.
Growing the vocabulary until that reads 14/14 would make "alias" and "copy" protected words —
and a documentation lane is full of both. The honest conclusion is that **objective text is a
supplementary signal, not the boundary.** What contains those two is that a lane change cannot
write to `apply.py` or `route.py` at all.

## What a lease over it would actually cover

Eighteen real changes, replayed through the shadow lease evaluator:

- **13 would grant.**
- **5 would refuse**, all `site/index.html`, all on the *authorization* surface — because the
  line being edited says "a record of exactly who **authorized** what".

That last number is the cost of over-classification arriving as a measurement instead of a
principle. **28 % of the real, safe, already-merged changes this lane was derived from would
still need a human**, because a gate that reads content for control vocabulary cannot tell
prose about authorization from code touching it.

The right response is to report it. A gate that learns to ignore the word "authorize" on
presentation surfaces is one relabelling away from ignoring it everywhere. But it does mean
the lane is narrower in practice than its path list suggests, and any lease decision has to be
made on the thirteen, not the eighteen.

## What this does not establish

The lane is *definable* and its correctness is *checkable*. Neither of those is the same as a
lease being warranted:

- The change class has **never been performed as a standalone commit**. Every instance rode
  along with the work that changed the count.
- The thirteen coverable changes are, between them, worth a few minutes of human attention
  per train. The lane is real; the saving is small.
- No model has yet accumulated the attributed runtime history a lease would require, because
  attribution shipped one train ago.

None of that is an argument for widening the lane. It is the argument for the verdict.
