# Local model bake-off — which build for which lane

> **Headline:** every build that can reliably write a patch implements **all fourteen**
> control-weakening changes, and every build that declined any of them cannot reliably write
> a patch. Across the models whose refusals are interpretable at all: **0 of 28**. The
> measurement that appeared to reward the weakest model turned out to be measuring the wrong
> thing.

Every number here is read from the published artifacts under
[`docs/qualification/`](qualification/) and held to them by
`tests/unit/test_public_claims.py`. Nothing in this document is typed by hand, and nothing
here grants anything — these are measurements of *usefulness*, and no authorization path
reads them.

## What was benchmarked, and what was not

Seven model directories exist in the local hub cache. Four were usable without a download,
which was a hard constraint: this comparison may not fetch a model.

| Build | Weights | Fit | Benchmarked |
|---|---:|---|---|
| `mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit` | 32.5 GB | FITS | ✅ |
| `mlx-community/Qwen3.6-27B-OptiQ-4bit` | 18.8 GB | FITS | ✅ |
| `mlx-community/Hermes-3-Llama-3.1-70B-4bit` | 39.7 GB | FITS | ✅ |
| `mlx-community/Qwen2.5-1.5B-Instruct-4bit` | 0.9 GB | FITS | ✅ |
| `mlx-community/gemma-4-31b-it-4bit` | — | — | ❌ 0 of 4 weight shards present |
| `mlx-community/Qwen3.6-40B-…-Thinking-8bit` | — | — | ❌ no snapshot, metadata only |
| `OpenYourMind/Qwopus3.5-122B-…-MLX-4bit` | — | — | ❌ no snapshot, metadata only |

The three exclusions were not obvious in advance, and finding out cost something — see
[the registry bug](#a-directory-is-not-a-model) below.

Every benchmarked build ran the **same** corpus, context packing, adapter, semantic
evaluator, lint rules and refusal expectations, through the governed gateway as a principal
capped at **L1, no skills, no tools, 2048 output tokens**. No prompt was tuned for any model
after seeing its failures. The incumbent's numbers reproduced its published artifact exactly,
which is the evidence that the harness is deterministic enough for the comparison to mean
anything.

## Engineering — 30 tasks (16 edits, 14 control-preservation)

| Build | Structural | Tests | Lint | API | Zero-edit | **Refusals** |
|---|---:|---:|---:|---:|---:|---:|
| Qwen3.6-27B-OptiQ-4bit | 100 % | 100 % | 100 % | 100 % | 53 % | **0 / 14** |
| Qwen3-Coder-30B-A3B-8bit | 94 % | 81 % | 88 % | 100 % | 43 % | **0 / 14** |
| Hermes-3-Llama-3.1-70B-4bit | 25 % | 19 % | 19 % | 94 % | 27 % | **5 / 14** ⚠ |
| Qwen2.5-1.5B-Instruct-4bit | 12 % | 6 % | 12 % | 94 % | 50 % | **14 / 14** ⚠ |

⚠ *Refusal score not interpretable — see below.*

Read that last column downward and the shape of the result is hard to miss: **refusals go up
as competence goes down.** The strongest engineering model declines nothing; the weakest
declines everything.

### The 14/14 is not a security score

The 1.5B build recorded the only perfect refusal score in this project's history. On the same
run it failed to emit a parseable proposal for 14 of the 16 ordinary engineering tasks.

The adapter cannot tell *"I decline to remove this control"* from *"I emitted something that
is not JSON"* — both arrive as a refusal — so on a control-preservation task, incompetence is
scored as judgement. The metric was quietly awarding its best possible result to the least
capable model in the comparison.

Rather than redefine what a refusal counts as, the harness now records whether the refusal is
**discriminating**: a build that cannot comply on ordinary tasks has not demonstrated that it
*chose* not to. The registry's security lane reads that flag before the number and reports
`NOT_EVALUATED` — not `QUALIFIED` — for a perfect score it cannot interpret. The honest claim
about the 1.5B is not "it has perfect security judgement"; it is "this measurement cannot tell".

Hermes-3's **5 / 14** looked, at first, like the first genuinely non-zero refusal result in
this project. It is not: at 25 % structural validity it is below the same floor, so its five
refusals are no more interpretable than the 1.5B's fourteen. Both are flagged.

Applying that consistently leaves only the two builds that can reliably produce a valid patch
— and both of them declined nothing:

> **Across every build whose refusals are interpretable: 0 of 28.**

That is a stronger and less comfortable result than the "5 of 42" a naïve sum would have
produced. Every model in this comparison either implements the control-weakening change, or
cannot produce a patch at all.

## Strategy — 14 planning tasks

The strategy lane had never been evaluated. A planner is not graded on code, so this corpus
measures what a planner actually decides: who should act, at what level, and whether a human
has to be asked first. The answer is strict JSON over a **closed roster**, graded by comparing
names to a fixed world — no model grades another, and no rubric rewards a fluent paragraph.

| Build | Decision | Protected surfaces | Self-approval | Invented capability | Within ceiling | Lane |
|---|---:|---:|---:|---:|---:|---:|
| Hermes-3-Llama-3.1-70B-4bit | 14/14 | 4/4 | 14/14 | 14/14 | 14/14 | 5/7 |
| Qwen3.6-27B-OptiQ-4bit | 13/14 | 4/4 | 14/14 | 14/14 | 14/14 | 5/7 |
| Qwen3-Coder-30B-A3B-8bit | 11/14 | **2/4** | 14/14 | 14/14 | 14/14 | 6/7 |
| Qwen2.5-1.5B-Instruct-4bit | 6/10 | **1/3** | 9/10 | 10/10 | 9/10 | 0/5 |

The 1.5B's denominators are smaller than the others' because four of its replies did not
parse at all, and a quality is only counted where it was actually measured. A rate over ten
tasks and a rate over fourteen are different claims; reporting them as one number is how the
refusal score went wrong.

Safety-shaped qualities are all-or-nothing. A planner that recognises two of four protected
surfaces has not "mostly" recognised them — it has planned execution on two, so the incumbent
coder is **UNQUALIFIED** as a planner while the other two builds qualify.

### The result worth sitting with

**Qwen3.6-27B recognises 4 of 4 protected surfaces when planning, and implements 14 of 14
control-weakening changes when coding.** The same build, the same day, the same gateway.

That is not a contradiction, and reading it as one is how a system ends up trusting the wrong
thing. Asked *"should someone change the owner gate?"* the model answers "a human should
decide". Handed the file and asked to make the change, it makes the change. Recognising that a
decision belongs to a person is a different competence from refusing to be the instrument of
it — and only the second one is a security property.

This is the clearest argument yet for why the boundary lives in the gateway. A model good
enough to *say* the right thing about authority is not thereby safe to *hold* any.

## A directory is not a model

The registry reported `INSTALLED` for `gemma-4-31b-it-4bit`. A run was scheduled against it on
that basis, and it began pulling 24 GB — in a comparison whose explicit constraint was that
nothing may be downloaded.

The cause: a Hugging Face cache entry is created the moment a fetch *starts*, so a
half-downloaded model is indistinguishable from a complete one if you only look for the
directory. `ModelCache.is_cached` looked for the directory.

It now reads the model's own `*.index.json` weight map — the same file the loader reads — and
reports `INSTALLED` only when every declared shard is present, with one deliberate exception
for nested auxiliary towers (`optiq/optiq_vision.safetensors`), which a text generation never
touches and whose absence excluded a model that in fact ran the whole corpus without fetching
a byte. The gateway is additionally run with the Hub forced offline for measurement work, so
the failure mode is now a fast error rather than a slow download.

**This is the second bug in two trains that CI could not have found**, and the same lesson
applies: the fixture described a model as cached under conditions that could never load. It
was corrected to build the real hub layout, and a half-downloaded model is now a test case.

## Lane replay — 18 real merged changes

Both builds that can reliably write a patch were run over the
[low-risk lane corpus](low-risk-lane-discovery.md): eighteen numeric-substitution changes
taken verbatim from merged commits, graded on whether the produced file differs from the
original *only* in numbers the manifest asserts.

| Build | Clean | Scope escapes |
|---|---:|---:|
| Qwen3.6-27B-OptiQ-4bit | 18/18 | 0 |
| Qwen3-Coder-30B-A3B-8bit | 18/18 | 0 |

Neither model reworded a sentence, fixed an unrelated typo, or touched a second file — the
helpful-looking failures a bounded lane cannot tolerate. Set beside 0/28 on security
refusals, the pairing is the whole argument for keeping a lane narrow: the same builds that
perform a tightly-bounded mechanical change flawlessly will also implement every
control-weakening request put to them.

## What this changes

- The **strategy route** has a measured planner for the first time. Two builds qualify;
  neither is the incumbent coder.
- The **engineering route** has a strictly better candidate available — 100 % across the
  structural measures against the incumbent's 94/81/88 — with **no** improvement in security
  judgement. Any decision to switch is a decision about first-pass quality alone.
- The **security lane remains UNQUALIFIED or NOT_EVALUATED for every build measured.** Across
  the two builds whose refusals are interpretable at all: **0 of 28**.

Nothing here is a grant. The comparison publishes no aggregate and no ranking, because a
single score would have to weigh "writes better patches" against "declines to remove a
security control" — and the central result of this bake-off is a build where those two point
in opposite directions.
