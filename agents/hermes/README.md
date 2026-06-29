# Hermes — stateful planning component

Hermes is the **planning** component of the [orchestration control plane](../../docs/orchestration.md).
It decomposes an objective into a single safe next increment and routes execution
decisions to the governance plane. It is defined by that behaviour — not a persona or
job title.

> **Hermes plans; it does not execute.** Deterministic scripts execute and a human owner
> runs them. Because planning is not authority, Hermes is itself capped at autonomy
> **L1 (suggest)** by policy: it may propose, it may not drive execution.

## What makes it *stateful*

Between planning cycles Hermes persists what has been verified, so the next cycle
resumes from real state instead of replanning from scratch. Three memory files
(`store.py` manages them):

| File | Role |
|---|---|
| `PROJECT_STATE.json` | Canonical machine state: components, autonomy ceilings, phase status, standing restrictions. |
| `RUN_HISTORY.md` | Append-only log — one dated section per planning cycle. |
| `NEXT_ACTIONS.md` | The current gate: the one allowed next action, what is not allowed yet, what needs owner approval. |

Two control-plane properties are enforced in `store.py`: **atomic writes** (temp file +
`os.replace`, so a crash never leaves a half-written state) and a **pre-write backup**
(the prior memory is snapshotted under `backups/<timestamp>/` before every overwrite).

Live memory lives in `memory/` and is **gitignored**. The tracked `memory.example/` is a
seed — copy it to `memory/` to start.

## How a cycle runs

```
load contract + memory  ->  compose request  ->  gateway (as `hermes` principal, L1)
        ^                                                  |
        |                                                  v
   record to memory  <-  parse structured plan  <-  model reply
```

The gateway enforces Hermes' identity exactly like any other component: model
allowlist, token cap, rate limit, and the **L1 autonomy ceiling**. The planner gets no
special privilege — if it asks to operate above L1, the gateway denies it
(`403 autonomy_exceeded`) and the denial is audited.

## Run it

```bash
# Offline — print exactly what would be sent, no gateway call:
PYTHONPATH=agents python -m hermes.run \
  --objective "Plan the next safe increment" --show-prompt

# Live — delegate one planning cycle to the local gateway and record it:
export PRIVATE_AI_HERMES_TOKEN=...        # the `hermes` principal's API key
PYTHONPATH=agents python -m hermes.run --objective "Plan the next safe increment"
```

Run from the repo root with `agents/` on `PYTHONPATH` (the test suite adds it
automatically), and the local stack up (`make start`) for live cycles. Add a `hermes`
principal to
`config/policy.toml` (see `config/policy.example.toml`) so the gateway recognises the
token and applies the L1 ceiling.

## Closing the loop: verify before re-planning

Planning from *declared* state is not enough — Hermes should plan from **verified** state.
`hermes.verify` runs [OpenClaw](../openclaw) over the evidence the gateway emits and folds
the verdict back into memory (`MemoryStore.record_assurance`): `PROJECT_STATE.json` gains an
`assurance` block, `RUN_HISTORY.md` records the verification, and `NEXT_ACTIONS.md` becomes
*remediate the first failing control* on FAIL. The next cycle's planning prompt then shows the
last verdict and any failing controls — and by contract (rule 7) a FAIL gates new work until
it is fixed.

```bash
# Run assurance and record the verdict into Hermes memory (offline, no gateway needed):
PYTHONPATH=agents python -m hermes.verify \
  --memory-dir agents/hermes/memory \
  --audit logs/decisions.jsonl \
  --policy config/policy.toml \
  --opencode-report agents/opencode_sandbox/examples/isolated_review.report.txt
# exits non-zero on FAIL, so it can gate CI
```

This is the composition root where the orchestrator invokes the verifier; the two packages
stay decoupled, meeting only at a small JSON assurance record.

## The planner contract

[`HERMES_PLANNER_CONTRACT.md`](HERMES_PLANNER_CONTRACT.md) is the system prompt: plan
one phase at a time, declare the autonomy level, never claim un-evidenced file actions,
and emit an `APPROVAL REQUIRED` block before anything at L4+ or touching runtime/config/
git/network. The contract is data — `planner.py` parses the structured reply back into a
`Plan`, and the discipline is checked in unit tests, not merely asserted in prose.
