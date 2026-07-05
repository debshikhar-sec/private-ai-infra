# Design Memo — Canonical Plan Hashing Spec

Design only. This document specifies the byte-exact canonical form and hash that binds an
approval to a plan. It is implementation-ready but contains no code. Illustrative digests
are shown as `sha256:<placeholder>` — they are format examples, **not** computed values.

Frozen baseline for this document: `canonicalization_version = 1`, `plan_schema_version = 1`.

## 1. Purpose

- **Why this spec exists:** the durable-approval design rests on one function —
  *canonical plan → hash*. If two parties can disagree about the bytes, an approval can be
  bound to one interpretation and an execution to another. This memo pins the field set,
  the byte-exact normalization, and the algorithm so `canonical_plan_hash` is reproducible
  by any implementation, at approve time and at apply time, identically.
- **Why hash binding prevents plan-swap:** the human approves a specific
  `canonical_plan_hash`. Before any mutation, `apply` reconstructs the plan it is about to
  run, canonicalizes it by these rules, and re-hashes. If any authority-bearing field
  differs (executor, skill, autonomy, scope, root, policy, delegation identity), the digest
  differs and the apply refuses. Approving plan A cannot authorize executing plan A′.

## 2. Hash Object Scope

The canonical plan object contains **exactly** these fields (all authority-bearing) and no
others:

| Field | Meaning / rule |
|---|---|
| `canonicalization_version` | integer; the version of *this normalization procedure*. Bound so a future rule change cannot silently re-interpret an old approval. |
| `plan_schema_version` | integer; the version of the *field set/semantics* below. |
| `objective_normalized` | the operator's goal after lossless whitespace/Unicode normalization (§4) — never paraphrased. |
| `principal_id` | principal that requested the action (e.g. `hermes`). |
| `executor` | the peer that will act (e.g. `opencode`). |
| `skill` | e.g. `code.apply`. |
| `task_class` | classified task type. |
| `requested_autonomy` | integer L-level the plan asked for. |
| `effective_autonomy` | integer L-level actually granted; policy-derived, ≤ ceiling. |
| `policy_version` | the governing policy's declared version. |
| `policy_hash` | hash of the active policy content (binds the decision context). |
| `resource_root_id` | the declared root / namespace that `target_resources` are relative to. **Authority-bearing:** the same relative path under a different root is a different approved action. |
| `target_resources` | explicit, normalized resource identifiers/paths the action may touch, relative to `resource_root_id` (§4). |
| `delegation` | present when delegation affects the action (see below); otherwise the key is present with value `null`. |
| `constraints` | policy/system-derived bounds from an allowlisted schema (§ note below). Object; keys sorted. |
| `environment` | the execution environment identifier (e.g. `demo`, `local`). |
| `data_sensitivity` | classification if known (e.g. `none`/`internal`/`restricted`); `null` if unknown. |

**`resource_root_id` (tightening #1):** `target_resources` are normalized *relative to a
declared root*. That root/namespace is itself authority-bearing — approving
`sample_handler.py` under `sandbox/reviewA` must not authorize the same relative path under
`sandbox/reviewB` or a repo root. `resource_root_id` is an opaque, verbatim-preserved
identifier bound into the hash.

**`constraints` (tightening #2):** `constraints` MUST be **policy/system-derived from an
allowlisted schema** — a fixed, known set of keys with typed values (e.g.
`no_commit: bool`, `sandbox_only: bool`, `max_files: int`). They MUST NOT be arbitrary,
model-generated text: model output can never introduce a constraint key or loosen one.
Adding a **new authority-bearing constraint** to the allowlisted schema requires a
`plan_schema_version` bump (so old approvals cannot be silently re-interpreted under a
wider constraint vocabulary).

**`delegation` sub-object** — included whenever the approved action is carried out via
delegation, so the approved executor/skill/scope is provably the one executed:

```
delegation = {
  delegation_id,        # id of the specific delegation authorizing this action
  parent_task_id,       # parent in the chain (null at root)
  delegation_chain,     # ordered list of {delegator, delegatee, skill, granted_level}
                        #   from root to the executing hop
  depth                 # integer depth of the executing hop
}
```

The `delegation_chain` binds the *path* of authority: an execute that runs under a
different delegation id, a different chain, a widened level, or a different delegatee
produces a different hash and is refused. If no delegation is involved, `delegation = null`
(and that null is part of the canonical bytes).

## 3. Explicitly Excluded Fields

Excluded because they are volatile and carry **no authority**; including them would cause
false refusals without adding security.

| Excluded | Why |
|---|---|
| `request_id` | per-hop, changes every call; the run is bound by `run_id` on the approval record, not inside the plan hash. |
| timestamps (`created_at`, `decided_at`, …) | wall-clock, non-deterministic; expiry is enforced by the approval record, not the hash. |
| tokens / secrets / credentials | must **never** enter a hash input (leak risk, and not part of the authorized action). |
| approver identity | recorded on the approval, not part of *what* is authorized; binding it would break re-approval and leak PII into the digest. |
| UI narration / `detail` / step text | human-readable prose that does not determine what executes. |
| non-authority display text (labels, phase names) | presentational; volatile across refactors. |

Rule: **a field belongs in the hash iff changing it changes what may happen.** Everything
else is excluded.

## 4. Normalization Rules

Applied to produce the canonical byte string:

- **Encoding:** UTF-8, no BOM.
- **Unicode:** every string normalized to **NFC**. (Composes with the ingress firewall's
  homoglyph/zero-width handling but is independent of it.)
- **Object keys:** sorted lexicographically by Unicode code point, recursively, at every
  nesting level.
- **Separators:** compact JSON — `","` and `":"` with **no** insignificant whitespace.
- **Arrays:**
  - `target_resources` and any list-valued `constraints` are treated as **sets**:
    de-duplicated, then sorted (post-normalization) — order must not affect authority.
  - `delegation_chain` is **order-significant** (it is a path) and is preserved as-is;
    only its element objects are key-sorted.
- **Null handling:** explicit. A field that is absent-but-defined is emitted as `null`
  (e.g. `"delegation":null`), not omitted. Omission vs `null` must never be ambiguous —
  the schema fixes the full key set.
- **Case:** identifiers case-insensitive by definition are lowercased **only where the
  domain says so**: `skill`, `task_class`, `environment`, `data_sensitivity` → lowercased.
  `principal_id`, `executor`, `resource_root_id`, `delegation_id`, `parent_task_id`,
  `policy_hash` → **preserved verbatim** (opaque ids). Autonomy levels are integers, not
  `"L3"` strings, in the canonical form.
- **Numbers:** integers only for the L-levels/versions/depth; emitted without leading zeros
  or signs; no floats introduced.
- **`target_resources` path normalization:** each entry is (a) made relative to
  `resource_root_id`, (b) `.`/`..` segments resolved, (c) separators normalized to `/`,
  (d) no trailing slash, (e) symlink-free logical form. A glob is preserved literally after
  separator normalization. Ambiguous or escaping paths (resolving outside the declared
  root) are a **canonicalization error → fail closed**, not a silent pass.
- **`objective_normalized`:** whitespace collapsed (runs of Unicode whitespace → single
  U+0020, trimmed ends), NFC applied, control characters stripped. **No paraphrasing,
  stemming, casing, or truncation** — the goal text is preserved losslessly except for
  whitespace/Unicode canonicalization.

## 5. Hash Algorithm

- Input: the canonical UTF-8 byte string produced by §2–§4.
- Function: **SHA-256**.
- Output format: lowercase hex, prefixed — `sha256:<64-hex>` — stored as
  `canonical_plan_hash`.
- Determinism requirement: given the same semantic plan and the same
  `canonicalization_version`, every implementation MUST produce identical bytes and
  therefore an identical digest.

## 6. Worked Example A — Valid Plan

Input plan object (pre-canonical, illustrative):

```
{ "plan_schema_version": 1, "canonicalization_version": 1,
  "objective_normalized": "review sample_handler.py for issues",
  "principal_id": "hermes", "executor": "opencode", "skill": "code.apply",
  "task_class": "code_apply", "requested_autonomy": 3, "effective_autonomy": 3,
  "policy_version": "demo-1", "policy_hash": "sha256:PP",
  "resource_root_id": "sandbox/run_20260705_011853",
  "target_resources": ["./sample_handler.py"],
  "delegation": { "delegation_id":"dg-0973d10825fc", "parent_task_id":null,
                  "delegation_chain":[{"delegator":"hermes","delegatee":"opencode","skill":"code.apply","granted_level":3}],
                  "depth":1 },
  "constraints": {"no_commit": true, "sandbox_only": true},
  "environment": "demo", "data_sensitivity": null }
```

Canonicalized bytes (keys sorted, compact, `target_resources` path-normalized relative to
`resource_root_id`, integers, `skill`/`task_class`/`environment` lowercased):

```
{"canonicalization_version":1,"constraints":{"no_commit":true,"sandbox_only":true},"data_sensitivity":null,"delegation":{"delegation_chain":[{"delegatee":"opencode","delegator":"hermes","granted_level":3,"skill":"code.apply"}],"delegation_id":"dg-0973d10825fc","depth":1,"parent_task_id":null},"effective_autonomy":3,"environment":"demo","executor":"opencode","objective_normalized":"review sample_handler.py for issues","plan_schema_version":1,"policy_hash":"sha256:PP","policy_version":"demo-1","principal_id":"hermes","requested_autonomy":3,"resource_root_id":"sandbox/run_20260705_011853","skill":"code.apply","target_resources":["sample_handler.py"],"task_class":"code_apply"}
```

→ `canonical_plan_hash = sha256:<A>` (placeholder). The approval record binds `sha256:<A>`
**and** the run's `run_id`.

## 7. Worked Example B — Plan-Swap Attempt

Approved: Example A (`skill=code.apply`, `effective_autonomy=3`, `target=sample_handler.py`
under `resource_root_id=sandbox/run_20260705_011853`). At execute, the reconstructed plan
differs in any of:

- `skill` → `deploy.prod`, **or**
- `effective_autonomy` → `5`, **or**
- `target_resources` → `["config/policy.toml"]`, **or**
- `resource_root_id` → a different root (same relative path, different namespace), **or**
- `delegation.delegation_chain[0].granted_level` → `5` / a different `delegatee`.

Each changes at least one authority-bearing field, so the canonical bytes change and the
digest becomes `sha256:<B> ≠ sha256:<A>`. `apply` recomputes, sees the mismatch, mutates
nothing, and refuses with **`apply_hash_mismatch`** (audited, fail closed).

## 8. Worked Example C — Benign Non-Authority Change

Between approve and execute, only excluded fields differ:

- a new `request_id` on the HTTP hop,
- different `created_at`/`decided_at` timestamps,
- different UI `detail`/narration text.

None of these are in the canonical object, so the canonical bytes are **byte-identical** and
the digest is still `sha256:<A>`. The approval remains valid and the apply proceeds (subject
to status/expiry/single-use). This is acceptable: nothing about *what may happen* changed.

## 9. Diff Hash Later

- **Why plan hash first (MVP):** the plan object exists at both approve time and apply time,
  so the plan hash is checkable end-to-end today. It binds *intent and scope* — enough to
  defeat plan-swap of executor/skill/autonomy/target/root.
- **When `diff_hash` is added:** once a **dry-run** produces the concrete diff *before* the
  human approves, the approval can additionally bind `diff_hash`, and `apply` re-derives it
  from the sandbox before/after manifests.
- **What `diff_hash` covers:** the exact byte-level changes to be written (per-file content
  hashes / unified-diff canonical form), closing the residual gap where the same plan could
  produce a materially different diff. Plan hash bounds *what may be touched and by whom*;
  diff hash bounds *the exact change*. Deferred, not built.

## 10. Tests Required (specified, not written)

- Same semantic plan (fields identical after normalization) → **stable** hash across
  runs/implementations.
- Hash **changes** when `executor` changes.
- Hash **changes** when `skill` changes.
- Hash **changes** when `requested_autonomy` or `effective_autonomy` changes.
- Hash **changes** when `target_resources` changes (including a path that normalizes
  differently).
- Hash **changes** when `resource_root_id` changes (same relative path, different root).
- Hash **changes** when `policy_hash` (or `policy_version`) changes.
- Hash **changes** when `delegation_id` / `delegation_chain` / `granted_level` /
  `delegatee` changes.
- Hash **does not change** when `request_id`, timestamps, or `detail` text change.
- Hash input **contains no** token/secret (assert by construction and by scanning canonical
  bytes).
- `canonicalization_version` mismatch between approval and apply → **fail closed**.
- `plan_schema_version` mismatch → **fail closed**.
- `objective_normalized` is lossless (only whitespace/Unicode canonicalized).
- Path escaping the declared root in `target_resources` → canonicalization error → fail
  closed.
- **Same `canonical_plan_hash` but different `run_id` → refuse.** The approval binds *both*
  `run_id` and `canonical_plan_hash`; a matching plan hash under a different run is not an
  authorization for that run.

## 11. Risks / Stop Conditions

- **Ambiguous canonicalization** (any input with more than one possible byte output) — must
  be eliminated; treat ambiguity as a spec bug.
- **Lossy objective normalization** (paraphrase/truncate/stem) — forbidden; would let
  semantically different goals collide.
- **Target path ambiguity** (unresolved `..`, symlinks, separator variance) — must fail
  closed, never silently normalize an escaping path to something inside root.
- **Root/namespace dropped or defaulted** — `resource_root_id` must be explicit; a missing
  or implicit root is a canonicalization error, not a default.
- **Schema/canonicalization version mismatch accepted** — must fail closed, never
  auto-migrate an approval across versions.
- **Hash excludes an authority-bearing field** — any new field that changes what may happen
  MUST be added to §2 (and bump `plan_schema_version`).
- **Hash includes a volatile field** — causes false refusals; volatile data must stay in §3.
- **Arbitrary/model-generated constraints** — `constraints` outside the allowlisted schema,
  or introduced by model output, must be rejected.
- **Model text influencing the canonical object** — the object is assembled from
  policy-derived, governed values, not from free model output.

## 12. Safe Next Action

This spec is design-only and changes nothing executable. Recommended next design-only
artifact: a **one-file implementation plan** binding this spec to the approval record and
`run_id` threading — the module boundary for a canonicalizer + in-process approval store,
the two call sites that must recompute-and-compare (`plan` issue, `apply` check), and the
audit-field additions — for review before any code.
