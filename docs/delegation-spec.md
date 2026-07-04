# GAD/1.1 — Governed Agent Delegation

**Status:** v1.1, normative for this gateway as of v0.17.0. (1.1 adds the optional
time-bound semantics of §3.1; the 1.0 core is unchanged.)
**Conformance suite:** `tests/conformance/test_delegation_spec.py` (runs against this
implementation in-process by default, or any other implementation over HTTP).

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Problem and scope

When agent A hands a task to agent B, A's *capability to ask* silently becomes B's
*authority to act*. GAD makes the hand-off itself an authorization decision. It
specifies the semantics of governed delegation — who may hand what to whom, under how
much authority, and who may speak for the outcome — independent of transport details.
This spec covers delegation between authenticated principals behind one enforcement
point. Cross-plane (federated) delegation is out of scope for 1.0.

## 2. Model

Every principal has, from policy (never from the request):

- **Skills** — the task types it may *hold or route* (`allowed_skills`).
- **An autonomy ceiling** — the maximum level it may *execute* at (L0–L6).

A **delegation** is a record `(id, parent_id, delegator, delegatee, skill,
granted_level, depth, status)`. `status` is `submitted` until its delegatee reports
exactly one terminal outcome (`completed` | `failed`). A delegation with a `parent_id`
is a **sub-delegation**; the transitive parent path is its **custody chain**.

The two axes are deliberately independent: skill possession is the right to route a
task type; the autonomy ceiling is the right to execute at a level. A low-autonomy
planner MAY route a high-level task to a peer whose *own policy* grants that level —
the delegatee's authority comes from policy, not from the delegator.

## 3. Invariants (normative)

An implementation MUST refuse the operation, with the stable error code shown, when:

| # | Invariant | Error code | HTTP |
|---|---|---|---|
| I1 | A principal MUST NOT delegate to itself. | `self_delegation` | 400 |
| I2 | The delegator MUST hold the skill it delegates (confused-deputy guard). | `skill_not_delegable` | 403 |
| I3 | The delegatee MUST hold the delegated skill. | `skill_not_allowed` | 403 |
| I4 | `granted_level` MUST NOT exceed the delegatee's own policy ceiling. | `autonomy_amplification` | 403 |
| I5 | The named delegatee MUST exist in policy. | `unknown_delegatee` | 404 |
| I6 | Only the *current holder* (delegatee) of a task may sub-delegate it. | `not_task_holder` | 403 |
| I7 | Only a `submitted` task may be sub-delegated. | `parent_not_active` | 409 |
| I8 | A sub-delegation's `granted_level` MUST NOT exceed the parent grant — chains only narrow. | `delegation_widening` | 403 |
| I9 | Chain depth MUST NOT exceed the policy maximum. | `delegation_too_deep` | 403 |
| I10 | Only the delegatee may report a task's outcome. | `not_task_holder` | 403 |
| I11 | An outcome MUST be reported at most once, and MUST be terminal. | `already_reported` / `invalid_status` | 409 / 400 |

Corollary of I4+I8: **no chain of delegations can ever amplify authority** — the
effective level at depth *n* is `min(policy ceilings…, grants…)` along the chain.

Additionally an implementation MUST:

- **I12 (audit):** record every refused *and* accepted operation in a decision audit,
  carrying the error code above; denials are evidence, not exhaust.
- **I13 (discovery from authority):** derive agent capability cards from enforced
  policy, not self-description, so peers match tasks against authority facts.

Implementations SHOULD bound `task` free-text length, and MAY expose the full ledger to
principals holding an explicit audit-read grant only.

### 3.1 Time bounds (optional, GAD/1.1)

An implementation MAY bound delegation lifetime (`expires_at`, from a policy TTL).
Unbounded grants are the *zombie-authority* hole: an agent that dies mid-task leaves a
live, sub-delegable grant behind forever. If time bounds are implemented:

| # | Invariant | Error code | HTTP |
|---|---|---|---|
| I14 | An expired task MUST NOT accept a result. | `task_expired` | 409 |
| I15 | An expired task MUST NOT be sub-delegated. | `parent_not_active` | 409 |
| I16 | A sub-delegation MUST NOT outlive its parent grant — time narrows like authority. | *(clamped, not refused)* | — |

Expiry MAY be enforced lazily (checked at every read) rather than by a background
reaper; what matters is that no operation ever succeeds against a lapsed grant.

## 4. Wire binding (HTTP/JSON, this implementation)

- `GET /a2a/agents` → `{agents: [card…], max_delegation_depth}` — cards derived from
  policy (I13).
- `POST /a2a/tasks` with `{skill, delegatee, autonomy_level?, parent_task?, task?}` →
  `202` with the delegation record, or the I1–I9 error envelope
  `{"error": {"code", "message", "type"}}`.
- `GET /a2a/tasks?role=delegatee|delegator&status=` → caller's inbox/outbox;
  `?all=true` requires the audit-read grant (else `audit_not_allowed`).
- `GET /a2a/tasks/<id>` → the record plus its custody chain (participants/auditors).
- `POST /a2a/tasks/<id>/result` with `{status: completed|failed, result?, verdict?}` →
  I10–I11 enforced.

Levels are integers 0–6 (see `docs/orchestration.md` for the ladder's meaning).

## 5. Conformance

The suite ships as ordinary pytest tests, one per MUST, tagged `GAD-I1` … `GAD-I13`
in the test names. Two ways to run it:

```bash
# 1. Against this gateway, in-process (default; runs in CI):
pytest tests/conformance/

# 2. Against any other implementation over HTTP:
GAD_BASE_URL=http://host:port \
GAD_TOKEN_CONDUCTOR=… GAD_TOKEN_WORKER=… GAD_TOKEN_CHECKER=… GAD_TOKEN_OUTSIDER=… \
pytest tests/conformance/
```

External targets MUST be configured with the **fixture cast** (any token values):

| Principal | `allowed_skills` | Ceiling | Audit read |
|---|---|---|---|
| `conductor` | `review` | L2 | yes |
| `worker` | `review`, `verify` | L3 | no |
| `checker` | `verify` | L2 | no |
| `outsider` | *(none)* | L1 | no |

Delegation `max_depth` MUST be set to 2 for the run (and any TTL left unset). A target
passes the GAD/1.0 core iff every test passes; the optional §3.1 time-bound behaviour
is covered by this implementation's unit suite rather than the portable core suite.

## 6. Versioning

Backward-incompatible changes to the invariants or error codes bump the major version.
New optional fields on the record or card are minor. This document is the change log
of record for the semantics; the implementation CHANGELOG tracks the code.
