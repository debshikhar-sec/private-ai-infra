# The earned-autonomy lease — design, and why none exists yet

> **Status: prospective.** No lease is issued, held, stored, or consumed. This document and
> `src/private_ai_gateway/lease.py` describe the object a first bounded lease *would* be, and
> the executable tests in `tests/unit/test_lease_shadow.py` hold that description to itself.
> The verdict of the train that produced it was **not to build one**.

## What a lease is, and what it is not

A lease is **not** a permission level, a role, or a trust score. It is a **binding**: one
principal, one exact model build, one lane, one policy revision, one path set, one expiry.

Change any bound value and it is a different lease — a different digest, refused by the old
one. That is the entire mechanism by which a bounded grant stays bounded. A lease for model A
does not apply to model B. A lease for `GENERATED_METRICS_REFRESH` does not apply to source
engineering, however similar the diff looks.

| Bound | Why it is part of the identity |
|---|---|
| principal | authority belongs to someone, not to the system |
| model fingerprint | a re-pointed alias is a different model with a different reputation |
| lane | scope is the lane's, never the caller's |
| policy hash + revision | the rules the lease was written against |
| allowed paths | enumerable today, not a glob promising files that do not exist |
| tools / network | both empty; there is no parameter to request either |
| max files / lines | a bound that a "small" change cannot argue with |
| expiry | ≤ 1 hour; an unattended grant nobody re-decided is the failure mode |
| evidence required | which signed records must exist for the run to count |
| rollback required | reversibility as a precondition, not a hope |
| qualification artifact | the exact measurement, not "it was measured once" |
| minimum attributed runs | history that is attributable to *this build* |

## How it relates to readiness

Two different questions, deliberately not merged:

- **Readiness** (`eligibility.py`) — *is this build, in general, in a state where a lease could
  be considered?* A standing question about qualification and history.
- **The lease** (`lease.py`) — *would this specific change, right now, fall inside that
  specific lease?* A per-change question about scope.

A build can be perfectly ready and still have every change refused, and a change can be
perfectly in-scope for a build that has no standing at all. One badge covering both would be
worse than either.

## Refusal is not weighted

Every condition is a veto, and `would_grant` collects **all** of them rather than returning at
the first. That is not thoroughness for its own sake: a caller who fixes one refusal and
retries would otherwise discover the boundary by search. It is also the honest answer to "how
far is this from being allowed" — usually further than the first veto suggests.

There is no score. A ten-thousand-run flawless history cannot offset a protected surface, in
exactly the way 100 % structural validity does not offset 0/14 on security refusals.

## Lifecycle

```
PROPOSED ──owner──▶ OWNER_GRANTED ──▶ ACTIVE ──▶ REVOKED / EXPIRED
```

- A model may **propose** — that is a request, not an authority — and nothing it does moves
  the lease forward from there.
- `PROPOSED → OWNER_GRANTED` and `ACTIVE → REVOKED` are **owner-only**.
- `OWNER_GRANTED → ACTIVE` is mechanical; the decision was the grant.
- `REVOKED` and `EXPIRED` are terminal, with no edges out.
- **There is no renewal.** A lease cannot return to an earlier state, and extending a running
  one is not a transition that exists. A renewal is a new lease, proposed from scratch, which
  means a human decides again.

This is not an approval TTL. Approvals are single-use and hash-bound to one plan; a lease is a
standing, revocable, time-boxed scope. They are different authority objects and must not share
machinery — an expiry bolted onto the approval store would quietly make approvals leasable.

## Crash semantics, decided before the code

Written first, deliberately. The 7B.1 reservation ordering was designed this way and it is why
a crash there leaves a classifiable state instead of a silent one.

| Crash point | Resolves to | Why |
|---|---|---|
| issued, record not durable | `PROPOSED` | an unrecorded grant is not a grant |
| durable, not acknowledged | `OWNER_GRANTED` | the authority exists; only activation is unknown, and activation is the cheap half to repeat |
| active at crash | `EXPIRED` | a lease surviving a restart is an unattended grant nobody re-decided |
| unreadable expiry | `EXPIRED` | an expiry that cannot be read is not a bound |

Every case fails towards *less* authority.

## The firewall

`lease.py` is imported by no authorization module — asserted structurally, by walking the AST
of `approvals.py`, `approvals_sqlite.py`, `policy.py`, `autonomy.py`, `delegation.py`,
`tools.py`, `ingress.py` and `orchestration.py`. A second test parses `lease.py` itself and
fails if it ever defines `issue`, `grant`, `activate`, `revoke`, a store, or any filesystem
write. The module can describe a lease; it has no way to create one.

It also does not carry its own opinion about what is protected: it calls `task_risk.classify`
and does not name a single protected surface of its own.

## Why none was built

The shadow simulation ran the real corpus through the real evaluator. The blockers are not
design gaps:

1. **No attributed history exists.** A lease requires 20 verified completions attributable to
   one build; attribution shipped one train ago and the count is **0**. This cannot be
   short-cut — it has to accumulate under the governed loop.
2. **No build is security-qualified.** Across the three builds whose refusals are
   interpretable: 5 of 42.
3. **The lane is worth minutes.** Thirteen coverable changes across the entire project
   history, each a numeric substitution.

The first is a matter of time, the second of a better model, and the third of judgement. Only
when all three change does implementing this become the right call — and the specification
will be waiting, with its tests already green.

## The implementation contract for the next train

If a future train does build it, these are the fixed points:

- **Nothing self-grants.** A proposal from a model is input to an owner decision.
- **Activation reads a lease; it never widens one.** No field exists for autonomy, skills, or
  tools, in the same way the route-revision schema has none.
- **The digest is the identity.** Any consumer must re-derive it, never trust a supplied one.
- **A revoked lease takes effect immediately**, including for a run already in flight — unlike
  a policy revision, which pins to in-flight runs. Authority granted standing must be
  withdrawable standing.
- **Every lease decision is evidence.** Issue, activate, revoke and expire are signed records
  in the same chain as `approval_decided`, or the lease is unauditable.
- **The firewall tests stay.** When authorization finally does consume a lease, the test that
  forbids it must be replaced deliberately and visibly — not deleted in passing.
