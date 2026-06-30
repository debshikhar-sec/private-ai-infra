# OpenCode act-step contract

OpenCode is the **implementer** component of the control plane. Its review half is
read-only and proves it changed nothing; its **act** half is the *write* boundary, and
the place the project's thesis — **AI capability is not AI authority** — must be
mechanical rather than advisory. A coding agent's ability to *propose* a change is not
authority to *apply* it.

## Standing rules

1. **A proposal is capability; an approval is authority — and they come from different
   inputs.** A `ChangeProposal` declares the edits and a rationale. It carries **no**
   approval. Authorization is a separately-sourced `Approval` (an owner and a reason).
   The proposer cannot approve itself.
2. **Fail closed.** Applying any write is at least `owner_run` (**L3**) on the autonomy
   ladder. Without an explicit *granted* approval the apply is **REFUSED** — exactly like
   the gateway's bearer auth refuses an unauthenticated request.
3. **No under-declaring.** A proposal that carries edits is treated as at least L3 even if
   it declares a lower level, so it cannot label itself `dry_run` to dodge the approval
   gate. The effective level is the most-privileged of declared-vs-required — the same
   rule the gateway uses across header/body channels.
4. **Confinement is checked before any write.** Every declared path must be relative and
   stay within the target root (no `..`, no absolute paths, no symlink escape). A path
   that escapes is **REJECTED** before a single byte is written.
5. **Apply only into a copy, then verify.** The change is applied inside a sandbox copy
   of the target; sha256 manifests taken before and after must show that **exactly the
   declared files changed and nothing else**. An undeclared write is a **FAILED** apply,
   not a silent success. Promotion onto the real target (`commit_to`) re-verifies the
   same way and still requires the approval.
6. **Every apply produces a record.** The `ApplyReport` (status, effective level,
   approver, declared vs changed files, violations) is a structured, serializable artifact
   — the same evidence doctrine as the review harness's isolation manifests — so it can be
   folded into Hermes' memory or checked by OpenClaw.

## Outcomes

| Status | Meaning |
|---|---|
| `REJECTED` | A confinement/consistency violation was found; nothing was written. |
| `REFUSED` | An authority-bearing apply had no granted approval; nothing was written (fail closed). |
| `FAILED` | The apply ran but verification found a change outside the declared files. |
| `APPLIED` | The declared change applied into the sandbox (and, if `--commit`, onto the target) and verified exactly. |

`exit_code()` is non-zero unless the status is `APPLIED`, so the act step can gate CI or a
pipeline.

## Not yet

This step confines the apply at the *protocol* and *filesystem-verification* layers. It is
not an OS-level jail (seccomp/namespaces); running the apply under a kernel sandbox is the
remaining OpenCode hardening step. The current guarantees are: separated capability/authority,
fail-closed approval gate, no-under-declaring, confinement validation, and verified-no-undeclared-writes.
