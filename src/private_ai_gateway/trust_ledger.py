"""A derived, read-only trust history. It grants nothing, and it scores nothing.

This is a **projection**, not a store. Everything below is re-derived from durable facts that
already exist — the signed evidence chain and the authority store — and nothing is persisted.
Re-running it on the same inputs produces the same answer; there is no accumulating state to
drift, corrupt, or quietly become authoritative.

Three rules shape it, and each exists because the obvious alternative is a trap.

  * **A chain that does not verify yields no ledger.** Not an empty one. An empty ledger reads
    as "this principal has no bad history", which is exactly the wrong conclusion to draw from
    "the evidence could not be read". :class:`TrustLedgerError` fails closed instead.
  * **Facts, never a score.** Counts of what happened: verified completions, dirty executions,
    non-PASS verdicts, human closures, rollbacks, containments. There is deliberately no
    single number, no rating, and no autonomy level — a scalar invites a threshold, and a
    threshold is a grant with extra steps.
  * **History does not transfer across dimensions.** Success at documentation work must not
    become trust for security work, so the projection is keyed by principal *and* task class,
    never by principal alone.

**Model attribution, and its limit.** Runs recorded since
:mod:`private_ai_gateway.attribution` shipped carry a signed ``candidate_attributed`` record
naming the model build that produced the candidate and the policy hash in force at the time.
Those runs are keyed by fingerprint and policy hash, so history genuinely belongs to a build.

Runs from before that — and runs on a deployment with no evidence sink — carry no such record,
and this module refuses to guess: :data:`NOT_RECORDED` is carried explicitly rather than filled
in from the currently-configured route, which would silently credit a new build with an old
one's record. Attribution is read back from what was signed at generation time and is never
recomputed from the live route map, so re-pointing an alias cannot move history onto a model
that never ran. Each entry reports exactly which of its own dimensions are unattributable, so
"we did not record this" never reads as "this model has no history".

**The authority firewall.** Nothing in the authorization path may consume any of this. Not the
policy decision point, not the autonomy ceiling, not approval validation, not skill or tool
grants. A structural test asserts it, and a falsification proves the test bites. The ledger
exists to make a future decision *inspectable by a human* — it does not make the decision, and
in this increment nothing consumes it at all.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

# Dimensions the signed evidence genuinely supports today.
DIM_PRINCIPAL = "principal"
DIM_TASK_CLASS = "task_class"
DIM_PLAN_HASH = "canonical_plan_hash"

# Dimensions the evidence does **not** carry. Named, never fabricated.
NOT_RECORDED = "not_recorded"
UNATTRIBUTABLE_DIMENSIONS = ("model_fingerprint", "policy_hash")


class TrustLedgerError(Exception):
    """The trust history could not be derived from verified facts — no ledger is produced."""


@dataclass(frozen=True)
class TrustKey:
    """One projection cell. Never principal alone — history is not transferable."""

    principal: str = ""
    task_class: str = ""
    model_fingerprint: str = NOT_RECORDED
    policy_hash: str = NOT_RECORDED

    def to_mapping(self) -> dict:
        return asdict(self)


@dataclass
class TrustFacts:
    """Counts of things that actually happened. No score, no rating, no level."""

    runs: int = 0
    verified_complete: int = 0
    non_pass_verdicts: int = 0
    dirty_executions: int = 0
    closed_unknown: int = 0
    human_asserted: int = 0
    rollback_attempted: int = 0
    rollback_restored: int = 0
    rollback_failed: int = 0
    contained: int = 0
    evidence_failures: int = 0

    def to_mapping(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class TrustEntry:
    """One key and its facts, plus which of *this entry's* dimensions were never recorded."""

    key: TrustKey
    facts: TrustFacts
    unattributable: tuple[str, ...] = UNATTRIBUTABLE_DIMENSIONS

    @staticmethod
    def unattributable_for(key: TrustKey) -> tuple[str, ...]:
        """Report only the dimensions this key actually lacks — never a blanket disclaimer."""
        return tuple(
            dim
            for dim in UNATTRIBUTABLE_DIMENSIONS
            if getattr(key, dim, NOT_RECORDED) == NOT_RECORDED
        )

    def to_mapping(self) -> dict:
        return {
            "key": self.key.to_mapping(),
            "facts": self.facts.to_mapping(),
            "unattributable": list(self.unattributable),
        }


@dataclass(frozen=True)
class TrustLedger:
    """The whole derived projection. Read-only, unpersisted, and non-authoritative."""

    entries: tuple[TrustEntry, ...] = ()
    derived_from_records: int = 0
    notes: tuple[str, ...] = ()

    def to_mapping(self) -> dict:
        return {
            "entries": [e.to_mapping() for e in self.entries],
            "derived_from_records": self.derived_from_records,
            "unattributable_dimensions": list(UNATTRIBUTABLE_DIMENSIONS),
            "notes": list(self.notes),
            "grants": "nothing",
        }


_NOTES = (
    "Runtime history only. Qualification-corpus results are a separate measurement and are "
    "never counted here.",
    "Model attribution is read back from the signed candidate_attributed record written when "
    "the candidate was generated — never recomputed from the current route map. Runs with no "
    "such record report not_recorded rather than being credited to whatever is routed now.",
    "Facts only — deliberately no trust score and no autonomy level.",
)


def derive_ledger(authority_store, evidence_sink) -> TrustLedger:
    """Re-derive the trust history from verified durable facts. Persists nothing.

    Fails closed on an unverifiable chain: an unreadable history is not a clean history, and
    an empty ledger would read as exactly that.
    """
    from openclaw.evidence import SinkGraphReader

    from private_ai_gateway.attribution import CANDIDATE_ATTRIBUTED_RECORD_TYPE
    from private_ai_gateway.disposition import (
        DISPOSITION_CLOSED_UNKNOWN,
        RUN_DISPOSITION_RECORD_TYPE,
    )

    if evidence_sink is None:
        raise TrustLedgerError("no evidence sink is configured; no trust history exists")

    reader = SinkGraphReader(evidence_sink)
    if reader.chain_error:
        raise TrustLedgerError(
            f"the evidence chain did not verify, so no ledger is produced: {reader.chain_error}"
        )

    try:
        approvals = tuple(authority_store.snapshot_approvals())
    except Exception as exc:  # noqa: BLE001 — unreadable authority is not clean authority
        raise TrustLedgerError(f"the authority store could not be read: {exc}") from exc

    # Attribution recorded at generation time, keyed by run. Read back from the signed chain,
    # never recomputed from the live route map — see the module docstring.
    attributed: dict[str, tuple[str, str]] = {}
    for rec in reader.records:
        if rec.envelope.record_type != CANDIDATE_ATTRIBUTED_RECORD_TYPE:
            continue
        payload = rec.payload if isinstance(rec.payload, dict) else {}
        fingerprint = payload.get("model_fingerprint") or ""
        if not fingerprint or rec.envelope.run_id in attributed:
            # Two attribution records for one run means the generation point ran twice and
            # neither can be preferred; fall back to unattributed rather than pick.
            attributed[rec.envelope.run_id] = (NOT_RECORDED, NOT_RECORDED)
            continue
        attributed[rec.envelope.run_id] = (
            fingerprint,
            payload.get("policy_hash") or NOT_RECORDED,
        )

    runs = {}
    for appr in approvals:
        run = authority_store.get_run(appr.run_id)
        runs[appr.approval_id] = (
            appr,
            getattr(run, "principal_id", "") if run is not None else "",
        )

    cells: dict[TrustKey, TrustFacts] = {}

    def key_for(appr, principal: str) -> TrustKey:
        fingerprint, policy_hash = attributed.get(
            appr.run_id, (NOT_RECORDED, NOT_RECORDED)
        )
        return TrustKey(
            principal=principal,
            task_class=appr.task_class or "unclassified",
            model_fingerprint=fingerprint,
            policy_hash=policy_hash,
        )

    def facts_for(approval_id: str) -> TrustFacts | None:
        entry = runs.get(approval_id)
        if entry is None:
            return None
        return cells.setdefault(key_for(*entry), TrustFacts())

    # One pass per approval for the shape of its history, then one pass over the records for
    # the outcomes. Both read the same verified snapshot.
    for appr, principal in runs.values():
        cells.setdefault(key_for(appr, principal), TrustFacts()).runs += 1

    for rec in reader.records:
        env = rec.envelope
        payload = rec.payload if isinstance(rec.payload, dict) else {}
        facts = facts_for(env.approval_id or "")
        if facts is None:
            # Evidence with no authority projection is a reconciliation concern, not a trust
            # fact. Counting it against a principal would mean guessing whose it was.
            continue

        if env.record_type == "verification_result":
            if payload.get("verdict") == "PASS":
                facts.verified_complete += 1
            else:
                facts.non_pass_verdicts += 1
            if not payload.get("evidence_graph_verified", True):
                facts.evidence_failures += 1
        elif env.record_type == RUN_DISPOSITION_RECORD_TYPE:
            if payload.get("disposition") == DISPOSITION_CLOSED_UNKNOWN:
                facts.closed_unknown += 1
            else:
                facts.human_asserted += 1
            facts.dirty_executions += 1
        elif env.record_type == "rollback_result":
            facts.rollback_attempted += 1
            if payload.get("status") == "restored":
                facts.rollback_restored += 1
            else:
                facts.rollback_failed += 1
            if payload.get("contained"):
                facts.contained += 1

    entries = tuple(
        TrustEntry(key=key, facts=facts, unattributable=TrustEntry.unattributable_for(key))
        for key, facts in sorted(
            cells.items(),
            key=lambda kv: (kv[0].principal, kv[0].task_class, kv[0].model_fingerprint),
        )
    )
    return TrustLedger(
        entries=entries, derived_from_records=len(reader.records), notes=_NOTES
    )


@dataclass(frozen=True)
class TrustView:
    """What a human is shown: qualification and runtime history, kept apart.

    They are different kinds of claim. Qualification is "how did this model do on a corpus we
    built"; runtime history is "what happened when this principal actually ran". Presenting
    corpus results as production history would be the most flattering possible lie, so the two
    never share a table, a count, or a heading.
    """

    qualification: tuple[dict, ...] = ()
    runtime: tuple[dict, ...] = ()

    def to_mapping(self) -> dict:
        return {
            "qualification": [dict(q) for q in self.qualification],
            "runtime": [dict(r) for r in self.runtime],
            "separation": (
                "QUALIFICATION is corpus measurement; RUNTIME HISTORY is what the governed "
                "loop actually did. They are never combined."
            ),
        }


def build_view(registry, ledger: TrustLedger | None) -> TrustView:
    """Assemble the console view from the capability registry and the derived ledger."""
    from private_ai_gateway import registry as reg

    qualification = []
    for model in getattr(registry, "models", ()):
        for lane, standing in sorted(model.lanes.items()):
            if standing.state == reg.NOT_EVALUATED and not standing.evidence:
                continue
            qualification.append({
                "kind": "QUALIFICATION",
                "lane": lane,
                "lane_label": reg.LANE_LABELS.get(lane, lane),
                "route_alias": model.identity.route_alias,
                "model": model.identity.resolved_model,
                "fingerprint": model.identity.short_fingerprint,
                "state": standing.state,
                "reason": standing.reason,
                "evidence": dict(standing.evidence),
            })

    runtime = []
    if ledger is not None:
        for entry in ledger.entries:
            runtime.append({
                "kind": "RUNTIME HISTORY",
                **entry.key.to_mapping(),
                **entry.facts.to_mapping(),
                "unattributable": list(entry.unattributable),
            })
    return TrustView(qualification=tuple(qualification), runtime=tuple(runtime))
