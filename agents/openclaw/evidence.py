"""Evidence loaders for OpenClaw.

OpenClaw does not generate its own truth — it reads the artifacts the governance plane
already emits and parses each into a typed view the controls can reason over:

  - ``AuditLog``       — the structured decision audit (``logs/decisions.jsonl``).
  - ``MetricSet``      — the Prometheus text exposition from ``GET /metrics``.
  - ``IsolationReport``— OpenCode's sandbox run report (``ISOLATION_RESULT=PASS`` etc.).
  - ``PolicyView``     — principals and their allowlists/ceilings from ``policy.toml``.
  - ``EvalReportView`` — the adversarial security-eval report (``evals.run --format json``).
  - ``ApplyReportView``— the OpenCode act-step apply report (``opencode_sandbox.act``).

Every loader is tolerant of *absence* (a missing optional source yields ``None`` so the
dependent control reports INCONCLUSIVE) but strict about *malformation* (a corrupt audit
line is recorded, not silently dropped — integrity is a control).

One loader is different in kind: ``load_apply_result_from_sink`` does not read a file an
emitter authored at a path it chose — it reduces a record the **verifier-owned evidence
sink** has already validated and chained (see ``sink.py`` / ``docs/evidence-sink-design.md``).
That record is authoritative precisely because its whole chain (author signatures + hash
links) was re-verified before it was reduced.

Standard library only (``json`` + ``tomllib``, 3.11+), plus the frozen ``openclaw.sink``
record model — never a third-party dependency.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from openclaw.sink import (
    EMITTER_GATEWAY,
    EMITTER_OPENCODE,
    EvidenceError,
    EvidenceRef,
    find_unique_record,
    resolve_evidence_ref,
)

# Decision values the gateway is known to emit (audit.py / app.py).
KNOWN_DECISIONS = {"allow", "deny", "filter"}
# Fields every audit record must carry to be well-formed.
REQUIRED_AUDIT_FIELDS = (
    "ts",
    "request_id",
    "principal",
    "method",
    "path",
    "model",
    "decision",
    "reason",
    "status",
)


# --------------------------------------------------------------------------- audit
@dataclass(frozen=True)
class AuditEvent:
    """One decision record from the audit log."""

    ts: str
    request_id: str
    principal: str | None
    method: str
    path: str
    model: str | None
    decision: str
    reason: str
    status: int
    raw: dict = field(default_factory=dict)


@dataclass
class AuditLog:
    """Parsed decision audit, plus the line numbers that failed to parse."""

    events: list[AuditEvent] = field(default_factory=list)
    malformed: list[int] = field(default_factory=list)
    source: str = ""

    def with_decision(self, decision: str) -> list[AuditEvent]:
        return [e for e in self.events if e.decision == decision]

    def matching_reason(self, needle: str) -> list[AuditEvent]:
        n = needle.lower()
        return [e for e in self.events if n in (e.reason or "").lower()]


def _coerce_event(obj: dict) -> AuditEvent | None:
    """Build an AuditEvent if all required fields are present, else ``None``."""
    if not isinstance(obj, dict):
        return None
    if any(key not in obj for key in REQUIRED_AUDIT_FIELDS):
        return None
    try:
        status = int(obj["status"])
    except (TypeError, ValueError):
        return None
    return AuditEvent(
        ts=str(obj["ts"]),
        request_id=str(obj["request_id"]),
        principal=obj["principal"],
        method=str(obj["method"]),
        path=str(obj["path"]),
        model=obj["model"],
        decision=str(obj["decision"]),
        reason=str(obj["reason"]),
        status=status,
        raw=obj,
    )


def load_audit(path: str | Path) -> AuditLog:
    """Parse a JSONL decision audit. Missing file -> empty log (not an error)."""
    p = Path(path)
    log = AuditLog(source=str(p))
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return log
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.malformed.append(lineno)
            continue
        event = _coerce_event(obj)
        if event is None:
            log.malformed.append(lineno)
        else:
            log.events.append(event)
    return log


# --------------------------------------------------------------------------- metrics
@dataclass(frozen=True)
class MetricSample:
    name: str
    labels: dict
    value: float


@dataclass
class MetricSet:
    samples: list[MetricSample] = field(default_factory=list)

    def total(self, name: str) -> float:
        """Sum every series of ``name`` (across all label combinations)."""
        return sum(s.value for s in self.samples if s.name == name)

    def has(self, name: str) -> bool:
        return any(s.name == name for s in self.samples)


def _parse_labels(blob: str) -> dict:
    """Parse a Prometheus label block ``k="v",k2="v2"`` into a dict."""
    labels: dict = {}
    for part in _split_labels(blob):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        labels[key.strip()] = val.strip().strip('"')
    return labels


def _split_labels(blob: str) -> list[str]:
    """Split on commas that are not inside a quoted value."""
    out: list[str] = []
    buf: list[str] = []
    in_quote = False
    for ch in blob:
        if ch == '"':
            in_quote = not in_quote
            buf.append(ch)
        elif ch == "," and not in_quote:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def parse_metrics(text: str) -> MetricSet:
    """Parse Prometheus text exposition (0.0.4) into samples, ignoring HELP/TYPE."""
    samples: list[MetricSample] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # name{labels} value   |   name value
        if "{" in line:
            name, _, rest = line.partition("{")
            label_blob, _, value_part = rest.partition("}")
            labels = _parse_labels(label_blob)
        else:
            name, _, value_part = line.partition(" ")
            labels = {}
        value_part = value_part.strip()
        if not value_part:
            continue
        try:
            value = float(value_part.split()[0])
        except (ValueError, IndexError):
            continue
        samples.append(MetricSample(name=name.strip(), labels=labels, value=value))
    return MetricSet(samples=samples)


# --------------------------------------------------------------------------- isolation
@dataclass
class IsolationReport:
    """OpenCode sandbox run report, reduced to the fields assurance cares about."""

    fields: dict[str, str] = field(default_factory=dict)
    pass_lines: list[str] = field(default_factory=list)
    fail_lines: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def result(self) -> str | None:
        return self.fields.get("ISOLATION_RESULT")

    @property
    def secret_scan(self) -> str | None:
        return self.fields.get("SECRET_SCAN_RESULT")

    @property
    def opencode_exit(self) -> str | None:
        return self.fields.get("OPENCODE_EXIT")


def parse_isolation_report(text: str) -> IsolationReport:
    """Parse the ``key=value`` markers and PASS:/FAIL: verdict lines from a run report."""
    report = IsolationReport()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("PASS:"):
            report.pass_lines.append(line[len("PASS:") :].strip())
        elif line.startswith("FAIL:") or line.startswith("FATAL:"):
            report.fail_lines.append(line.split(":", 1)[1].strip())
        elif "=" in line and " " not in line.split("=", 1)[0]:
            key, _, val = line.partition("=")
            report.fields[key.strip()] = val.strip()
    return report


def load_isolation_report(path: str | Path) -> IsolationReport | None:
    """Load an isolation report, or ``None`` if the file is absent."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    report = parse_isolation_report(text)
    report.source = str(p)
    return report


# --------------------------------------------------------------------------- policy
@dataclass
class PolicyView:
    """Principals reduced to what authorization assurance needs."""

    principals: dict[str, dict] = field(default_factory=dict)
    source: str = ""

    def allowed_models(self, principal: str) -> set[str] | None:
        entry = self.principals.get(principal)
        if entry is None:
            return None
        return set(entry.get("allowed_models", []))


def load_policy(path: str | Path) -> PolicyView | None:
    """Load principals from a TOML policy file, or ``None`` if absent."""
    p = Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    view = PolicyView(source=str(p))
    for entry in data.get("principals", []):
        name = entry.get("name")
        if not name:
            continue
        view.principals[name] = {
            "allowed_models": list(entry.get("allowed_models", [])),
            "max_autonomy_level": entry.get("max_autonomy_level"),
        }
    return view


# ------------------------------------------------------------------------- eval report
@dataclass
class EvalReportView:
    """The adversarial security-eval report, reduced to what assurance needs.

    The eval harness *attacks* the live enforced controls; OpenClaw treats its JSON
    output as one more evidence artifact — exactly like the audit or an isolation
    report — rather than importing the harness. A report that does not parse, or is
    missing its ``verdict``/``counts``, is ``malformed`` (an integrity gap, not a pass).
    """

    verdict: str | None = None
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    failed_probes: list[str] = field(default_factory=list)
    malformed: bool = False
    source: str = ""


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_eval_report(text: str, *, source: str = "") -> EvalReportView:
    """Parse the JSON emitted by ``python -m evals.run --format json``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return EvalReportView(malformed=True, source=source)
    if not isinstance(data, dict) or "verdict" not in data or "counts" not in data:
        return EvalReportView(malformed=True, source=source)
    counts = data.get("counts") or {}
    results = data.get("results") or []
    failed_probes = [
        f"{r.get('id')} ({r.get('owasp')}): {r.get('attack')}"
        for r in results
        if isinstance(r, dict) and r.get("status") == "fail"
    ]
    return EvalReportView(
        verdict=str(data.get("verdict")),
        passed=_as_int(counts.get("pass")),
        failed=_as_int(counts.get("fail")),
        skipped=_as_int(counts.get("skip")),
        failed_probes=failed_probes,
        source=source,
    )


def load_eval_report(path: str | Path) -> EvalReportView | None:
    """Load a security-eval report, or ``None`` if the file is absent."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return parse_eval_report(text, source=str(p))


# ------------------------------------------------------------------------ apply report
@dataclass
class ApplyReportView:
    """The OpenCode act-step apply report, reduced to what assurance needs.

    The act step gates a code change behind an explicit approval, applies it confined,
    and verifies it. OpenClaw treats its JSON record as one more evidence artifact (it
    does not import ``opencode_sandbox``) and asks an independent question: did the
    approval gate and the change-confinement actually hold? A report that does not parse,
    or is missing its ``status``, is ``malformed``.
    """

    status: str | None = None
    approver: str | None = None
    committed: bool = False
    declared_files: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    malformed: bool = False
    source: str = ""


def parse_apply_report(text: str, *, source: str = "") -> ApplyReportView:
    """Parse the JSON from ``opencode_sandbox.act`` (``to_dict``/``to_record`` shape)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ApplyReportView(malformed=True, source=source)
    if not isinstance(data, dict) or "status" not in data:
        return ApplyReportView(malformed=True, source=source)

    def _strlist(value) -> list[str]:
        return [str(x) for x in value] if isinstance(value, list) else []

    approver = data.get("approver")
    return ApplyReportView(
        status=str(data.get("status")),
        approver=str(approver) if approver else None,
        committed=bool(data.get("committed", False)),
        declared_files=_strlist(data.get("declared_files")),
        changed_files=_strlist(data.get("changed_files")),
        violations=_strlist(data.get("violations")),
        source=source,
    )


def load_apply_report(path: str | Path) -> ApplyReportView | None:
    """Load an act-step apply report, or ``None`` if the file is absent."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return parse_apply_report(text, source=str(p))


# ------------------------------------------------ signed apply_result (evidence sink)
# The record type OpenCode's executor emits into the sink (mirrors
# ``opencode_sandbox.evidence_emit.RECORD_TYPE_APPLY_RESULT``; duplicated as a bare string so
# the verifier does not import the executor package).
APPLY_RESULT_RECORD_TYPE = "apply_result"


def _as_strlist(value) -> list[str]:
    """Coerce a JSON value to ``list[str]`` (non-lists become empty — a malformed field)."""
    return [str(x) for x in value] if isinstance(value, list) else []


@dataclass
class AppliedEvidenceView:
    """A signed ``apply_result`` record pulled from the verifier-owned evidence sink.

    Unlike :class:`ApplyReportView` (which parses an executor-authored file at an
    executor-chosen path), this view is derived only from a record the sink has *validated and
    chained*. The payload is authoritative because :func:`load_apply_result_from_sink`
    re-verified the whole chain (author signatures + hash links) before reducing it. Every
    condition short of a clean match is a **flag**, never an exception — the verifier fails
    closed, it does not crash.
    """

    status: str | None = None
    approver: str | None = None
    committed: bool = False
    declared_files: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    run_id: str | None = None
    approval_id: str | None = None
    seq: int | None = None
    record_hash: str | None = None
    configured: bool = False  # a sink was supplied
    missing: bool = False  # no matching apply_result record on the (valid) chain
    malformed: bool = False  # a matching record's payload is unusable
    chain_error: bool = False  # verify_chain rejected the whole log
    reason: str = ""  # human-readable detail for the finding

    @property
    def usable(self) -> bool:
        """True only for a matching, well-formed signed record on a verified chain."""
        return self.configured and not (self.missing or self.malformed or self.chain_error)


def load_apply_result_from_sink(
    evidence_sink,
    *,
    run_id: str | None = None,
    approval_id: str | None = None,
) -> AppliedEvidenceView:
    """Verify the sink's chain, then reduce the matching signed ``apply_result`` to a view.

    Fail-closed and total (never raises):

      - ``evidence_sink is None`` -> ``configured=False`` ("no sink supplied").
      - ``verify_chain`` raises -> ``chain_error=True`` (log integrity unestablished).
      - no record matching emitter ``opencode`` + type ``apply_result`` + the supplied
        ``run_id``/``approval_id`` -> ``missing=True``.
      - the matching record's payload is not a usable mapping -> ``malformed=True``.

    When several records match, the **highest ``seq``** wins (deterministic: seq is the
    sink-assigned append position). The signed payload is authoritative over any file.
    """
    if evidence_sink is None:
        return AppliedEvidenceView(configured=False, reason="no evidence sink supplied")

    # The whole log must re-derive before any record it holds may be trusted (design §9c).
    try:
        evidence_sink.verify_chain()
    except EvidenceError as exc:
        return AppliedEvidenceView(
            configured=True, chain_error=True, reason=f"sink chain did not verify: {exc}"
        )

    matches = []
    for rec in getattr(evidence_sink, "records", ()):  # detached snapshots; safe to read
        env = getattr(rec, "envelope", None)
        if env is None:
            continue
        if getattr(env, "emitter", None) != EMITTER_OPENCODE:
            continue
        if getattr(env, "record_type", None) != APPLY_RESULT_RECORD_TYPE:
            continue
        if run_id is not None and getattr(env, "run_id", None) != run_id:
            continue
        if approval_id is not None and getattr(env, "approval_id", None) != approval_id:
            continue
        matches.append(rec)

    if not matches:
        return AppliedEvidenceView(
            configured=True, missing=True, reason="no matching signed apply_result record"
        )

    rec = max(matches, key=lambda r: r.seq)
    env = rec.envelope
    payload = rec.payload
    if not isinstance(payload, dict) or "status" not in payload:
        return AppliedEvidenceView(
            configured=True,
            malformed=True,
            run_id=getattr(env, "run_id", None),
            approval_id=getattr(env, "approval_id", None),
            seq=rec.seq,
            record_hash=rec.record_hash,
            reason="signed apply_result payload is malformed or missing its status",
        )

    approver = payload.get("approver")
    return AppliedEvidenceView(
        status=str(payload.get("status")),
        approver=str(approver) if approver else None,
        committed=bool(payload.get("committed", False)),
        declared_files=_as_strlist(payload.get("declared_files")),
        changed_files=_as_strlist(payload.get("changed_files")),
        violations=_as_strlist(payload.get("violations")),
        run_id=getattr(env, "run_id", None),
        approval_id=getattr(env, "approval_id", None),
        seq=rec.seq,
        record_hash=rec.record_hash,
        configured=True,
    )


# ---------------------------------------------- signed evidence graph (Step 6B linkage)
# The two gateway-emitted record types the apply_result chains back to. Duplicated as bare
# strings (like ``APPLY_RESULT_RECORD_TYPE``) so the verifier never imports the gateway.
EXECUTE_VALIDATED_RECORD_TYPE = "execute_validated"
APPROVAL_DECIDED_RECORD_TYPE = "approval_decided"
_APPROVE_DECISION = "approve"


@dataclass
class LinkedEvidenceView:
    """The result of walking the signed evidence graph ``apply_result → execute_validated →
    approval_decided`` for one run, reduced to a verdict-ready view.

    Every condition short of a fully-resolved graph is a **flag**, never an exception — the
    verifier fails closed, it does not crash. ``linkage_present`` records whether the
    ``apply_result`` even carries an ``execute_ref`` (so a legacy unsigned apply_result can
    still fall back to INCONCLUSIVE when linkage is not required); ``broken`` means a link was
    present but an edge or cross-record invariant did not hold (an integrity signal that fails
    regardless of the required flag).
    """

    configured: bool = False       # a sink was supplied
    chain_error: bool = False      # verify_chain rejected the whole log
    apply_missing: bool = False    # no unique apply_result for this run/approval
    linkage_present: bool = False  # the apply_result carries an execute_ref
    linked: bool = False           # both edges resolved and all invariants held
    broken: bool = False           # a present link failed to resolve/validate
    decision: str | None = None
    canonical_plan_hash: str | None = None
    run_id: str | None = None
    approval_id: str | None = None
    apply_seq: int | None = None
    execute_seq: int | None = None
    approval_seq: int | None = None
    reason: str = ""

    @property
    def usable(self) -> bool:
        """True only for a fully-resolved signed graph on a verified chain."""
        return self.configured and self.linked


def _need(cond: bool, msg: str) -> None:
    """Fail one graph edge/invariant closed with an :class:`EvidenceError`."""
    if not cond:
        raise EvidenceError(msg)


def load_evidence_graph_from_sink(
    evidence_sink,
    *,
    run_id: str | None = None,
    approval_id: str | None = None,
) -> LinkedEvidenceView:
    """Verify the chain, then walk ``apply_result → execute_validated → approval_decided``.

    Fail-closed and total (never raises). After the whole log re-derives, the unique signed
    ``apply_result`` for this run is located; if it carries an ``execute_ref`` both edges are
    resolved by :func:`openclaw.sink.resolve_evidence_ref` (unique ``evidence_id`` + recomputed
    ``evidence_digest`` + ``record_type`` + ``sink_id`` — never ``seq``/``record_hash``) and
    every cross-record invariant is checked (emitter is gateway, run/approval match, the
    referenced decision is ``approve``, the canonical plan hash agrees, and each authority
    record is unique for the approval). Any failure sets ``broken`` with a reason.
    """
    if evidence_sink is None:
        return LinkedEvidenceView(configured=False, reason="no evidence sink supplied")

    # The whole log must re-derive before any record it holds may be trusted (design §9c).
    try:
        evidence_sink.verify_chain()
    except EvidenceError as exc:
        return LinkedEvidenceView(
            configured=True, chain_error=True, reason=f"sink chain did not verify: {exc}"
        )

    sink_id = getattr(evidence_sink, "sink_id", "")
    records = tuple(getattr(evidence_sink, "records", ()))

    # Anchor: the unique opencode apply_result for this run/approval.
    try:
        apply_rec = find_unique_record(
            records,
            emitter=EMITTER_OPENCODE,
            record_type=APPLY_RESULT_RECORD_TYPE,
            run_id=run_id,
            approval_id=approval_id,
        )
    except EvidenceError as exc:
        return LinkedEvidenceView(
            configured=True, apply_missing=True, run_id=run_id, approval_id=approval_id,
            reason=f"no unique signed apply_result: {exc}",
        )

    apply_env = apply_rec.envelope
    apply_payload = apply_rec.payload if isinstance(apply_rec.payload, dict) else {}
    base = dict(
        configured=True,
        run_id=getattr(apply_env, "run_id", None),
        approval_id=getattr(apply_env, "approval_id", None),
        apply_seq=apply_rec.seq,
    )

    # Legacy/unsigned apply_result: no execution edge present at all.
    if "execute_ref" not in apply_payload:
        return LinkedEvidenceView(
            **base, linkage_present=False,
            reason="apply_result carries no execute_ref (unsigned/legacy apply)",
        )

    try:
        # --- edge: apply_result -> execute_validated ---
        execute_ref = EvidenceRef.from_mapping(apply_payload["execute_ref"])
        _need(execute_ref.record_type == EXECUTE_VALIDATED_RECORD_TYPE,
              f"execute_ref record_type is {execute_ref.record_type!r}, not execute_validated")
        exec_rec = resolve_evidence_ref(records, execute_ref, sink_id=sink_id)
        exec_env = exec_rec.envelope
        _need(exec_env.emitter == EMITTER_GATEWAY, "execute_validated emitter is not gateway")
        _need(exec_env.run_id == apply_env.run_id, "execute_validated run_id mismatch")
        _need(exec_env.approval_id == apply_env.approval_id,
              "execute_validated approval_id mismatch")
        # At most one execute_validated may be consumed for this approval.
        uniq_exec = find_unique_record(
            records, emitter=EMITTER_GATEWAY, record_type=EXECUTE_VALIDATED_RECORD_TYPE,
            run_id=exec_env.run_id, approval_id=exec_env.approval_id,
        )
        _need(uniq_exec.envelope.evidence_id == exec_env.evidence_id,
              "ambiguous execute_validated for this approval")
        exec_payload = exec_rec.payload if isinstance(exec_rec.payload, dict) else {}

        # --- edge: execute_validated -> approval_decided ---
        _need("approval_ref" in exec_payload, "execute_validated carries no approval_ref")
        approval_ref = EvidenceRef.from_mapping(exec_payload["approval_ref"])
        _need(approval_ref.record_type == APPROVAL_DECIDED_RECORD_TYPE,
              f"approval_ref record_type is {approval_ref.record_type!r}, not approval_decided")
        appr_rec = resolve_evidence_ref(records, approval_ref, sink_id=sink_id)
        appr_env = appr_rec.envelope
        _need(appr_env.emitter == EMITTER_GATEWAY, "approval_decided emitter is not gateway")
        _need(appr_env.run_id == exec_env.run_id, "approval_decided run_id mismatch")
        _need(appr_env.approval_id == exec_env.approval_id,
              "approval_decided approval_id mismatch")
        uniq_appr = find_unique_record(
            records, emitter=EMITTER_GATEWAY, record_type=APPROVAL_DECIDED_RECORD_TYPE,
            run_id=appr_env.run_id, approval_id=appr_env.approval_id,
        )
        _need(uniq_appr.envelope.evidence_id == appr_env.evidence_id,
              "ambiguous approval_decided for this approval")
        appr_payload = appr_rec.payload if isinstance(appr_rec.payload, dict) else {}

        # --- cross-record invariants ---
        _need(appr_payload.get("decision") == _APPROVE_DECISION,
              f"referenced approval decision is {appr_payload.get('decision')!r}, not approve")
        _need(appr_payload.get("canonical_plan_hash") == exec_payload.get("canonical_plan_hash"),
              "canonical_plan_hash differs between approval_decided and execute_validated")
    except EvidenceError as exc:
        return LinkedEvidenceView(**base, linkage_present=True, broken=True, reason=str(exc))

    return LinkedEvidenceView(
        **base, linkage_present=True, linked=True,
        decision=_APPROVE_DECISION,
        canonical_plan_hash=exec_payload.get("canonical_plan_hash"),
        execute_seq=exec_rec.seq,
        approval_seq=appr_rec.seq,
        reason="signed evidence graph resolved: apply_result -> execute_validated -> approval_decided",
    )
