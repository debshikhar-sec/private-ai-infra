"""The OpenCode act step: an approval-gated, confined, verified apply path.

This is the *write* boundary of the control plane, and the place the project's thesis —
**AI capability is not AI authority** — has to be mechanical rather than advisory. A
coding agent's ability to *propose* a change is not authority to *apply* it.

The protocol, in four enforced steps:

  1. **Confinement / consistency gate.** A proposal declares exactly which files it
     edits (and how). Any path that escapes the target root, any inconsistent edit
     (modify a missing file, create over an existing one), is **REJECTED** before a
     single byte is written.
  2. **Authority gate.** Applying any write is at least ``owner_run`` (L3) on the
     autonomy ladder — the read/propose/dry-run band (L0–L2) never writes. At or above
     L3 an explicit, *separately-sourced* ``Approval`` is mandatory; without it the apply
     is **REFUSED** (fail closed, exactly like the gateway's bearer auth). The proposer
     cannot approve itself — capability and authority come from different inputs.
  3. **Confined apply.** The change is applied only inside a **copy** of the target
     (a sandbox), never the working tree, unless a real target is explicitly committed to.
  4. **Verification.** sha256 manifests taken before and after prove that **exactly the
     declared files changed and nothing else**. An undeclared write is a **FAILED** apply,
     not a silent success.

The result is an ``ApplyReport`` — a structured, serializable record (the same evidence
doctrine as the review harness's isolation manifests) that can be folded into Hermes'
memory or checked by OpenClaw.

Standard library only (plus the gateway's ``autonomy`` ladder for level names).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from private_ai_gateway import autonomy

# Applying a change to the tree is at least owner_run (L3): writing is authority, not the
# observe/suggest/dry-run band (L0–L2). At or above this level an explicit granted
# approval is mandatory.
REQUIRED_APPROVAL_LEVEL = 3

KIND_MODIFY = "modify"
KIND_CREATE = "create"
KIND_DELETE = "delete"
KINDS = {KIND_MODIFY, KIND_CREATE, KIND_DELETE}

# Apply outcomes.
APPLIED = "applied"
REFUSED = "refused"  # gated: no/ungranted approval for an authority-bearing apply
REJECTED = "rejected"  # confinement / consistency violation — rejected before any write
FAILED = "failed"  # apply attempted but verification found an undeclared change


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- model
@dataclass(frozen=True)
class FileEdit:
    """One declared edit. ``new_content`` is ``None`` only for a delete."""

    path: str
    kind: str
    new_content: str | None = None


@dataclass
class ChangeProposal:
    """A proposed change set: capability, not authority. Carries no approval."""

    edits: list[FileEdit] = field(default_factory=list)
    rationale: str = ""
    autonomy_level: int = REQUIRED_APPROVAL_LEVEL
    source: str = ""

    @property
    def declared_files(self) -> list[str]:
        return [e.path for e in self.edits]


@dataclass(frozen=True)
class Approval:
    """An owner's authorization to apply — supplied separately from the proposal."""

    approver: str
    reason: str
    granted: bool = True


def parse_proposal(text: str, *, source: str = "") -> ChangeProposal:
    """Parse a proposal from JSON. An approval is deliberately *not* read from here."""
    data = json.loads(text)
    edits = [
        FileEdit(
            path=str(e.get("path", "")),
            kind=str(e.get("kind", "")),
            new_content=e.get("new_content"),
        )
        for e in data.get("edits", [])
    ]
    return ChangeProposal(
        edits=edits,
        rationale=str(data.get("rationale", "")),
        autonomy_level=autonomy.parse_level(
            data.get("autonomy_level"), REQUIRED_APPROVAL_LEVEL
        ),
        source=source,
    )


def load_proposal(path: str | Path) -> ChangeProposal:
    p = Path(path)
    return parse_proposal(p.read_text(encoding="utf-8"), source=str(p))


# ----------------------------------------------------------------------- confinement
def _is_confined(rel: str) -> bool:
    """A declared path must be relative and never climb out of the target root."""
    if not rel or rel.startswith("/") or rel.startswith("~"):
        return False
    parts = Path(rel).parts
    return ".." not in parts and not any(p.startswith("/") for p in parts)


def _resolves_within(root: Path, rel: str) -> bool:
    """Defense in depth against symlink/`..` escape: the resolved path stays under root."""
    try:
        root_resolved = root.resolve()
        target = (root / rel).resolve()
    except (OSError, RuntimeError):
        return False
    return target == root_resolved or root_resolved in target.parents


def validate(proposal: ChangeProposal, root: str | Path) -> list[str]:
    """Return a list of confinement/consistency violations (empty == clean)."""
    root = Path(root)
    violations: list[str] = []
    seen: set[str] = set()
    for e in proposal.edits:
        if e.kind not in KINDS:
            violations.append(f"{e.path or '<empty>'}: unknown edit kind {e.kind!r}")
            continue
        if not _is_confined(e.path) or not _resolves_within(root, e.path):
            violations.append(f"{e.path or '<empty>'}: path escapes the target root")
            continue
        if e.path in seen:
            violations.append(f"{e.path}: duplicate edit for the same path")
        seen.add(e.path)
        exists = (root / e.path).exists()
        if e.kind == KIND_MODIFY:
            if not exists:
                violations.append(f"{e.path}: modify of a file that does not exist")
            if e.new_content is None:
                violations.append(f"{e.path}: modify requires new_content")
        elif e.kind == KIND_CREATE:
            if exists:
                violations.append(f"{e.path}: create of a file that already exists")
            if e.new_content is None:
                violations.append(f"{e.path}: create requires new_content")
        elif e.kind == KIND_DELETE and not exists:
            violations.append(f"{e.path}: delete of a file that does not exist")
    return violations


def render_diff(proposal: ChangeProposal, root: str | Path) -> str:
    """A unified diff of the proposal against ``root`` — for human review before approval."""
    root = Path(root)
    chunks: list[str] = []
    for e in proposal.edits:
        target = root / e.path
        old = (
            target.read_text(encoding="utf-8").splitlines(keepends=True)
            if e.kind != KIND_CREATE and target.exists()
            else []
        )
        new = [] if e.kind == KIND_DELETE else (e.new_content or "").splitlines(keepends=True)
        diff = difflib.unified_diff(old, new, fromfile=f"a/{e.path}", tofile=f"b/{e.path}")
        chunk = "".join(diff)
        if chunk:
            chunks.append(chunk if chunk.endswith("\n") else chunk + "\n")
    return "\n".join(chunks)


# --------------------------------------------------------------------------- report
@dataclass
class ApplyReport:
    status: str
    autonomy_level: int
    declared_files: list[str]
    changed_files: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    approver: str | None = None
    committed: bool = False
    sandbox: str | None = None
    rationale: str = ""
    detail: str = ""
    generated_at: str = field(default_factory=_utc_now_iso)

    @property
    def applied(self) -> bool:
        return self.status == APPLIED

    def exit_code(self) -> int:
        return 0 if self.status == APPLIED else 1

    def to_dict(self) -> dict:
        d = asdict(self)
        d["autonomy_name"] = autonomy.level_name(self.autonomy_level)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def to_record(self) -> dict:
        """Compact, JSON-only hand-off for memory/evidence — no internal types."""
        return {
            "component": "opencode-act",
            "status": self.status,
            "autonomy_level": self.autonomy_level,
            "autonomy_name": autonomy.level_name(self.autonomy_level),
            "approver": self.approver,
            "committed": self.committed,
            "declared_files": self.declared_files,
            "changed_files": self.changed_files,
            "violations": self.violations,
            "generated_at": self.generated_at,
            "detail": self.detail,
        }

    def to_text(self) -> str:
        lines = [
            "OpenCode act report",
            f"generated: {self.generated_at}",
            f"status:    {self.status.upper()}",
            f"autonomy:  L{self.autonomy_level} ({autonomy.level_name(self.autonomy_level)})",
            f"approver:  {self.approver or '(none)'}",
            f"committed: {self.committed}",
            "",
            f"declared:  {', '.join(self.declared_files) or '(none)'}",
            f"changed:   {', '.join(self.changed_files) or '(none)'}",
        ]
        if self.violations:
            lines.append("violations:")
            lines.extend(f"  - {v}" for v in self.violations)
        if self.sandbox:
            lines.append(f"sandbox:   {self.sandbox}")
        lines += ["", self.detail, ""]
        return "\n".join(lines)


# --------------------------------------------------------------------------- apply
def _manifest(root: Path) -> dict[str, str]:
    """sha256 of every file under ``root``, keyed by relative path."""
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _apply_edit(root: Path, edit: FileEdit) -> None:
    target = root / edit.path
    if edit.kind == KIND_DELETE:
        if target.exists():
            target.unlink()
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(edit.new_content or "", encoding="utf-8")


def _apply_and_verify(
    root: Path, edits: list[FileEdit], declared: set[str]
) -> tuple[list[str], list[str], list[str]]:
    """Apply edits under ``root`` and diff manifests: (changed, unexpected, noops)."""
    before = _manifest(root)
    for e in edits:
        _apply_edit(root, e)
    after = _manifest(root)
    keys = set(before) | set(after)
    changed = {k for k in keys if before.get(k) != after.get(k)}
    unexpected = sorted(changed - declared)
    noops = sorted(declared - changed)
    return sorted(changed), unexpected, noops


def apply_proposal(
    proposal: ChangeProposal,
    src_root: str | Path,
    sandbox_root: str | Path,
    *,
    approval: Approval | None = None,
    commit_to: str | Path | None = None,
) -> ApplyReport:
    """Gate, confine, apply, and verify a proposal. ``src_root`` is never written to.

    Always applies into ``sandbox_root`` (a copy). If ``commit_to`` is given, the same
    verified change is mirrored onto that real target — which still requires the approval
    the authority gate already demanded.
    """
    src_root = Path(src_root)
    sandbox_root = Path(sandbox_root)
    declared = proposal.declared_files
    declared_set = set(declared)
    # Any actual write is inherently at least owner_run (L3). The effective level is the
    # most privileged of what the proposal declared and what an apply requires, so a
    # proposal cannot under-declare (e.g. "L2 dry_run") to dodge the approval gate while
    # still carrying edits — the same most-privileged-wins rule the gateway uses.
    under_declared = bool(proposal.edits) and proposal.autonomy_level < REQUIRED_APPROVAL_LEVEL
    level = max(proposal.autonomy_level, REQUIRED_APPROVAL_LEVEL) if proposal.edits else proposal.autonomy_level
    base = dict(
        autonomy_level=level,
        declared_files=declared,
        rationale=proposal.rationale,
        approver=(approval.approver if approval and approval.granted else None),
    )

    # 1) confinement / consistency — reject before any write
    violations = validate(proposal, src_root)
    if violations:
        return ApplyReport(
            status=REJECTED,
            violations=violations,
            detail="rejected before any write: confinement/consistency violations.",
            **base,
        )

    # 2) authority — capability to propose is not authority to apply
    if level >= REQUIRED_APPROVAL_LEVEL and not (approval and approval.granted):
        note = (
            f" (proposal under-declared L{proposal.autonomy_level}; an apply is at least "
            f"L{REQUIRED_APPROVAL_LEVEL})"
            if under_declared
            else ""
        )
        return ApplyReport(
            status=REFUSED,
            detail=(
                f"apply at L{level} ({autonomy.level_name(level)}){note} requires an explicit "
                "granted approval; none supplied — refusing (fail closed)."
            ),
            **base,
        )

    # 3) confined apply into a sandbox copy, then 4) verify via manifests
    shutil.copytree(src_root, sandbox_root)
    changed, unexpected, noops = _apply_and_verify(sandbox_root, proposal.edits, declared_set)
    if unexpected:
        return ApplyReport(
            status=FAILED,
            changed_files=changed,
            sandbox=str(sandbox_root),
            detail=f"verification failed: apply touched undeclared file(s): {unexpected}.",
            **base,
        )

    detail = f"applied and verified in sandbox: exactly the {len(declared_set)} declared file(s) changed"
    if noops:
        detail += f" (no-op on {noops}: declared but content was unchanged)"

    committed = False
    if commit_to is not None:
        c_changed, c_unexpected, _ = _apply_and_verify(
            Path(commit_to), proposal.edits, declared_set
        )
        if c_unexpected:
            return ApplyReport(
                status=FAILED,
                changed_files=c_changed,
                sandbox=str(sandbox_root),
                detail=f"commit verification failed: touched undeclared file(s) in target: {c_unexpected}.",
                **base,
            )
        committed = True
        detail += f"; committed to {commit_to}"
    else:
        detail += "; not committed in place (sandbox only)"

    return ApplyReport(
        status=APPLIED,
        changed_files=changed,
        sandbox=str(sandbox_root),
        committed=committed,
        detail=detail + ".",
        **base,
    )
