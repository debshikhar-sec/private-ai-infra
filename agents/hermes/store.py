"""Hermes persistent memory: project state, run history, and next actions.

Hermes is a *stateful* planner. Between planning cycles it persists what has been
verified so far, so the next cycle resumes from real state instead of replanning from
scratch. Three files make up that memory, mirroring the original design:

  - ``PROJECT_STATE.json`` — the canonical, machine-readable state (components,
    autonomy ceilings, phase status, standing restrictions).
  - ``RUN_HISTORY.md``     — an append-only log: one dated section per planning cycle.
  - ``NEXT_ACTIONS.md``    — the current gate: the one allowed next action, what is
    not allowed yet, and what needs owner approval.

Two properties matter for a control plane and are enforced here:

  - **Atomic writes.** State is written to a temp file and ``os.replace``'d into place,
    so a crash mid-write never leaves a half-written ``PROJECT_STATE.json``.
  - **Pre-write backup.** Before state is overwritten, the prior copy is snapshotted
    under ``backups/<timestamp>/`` — the original design kept a memory backup before
    every phase, and so does this.

Pure standard library: this adds no dependency to the project.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = "PROJECT_STATE.json"
HISTORY_FILE = "RUN_HISTORY.md"
NEXT_ACTIONS_FILE = "NEXT_ACTIONS.md"
BACKUPS_DIR = "backups"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically (temp file + ``os.replace``)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


@dataclass
class RunEntry:
    """One planning cycle, recorded to RUN_HISTORY.md."""

    goal: str
    autonomy_level: str = "L1"
    results: list[str] = field(default_factory=list)
    next_action: str = ""
    approval_required: str = "none"
    recorded_at: str = field(default_factory=_utc_now_iso)

    def to_markdown(self) -> str:
        lines = [f"## {self.recorded_at} — {self.goal}", ""]
        lines.append(f"Autonomy level: {self.autonomy_level}")
        lines.append(f"Approval required: {self.approval_required}")
        lines.append("")
        lines.append("Results:")
        if self.results:
            lines.extend(f"- {r}" for r in self.results)
        else:
            lines.append("- (none recorded)")
        lines.append("")
        lines.append(f"Next action: {self.next_action or '(undetermined)'}")
        lines.append("")
        return "\n".join(lines)


@dataclass
class NextGate:
    """The current gate, rendered to NEXT_ACTIONS.md."""

    current_gate: str
    allowed_next_action: str
    not_allowed: list[str] = field(default_factory=list)
    approval_needed: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = ["# Next Actions", "", f"## Current gate — {self.current_gate}", ""]
        lines.append(f"Allowed next action:\n- {self.allowed_next_action}")
        lines.append("")
        lines.append("Not allowed yet:")
        lines.extend(f"- {x}" for x in (self.not_allowed or ["(none)"]))
        lines.append("")
        lines.append("Approval needed for:")
        lines.extend(f"- {x}" for x in (self.approval_needed or ["(none)"]))
        lines.append("")
        return "\n".join(lines)


class MemoryStore:
    """Read/write Hermes' persistent memory under a single directory."""

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)

    # -- paths ---------------------------------------------------------------
    @property
    def state_path(self) -> Path:
        return self.root / STATE_FILE

    @property
    def history_path(self) -> Path:
        return self.root / HISTORY_FILE

    @property
    def next_actions_path(self) -> Path:
        return self.root / NEXT_ACTIONS_FILE

    # -- state ---------------------------------------------------------------
    def load_state(self) -> dict:
        """Return the parsed PROJECT_STATE.json, or ``{}`` if absent.

        A malformed state file raises ``ValueError`` rather than being silently
        treated as empty — losing canonical state must not be quiet.
        """
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"corrupt {STATE_FILE}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{STATE_FILE} must contain a JSON object")
        return data

    def save_state(self, state: dict, *, backup: bool = True) -> None:
        """Write PROJECT_STATE.json atomically, snapshotting the prior copy first."""
        if backup and self.state_path.exists():
            self._backup_existing()
        state = dict(state)
        state["updated_at"] = _utc_now_iso()
        _atomic_write(self.state_path, json.dumps(state, indent=2, sort_keys=True) + "\n")

    def _backup_existing(self) -> Path:
        """Copy the current memory files into ``backups/<timestamp>/``."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = self.root / BACKUPS_DIR / stamp
        dest.mkdir(parents=True, exist_ok=True)
        for name in (STATE_FILE, HISTORY_FILE, NEXT_ACTIONS_FILE):
            src = self.root / name
            if src.exists():
                shutil.copy2(src, dest / name)
        return dest

    # -- run history ---------------------------------------------------------
    def append_run(self, entry: RunEntry) -> None:
        """Append one planning cycle to RUN_HISTORY.md (creating it if needed)."""
        self.root.mkdir(parents=True, exist_ok=True)
        block = entry.to_markdown()
        if self.history_path.exists():
            existing = self.history_path.read_text(encoding="utf-8").rstrip("\n")
            text = f"{existing}\n\n{block}"
        else:
            text = f"# Run History\n\n{block}"
        _atomic_write(self.history_path, text.rstrip("\n") + "\n")

    # -- next actions --------------------------------------------------------
    def set_next_gate(self, gate: NextGate) -> None:
        """Replace NEXT_ACTIONS.md with the current gate."""
        _atomic_write(self.next_actions_path, gate.to_markdown())
