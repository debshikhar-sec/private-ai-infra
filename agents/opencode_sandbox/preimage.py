"""Step 7C.3A — the reversibility foundation: a bounded pre-image taken before mutation.

Nothing in this runtime can currently be undone, and an audit of the existing apply
artifacts says why. ``_apply_and_verify`` computes a full sha256 manifest of the tree before
*and* after the edits, but keeps only the derived **set difference**: ``ApplyReport`` records
``changed_files`` as bare paths, and the signed ``apply_result`` carries exactly that. No
hashes survive, no content survives, and the report cannot even distinguish a create from a
delete. The sandbox is a copy made *before* the edits and then mutated in place, so it holds
the post-state; with ``commit_to`` the target's prior bytes are simply gone. **The existing
artifacts are not sufficient to reverse anything**, and no amount of reading them harder will
make them so — hashes recorded after the fact cannot reconstruct content.

So this module records the one thing that can: the **pre-image**, captured before the first
byte is written, for exactly the declared mutation targets and nothing else.

What that buys, precisely:

  * ``existed: false`` for an addition — reversing a create means *deleting* it, and the
    snapshot has to say so rather than leave the absence implicit;
  * the prior bytes for an update or a delete, stored as content-addressed blobs;
  * a manifest digest over the whole thing, so a later restore can prove it is restoring what
    it thinks it is.

Boundaries this holds, because a rollback primitive is a write primitive:

  * **Sandbox-confined.** Declared paths are re-validated with the same confinement rules the
    apply itself uses; absolute paths, ``..``, and symlinks fail closed, as does anything that
    is not a regular file.
  * **Not caller-placed.** A caller supplies a store *base*; the snapshot id is generated, so
    no caller chooses where a snapshot lands.
  * **Bounded.** Per-entry and per-snapshot byte ceilings, checked before reading. An
    oversized target refuses the snapshot outright rather than capturing part of it — a
    partial pre-image is worse than none, because it looks reversible and is not.
  * **Never in signed evidence.** :meth:`PreimageSnapshot.evidence` returns identity and
    digests only. Snapshot *contents* stay on local disk; putting a file's prior bytes into a
    governance record would put arbitrary — possibly secret — content into the audit trail.
  * **Atomic.** A snapshot is built under a temporary name and renamed into place, so a
    crash mid-capture leaves no directory that looks complete.

**No rollback happens here.** :func:`restore_into` is the reversibility *primitive*, and it is
deliberately reachable from nothing: no approval, no reservation, no evidence, no caller in
the governed path. Step 7C.3B supplies the authority around it — owner approval, a
single-use reservation, and a signed outcome — and until it does, restoring is something only
a test does.

**Old applies stay irreversible.** A run that predates its snapshot has no pre-image and
never will; nothing here fabricates one, and no historical run becomes rollback-eligible
because this module exists.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from opencode_sandbox.apply import KIND_CREATE, _is_confined, _resolves_within

# Bounds. A pre-image is a safety net, not an archive: these ceilings keep a runaway apply
# from filling the state directory, and are checked *before* any file is read.
MAX_ENTRY_BYTES = 1 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024

MANIFEST_NAME = "manifest.json"
BLOBS_DIR = "blobs"
SNAPSHOT_SCHEMA = 1

# Refusal codes — a snapshot that cannot be taken completely is never taken partially.
R_UNCONFINED = "path_not_confined"
R_NOT_REGULAR = "not_a_regular_file"
R_ENTRY_TOO_LARGE = "entry_too_large"
R_SNAPSHOT_TOO_LARGE = "snapshot_too_large"
R_NO_TARGETS = "no_declared_targets"
R_STORE_UNUSABLE = "store_unusable"
R_SNAPSHOT_CORRUPT = "snapshot_corrupt"
R_ALREADY_EXISTS = "snapshot_already_exists"


class PreimageError(Exception):
    """A pre-image could not be captured or read back. ``code`` is the reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(manifest: dict) -> str:
    """``sha256:`` over the canonical bytes of a snapshot manifest."""
    return "sha256:" + hashlib.sha256(_canonical(manifest)).hexdigest()


@dataclass(frozen=True)
class PreimageEntry:
    """One declared target's state *before* the mutation."""

    path: str
    existed: bool
    digest: str = ""      # "" exactly when the file did not exist
    size: int = 0

    def to_mapping(self) -> dict:
        return {
            "path": self.path,
            "existed": self.existed,
            "digest": self.digest,
            "size": self.size,
        }


@dataclass(frozen=True)
class PreimageSnapshot:
    """A captured, verified pre-image of every declared mutation target."""

    snapshot_id: str
    root: Path
    entries: tuple[PreimageEntry, ...]
    digest: str
    run_id: str = ""
    approval_id: str = ""

    @property
    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries)

    def evidence(self) -> dict:
        """The only part of a snapshot that may enter signed evidence.

        Identity and digests — never contents, never absolute paths. A verifier can bind an
        apply to *this* snapshot and later confirm the snapshot has not changed, without the
        governance log ever holding a byte of the file it is protecting.
        """
        return {
            "snapshot_id": self.snapshot_id,
            "snapshot_digest": self.digest,
            "entries": len(self.entries),
            "bytes": self.total_bytes,
        }

    def verify(self) -> None:
        """Re-derive the snapshot from disk; raise if anything no longer matches.

        Trusts no stored derived value: the manifest is re-read, its digest recomputed, and
        every blob re-hashed. A snapshot that does not re-derive is not a weaker snapshot —
        it is not a snapshot, and a rollback resting on it must fail closed.
        """
        stored = _read_manifest(self.root)
        if manifest_digest(stored) != self.digest:
            raise PreimageError(
                R_SNAPSHOT_CORRUPT, f"manifest digest changed for {self.snapshot_id!r}"
            )
        for entry in self.entries:
            if not entry.existed:
                continue
            blob = self.root / BLOBS_DIR / _blob_name(entry)
            if not blob.is_file():
                raise PreimageError(
                    R_SNAPSHOT_CORRUPT, f"missing pre-image blob for {entry.path!r}"
                )
            if _sha256_file(blob) != entry.digest:
                raise PreimageError(
                    R_SNAPSHOT_CORRUPT, f"pre-image blob for {entry.path!r} does not re-hash"
                )


def _blob_name(entry: PreimageEntry) -> str:
    """Content-addressed blob name, so identical prior contents are stored once."""
    return entry.digest.split(":", 1)[1]


def _read_manifest(root: Path) -> dict:
    try:
        return json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PreimageError(R_SNAPSHOT_CORRUPT, f"manifest unreadable: {exc}") from exc


def capture_preimage(
    proposal,
    target_root: str | Path,
    store_base: str | Path,
    *,
    run_id: str = "",
    approval_id: str = "",
    max_entry_bytes: int | None = None,
    max_total_bytes: int | None = None,
) -> PreimageSnapshot:
    """Capture the pre-image of ``proposal``'s declared targets under ``target_root``.

    Called *before* the mutation. Every declared path is re-confined here rather than trusted
    from validation earlier in the call chain — this module writes to disk, so it re-derives
    its own safety. Anything that cannot be captured completely and safely refuses the whole
    snapshot: an unconfined path, a symlink, a directory, a device node, a file over the entry
    ceiling, or a set over the total ceiling.

    The snapshot id is generated here. A caller chooses the store *base* and nothing else, so
    no caller can direct a snapshot outside the state directory it was given.
    """
    target_root = Path(target_root)
    base = Path(store_base)
    # Resolved at call time, not bound as defaults, so the ceilings stay one authority.
    max_entry_bytes = MAX_ENTRY_BYTES if max_entry_bytes is None else max_entry_bytes
    max_total_bytes = MAX_TOTAL_BYTES if max_total_bytes is None else max_total_bytes
    edits = list(getattr(proposal, "edits", ()))
    if not edits:
        raise PreimageError(R_NO_TARGETS, "the proposal declares no mutation targets")

    planned: list[PreimageEntry] = []
    total = 0
    for edit in edits:
        rel = edit.path
        if not _is_confined(rel) or not _resolves_within(target_root, rel):
            raise PreimageError(R_UNCONFINED, f"{rel!r} escapes the mutation root")
        target = target_root / rel
        if edit.kind == KIND_CREATE or not target.exists():
            # An addition has no prior bytes. Recording "did not exist" is what makes the
            # create reversible at all: reversing it means removing the file.
            planned.append(PreimageEntry(path=rel, existed=False))
            continue
        if target.is_symlink() or not target.is_file():
            raise PreimageError(
                R_NOT_REGULAR, f"{rel!r} is a symlink or not a regular file"
            )
        size = target.stat().st_size
        if size > max_entry_bytes:
            raise PreimageError(
                R_ENTRY_TOO_LARGE, f"{rel!r} is {size} bytes, over the {max_entry_bytes} limit"
            )
        total += size
        if total > max_total_bytes:
            raise PreimageError(
                R_SNAPSHOT_TOO_LARGE,
                f"pre-image would exceed the {max_total_bytes}-byte snapshot limit",
            )
        planned.append(
            PreimageEntry(path=rel, existed=True, digest=_sha256_file(target), size=size)
        )

    snapshot_id = "pre-" + uuid.uuid4().hex
    manifest = {
        "schema": SNAPSHOT_SCHEMA,
        "snapshot_id": snapshot_id,
        "run_id": run_id,
        "approval_id": approval_id,
        "entries": [e.to_mapping() for e in planned],
    }

    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PreimageError(R_STORE_UNUSABLE, f"snapshot store unusable: {exc}") from exc
    final = base / snapshot_id
    if final.exists():  # pragma: no cover - a uuid4 collision
        raise PreimageError(R_ALREADY_EXISTS, f"snapshot {snapshot_id!r} already exists")

    # Build under a temporary name and rename into place, so a crash mid-capture can never
    # leave a directory that looks like a complete pre-image.
    staging = base / f".{snapshot_id}.partial"
    try:
        (staging / BLOBS_DIR).mkdir(parents=True)
        for entry in planned:
            if not entry.existed:
                continue
            shutil.copyfile(target_root / entry.path, staging / BLOBS_DIR / _blob_name(entry))
        (staging / MANIFEST_NAME).write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        os.replace(staging, final)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise PreimageError(R_STORE_UNUSABLE, f"pre-image could not be written: {exc}") from exc

    snapshot = PreimageSnapshot(
        snapshot_id=snapshot_id,
        root=final,
        entries=tuple(planned),
        digest=manifest_digest(manifest),
        run_id=run_id,
        approval_id=approval_id,
    )
    snapshot.verify()   # a snapshot is only a snapshot once it re-derives
    return snapshot


def load_preimage(store_base: str | Path, snapshot_id: str) -> PreimageSnapshot:
    """Read back a captured snapshot and re-verify it; fail closed on any mismatch."""
    base = Path(store_base)
    if not _is_confined(snapshot_id) or "/" in snapshot_id or snapshot_id.startswith("."):
        raise PreimageError(R_UNCONFINED, f"{snapshot_id!r} is not a snapshot id")
    root = base / snapshot_id
    if not root.is_dir():
        raise PreimageError(R_SNAPSHOT_CORRUPT, f"no snapshot {snapshot_id!r}")
    manifest = _read_manifest(root)
    try:
        entries = tuple(
            PreimageEntry(
                path=e["path"], existed=bool(e["existed"]),
                digest=e.get("digest", ""), size=int(e.get("size", 0)),
            )
            for e in manifest["entries"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PreimageError(R_SNAPSHOT_CORRUPT, f"manifest is malformed: {exc}") from exc
    snapshot = PreimageSnapshot(
        snapshot_id=manifest.get("snapshot_id", snapshot_id),
        root=root,
        entries=entries,
        digest=manifest_digest(manifest),
        run_id=manifest.get("run_id", ""),
        approval_id=manifest.get("approval_id", ""),
    )
    snapshot.verify()
    return snapshot


def restore_into(snapshot: PreimageSnapshot, target_root: str | Path) -> list[str]:
    """The reversibility **primitive**: put ``target_root`` back to the captured pre-image.

    This is a write. It carries **no authority of its own** and is deliberately reachable
    from nothing in the governed path — no approval, no reservation, no signed outcome, no
    caller outside this module and its tests. Step 7C.3B is where an owner-approved,
    reserved, independently-verified rollback wraps it; until then the only thing that calls
    this is a test proving byte-exact restoration is *possible*.

    Fail-closed and ordered so a failure cannot half-restore silently: the snapshot is
    re-verified first, every path is re-confined against the destination, and only then is
    anything written. Returns the relative paths it touched.
    """
    target_root = Path(target_root)
    snapshot.verify()
    for entry in snapshot.entries:
        if not _is_confined(entry.path) or not _resolves_within(target_root, entry.path):
            raise PreimageError(
                R_UNCONFINED, f"{entry.path!r} escapes the restore root"
            )

    touched: list[str] = []
    for entry in snapshot.entries:
        target = target_root / entry.path
        if not entry.existed:
            # It did not exist before the mutation, so reversing means it must not exist now.
            if target.is_file() or target.is_symlink():
                target.unlink()
                touched.append(entry.path)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(snapshot.root / BLOBS_DIR / _blob_name(entry), target)
        touched.append(entry.path)
    return sorted(touched)
