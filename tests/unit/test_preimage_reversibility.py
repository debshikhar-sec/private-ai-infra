"""Step 7C.3A — the reversibility foundation, and the audit that made it necessary.

The first two tests are the audit itself, kept executable rather than written down: they
demonstrate that the pre-7C.3A apply artifacts **cannot** reverse anything. Everything after
holds the new pre-image to the properties that make a future rollback honest:

  * byte-exact restoration of updates and deletions, and removal of creations;
  * a snapshot is only a snapshot once it re-derives — corruption fails closed, it does not
    degrade into a weaker snapshot;
  * bounded, confined, atomic, and never caller-placed;
  * contents never reach signed evidence, only identity and digests;
  * a capture that cannot complete **rejects the apply** rather than quietly producing an
    irreversible one;
  * historical applies gain nothing: no pre-image is fabricated for them.

And the boundary: `restore_into` is a write primitive with no authority. These tests assert
structurally that nothing in the governed path reaches it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from opencode_sandbox import preimage
from opencode_sandbox.apply import (
    APPLIED,
    REJECTED,
    Approval,
    ChangeProposal,
    FileEdit,
    apply_proposal,
)
from opencode_sandbox.preimage import (
    PreimageError,
    capture_preimage,
    load_preimage,
    restore_into,
)

APPROVED = Approval("owner", "reviewed")


@pytest.fixture
def tree(tmp_path):
    """A small target tree: one file to update, one to delete, one untouched."""
    root = tmp_path / "target"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "keep.py").write_text("UNTOUCHED\n", encoding="utf-8")
    (root / "pkg" / "edit.py").write_text("original edit\n", encoding="utf-8")
    (root / "pkg" / "gone.py").write_text("about to be deleted\n", encoding="utf-8")
    return root


@pytest.fixture
def store(tmp_path):
    return tmp_path / "state" / "preimage"


def _proposal():
    return ChangeProposal(
        edits=[
            FileEdit("pkg/edit.py", "modify", "rewritten\n"),
            FileEdit("pkg/gone.py", "delete", None),
            FileEdit("pkg/added.py", "create", "brand new\n"),
        ],
        rationale="exercise all three edit kinds",
        autonomy_level=3,
    )


def _contents(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): p.read_text(encoding="utf-8")
        for p in sorted(root.rglob("*")) if p.is_file()
    }


# --- the audit: what the existing artifacts actually retain -----------------------------

def test_the_pre_7c3a_apply_record_retains_no_content_or_hashes(tree, tmp_path):
    """Audit, executable: the shipped record cannot reverse anything.

    ``_apply_and_verify`` hashes the whole tree before *and* after, but only the derived set
    difference survives. The record carries bare paths — no hashes, no content, and no way to
    tell a create from a delete.
    """
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED)
    assert report.status == APPLIED
    record = report.to_record()

    assert record["changed_files"] == ["pkg/added.py", "pkg/edit.py", "pkg/gone.py"]
    blob = json.dumps(record)
    assert "original edit" not in blob            # no prior content
    assert "about to be deleted" not in blob
    assert "sha256" not in blob                   # not even prior hashes
    assert "preimage" not in record               # and no snapshot, by default


def test_an_apply_without_a_store_stays_byte_identical_to_before(tree, tmp_path):
    """The default path is unchanged, so no historical run gains a pre-image."""
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED)
    assert report.preimage is None
    assert set(report.to_record()) == {
        "component", "status", "autonomy_level", "autonomy_name", "approver", "committed",
        "declared_files", "changed_files", "violations", "generated_at", "detail",
    }


# --- byte-exact restoration --------------------------------------------------------------

def test_a_captured_pre_image_restores_the_sandbox_byte_for_byte(tree, tmp_path, store):
    sandbox = tmp_path / "sbx"
    report = apply_proposal(
        _proposal(), tree, sandbox, approval=APPROVED, preimage_store=store,
        run_id="run-1", approval_id="appr-1",
    )
    assert report.status == APPLIED
    mutated = _contents(sandbox)
    assert mutated["pkg/edit.py"] == "rewritten\n"
    assert "pkg/gone.py" not in mutated
    assert mutated["pkg/added.py"] == "brand new\n"

    snapshot = load_preimage(store, report.preimage["snapshot_id"])
    restored = restore_into(snapshot, sandbox)

    assert restored == ["pkg/added.py", "pkg/edit.py", "pkg/gone.py"]
    assert _contents(sandbox) == _contents(tree)          # byte-exact, whole tree
    assert (sandbox / "pkg" / "keep.py").read_text() == "UNTOUCHED\n"
    assert not (sandbox / "pkg" / "added.py").exists()    # a creation is *removed*


def test_restoration_is_byte_exact_for_binary_and_unicode_content(tmp_path, store):
    root = tmp_path / "target"
    root.mkdir()
    original = "héllo — ünicode\r\nwith CRLF and a trailing space \n\x00embedded nul\n"
    (root / "odd.txt").write_text(original, encoding="utf-8", newline="")
    raw = (root / "odd.txt").read_bytes()

    proposal = ChangeProposal(edits=[FileEdit("odd.txt", "modify", "flattened\n")],
                              autonomy_level=3)
    sandbox = tmp_path / "sbx"
    report = apply_proposal(proposal, root, sandbox, approval=APPROVED,
                            preimage_store=store)
    assert (sandbox / "odd.txt").read_bytes() != raw

    restore_into(load_preimage(store, report.preimage["snapshot_id"]), sandbox)
    assert (sandbox / "odd.txt").read_bytes() == raw


def test_a_pre_image_survives_being_read_back_from_disk(tree, tmp_path, store):
    """Nothing in the snapshot depends on the process that wrote it."""
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store, run_id="run-9", approval_id="appr-9")
    reloaded = load_preimage(store, report.preimage["snapshot_id"])
    assert reloaded.digest == report.preimage["snapshot_digest"]
    assert reloaded.run_id == "run-9" and reloaded.approval_id == "appr-9"
    assert {e.path for e in reloaded.entries} == {
        "pkg/edit.py", "pkg/gone.py", "pkg/added.py"
    }
    assert next(e for e in reloaded.entries if e.path == "pkg/added.py").existed is False


# --- a snapshot is only a snapshot once it re-derives ------------------------------------

def test_a_tampered_blob_fails_closed(tree, tmp_path, store):
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store)
    snapshot = load_preimage(store, report.preimage["snapshot_id"])
    blob = next((snapshot.root / preimage.BLOBS_DIR).iterdir())
    blob.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(PreimageError) as exc:
        load_preimage(store, report.preimage["snapshot_id"])
    assert exc.value.code == preimage.R_SNAPSHOT_CORRUPT


def test_a_missing_blob_fails_closed(tree, tmp_path, store):
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store)
    snapshot = load_preimage(store, report.preimage["snapshot_id"])
    next((snapshot.root / preimage.BLOBS_DIR).iterdir()).unlink()
    with pytest.raises(PreimageError) as exc:
        snapshot.verify()
    assert exc.value.code == preimage.R_SNAPSHOT_CORRUPT


def test_a_tampered_manifest_fails_closed(tree, tmp_path, store):
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store)
    snapshot = load_preimage(store, report.preimage["snapshot_id"])
    manifest = json.loads((snapshot.root / preimage.MANIFEST_NAME).read_text())
    manifest["entries"][0]["digest"] = "sha256:" + "0" * 64
    (snapshot.root / preimage.MANIFEST_NAME).write_text(json.dumps(manifest))

    with pytest.raises(PreimageError):
        load_preimage(store, report.preimage["snapshot_id"])
    # And the digest recorded in the apply evidence no longer matches the manifest on disk.
    assert preimage.manifest_digest(manifest) != report.preimage["snapshot_digest"]


def test_a_restore_re_verifies_before_writing_anything(tree, tmp_path, store):
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store)
    sandbox = tmp_path / "sbx"
    snapshot = load_preimage(store, report.preimage["snapshot_id"])
    next((snapshot.root / preimage.BLOBS_DIR).iterdir()).unlink()

    before = _contents(sandbox)
    with pytest.raises(PreimageError):
        restore_into(snapshot, sandbox)
    assert _contents(sandbox) == before          # nothing half-restored


def test_a_missing_snapshot_is_refused_not_treated_as_empty(store):
    with pytest.raises(PreimageError) as exc:
        load_preimage(store, "pre-" + "0" * 32)
    assert exc.value.code == preimage.R_SNAPSHOT_CORRUPT


# --- confinement, bounds, placement -------------------------------------------------------

@pytest.mark.parametrize("bad", ["/etc/passwd", "../escape.py", "~/secrets"])
def test_an_unconfined_target_refuses_the_snapshot(tmp_path, store, bad):
    root = tmp_path / "target"
    root.mkdir()
    proposal = ChangeProposal(edits=[FileEdit(bad, "modify", "x")], autonomy_level=3)
    with pytest.raises(PreimageError) as exc:
        capture_preimage(proposal, root, store)
    assert exc.value.code == preimage.R_UNCONFINED


def test_a_symlinked_target_refuses_the_snapshot(tmp_path, store):
    root = tmp_path / "target"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret\n", encoding="utf-8")
    (root / "link.txt").symlink_to(tmp_path / "outside.txt")
    proposal = ChangeProposal(edits=[FileEdit("link.txt", "modify", "x")], autonomy_level=3)
    with pytest.raises(PreimageError) as exc:
        capture_preimage(proposal, root, store)
    assert exc.value.code in (preimage.R_UNCONFINED, preimage.R_NOT_REGULAR)


def test_a_directory_target_refuses_the_snapshot(tmp_path, store):
    root = tmp_path / "target"
    (root / "adir").mkdir(parents=True)
    proposal = ChangeProposal(edits=[FileEdit("adir", "modify", "x")], autonomy_level=3)
    with pytest.raises(PreimageError) as exc:
        capture_preimage(proposal, root, store)
    assert exc.value.code == preimage.R_NOT_REGULAR


def test_an_oversized_file_refuses_the_whole_snapshot(tmp_path, store):
    """A partial pre-image is worse than none: it looks reversible and is not."""
    root = tmp_path / "target"
    root.mkdir()
    (root / "small.txt").write_text("small\n", encoding="utf-8")
    (root / "big.bin").write_bytes(b"x" * 4096)
    proposal = ChangeProposal(
        edits=[FileEdit("small.txt", "modify", "a"), FileEdit("big.bin", "modify", "b")],
        autonomy_level=3,
    )
    with pytest.raises(PreimageError) as exc:
        capture_preimage(proposal, root, store, max_entry_bytes=1024)
    assert exc.value.code == preimage.R_ENTRY_TOO_LARGE
    assert list(store.glob("pre-*")) == []       # nothing partial was left behind


def test_an_oversized_snapshot_is_refused_in_total(tmp_path, store):
    root = tmp_path / "target"
    root.mkdir()
    for i in range(4):
        (root / f"f{i}.txt").write_bytes(b"y" * 500)
    proposal = ChangeProposal(
        edits=[FileEdit(f"f{i}.txt", "modify", "z") for i in range(4)], autonomy_level=3
    )
    with pytest.raises(PreimageError) as exc:
        capture_preimage(proposal, root, store, max_entry_bytes=1024, max_total_bytes=1200)
    assert exc.value.code == preimage.R_SNAPSHOT_TOO_LARGE
    assert list(store.glob("pre-*")) == []


def test_the_snapshot_id_is_generated_never_caller_chosen(tree, tmp_path, store):
    first = capture_preimage(_proposal(), tree, store)
    second = capture_preimage(_proposal(), tree, store)
    assert first.snapshot_id != second.snapshot_id
    assert first.snapshot_id.startswith("pre-")
    # Every snapshot lands directly under the store base the caller was given.
    assert first.root.parent == store and second.root.parent == store


@pytest.mark.parametrize("bad", ["../elsewhere", "/abs", "a/b", ".hidden"])
def test_a_snapshot_id_cannot_be_used_to_read_outside_the_store(store, bad):
    with pytest.raises(PreimageError):
        load_preimage(store, bad)


def test_a_proposal_with_no_targets_is_refused(tmp_path, store):
    with pytest.raises(PreimageError) as exc:
        capture_preimage(ChangeProposal(edits=[]), tmp_path, store)
    assert exc.value.code == preimage.R_NO_TARGETS


# --- what reaches signed evidence ---------------------------------------------------------

def test_signed_evidence_carries_identity_and_digests_but_never_content(tree, tmp_path,
                                                                        store):
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store)
    ev = report.preimage
    assert set(ev) == {"snapshot_id", "snapshot_digest", "entries", "bytes"}
    assert ev["snapshot_digest"].startswith("sha256:")
    assert ev["entries"] == 3

    blob = json.dumps(report.to_record())
    assert "original edit" not in blob
    assert "about to be deleted" not in blob
    assert str(store) not in blob                # no local filesystem layout either


def test_the_apply_record_binds_to_the_snapshot_that_can_reverse_it(tree, tmp_path, store):
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store, run_id="run-7", approval_id="appr-7")
    snapshot = load_preimage(store, report.to_record()["preimage"]["snapshot_id"])
    assert snapshot.digest == report.to_record()["preimage"]["snapshot_digest"]
    assert snapshot.run_id == "run-7"


# --- a capture that cannot complete rejects the apply -------------------------------------

def test_a_failed_capture_rejects_the_apply_rather_than_applying_irreversibly(tmp_path,
                                                                              store):
    root = tmp_path / "target"
    root.mkdir()
    (root / "big.bin").write_bytes(b"x" * 4096)
    proposal = ChangeProposal(edits=[FileEdit("big.bin", "modify", "small")],
                              autonomy_level=3)
    sandbox = tmp_path / "sbx"

    from unittest.mock import patch

    with patch.object(preimage, "MAX_ENTRY_BYTES", 16):
        report = apply_proposal(proposal, root, sandbox, approval=APPROVED,
                                preimage_store=store)

    assert report.status == REJECTED
    assert any("pre-image capture refused" in v for v in report.violations)
    assert report.preimage is None
    assert (sandbox / "big.bin").read_bytes() == b"x" * 4096   # unmutated


def test_the_capture_happens_before_the_first_declared_write(tree, tmp_path, store):
    """Otherwise the 'pre-image' would record the post-state."""
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                            preimage_store=store)
    snapshot = load_preimage(store, report.preimage["snapshot_id"])
    edit = next(e for e in snapshot.entries if e.path == "pkg/edit.py")
    assert edit.digest == preimage._sha256_file(tree / "pkg" / "edit.py")
    assert edit.size == len("original edit\n")


def test_an_unapproved_apply_captures_nothing(tree, tmp_path, store):
    """No authority, no write — and therefore no snapshot to imply one happened."""
    report = apply_proposal(_proposal(), tree, tmp_path / "sbx", preimage_store=store)
    assert report.status == "refused"
    assert report.preimage is None
    assert not store.exists() or list(store.glob("pre-*")) == []


# --- the authority boundary ----------------------------------------------------------------

def test_restore_is_reachable_from_nothing_in_the_governed_path():
    """`restore_into` is a write primitive with no authority; 7C.3B supplies that."""
    repo = Path(__file__).resolve().parents[2]
    hits = sorted(
        str(p.relative_to(repo))
        for base in ("src", "agents")
        for p in (repo / base).rglob("*.py")
        if "restore_into" in p.read_text(encoding="utf-8")
    )
    assert hits == ["agents/opencode_sandbox/preimage.py"]


def test_the_preimage_module_performs_no_rollback_of_its_own(tree, tmp_path, store):
    """Capturing is not reversing: an apply with a store still applies."""
    sandbox = tmp_path / "sbx"
    report = apply_proposal(_proposal(), tree, sandbox, approval=APPROVED,
                            preimage_store=store)
    assert report.status == APPLIED
    assert (sandbox / "pkg" / "edit.py").read_text() == "rewritten\n"
    assert not (sandbox / "pkg" / "gone.py").exists()


def test_the_real_checkout_is_never_touched(tree, tmp_path, store):
    before = _contents(tree)
    apply_proposal(_proposal(), tree, tmp_path / "sbx", approval=APPROVED,
                   preimage_store=store)
    assert _contents(tree) == before
    assert store.resolve().is_relative_to(tmp_path.resolve())


def test_a_crash_mid_capture_leaves_no_directory_that_looks_complete(tree, tmp_path, store,
                                                                     monkeypatch):
    import shutil as shutil_mod

    calls = {"n": 0}
    real_copyfile = shutil_mod.copyfile

    def flaky(src, dst, *a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("disk full")
        return real_copyfile(src, dst, *a, **k)

    monkeypatch.setattr(preimage.shutil, "copyfile", flaky)
    with pytest.raises(PreimageError) as exc:
        capture_preimage(_proposal(), tree, store)
    assert exc.value.code == preimage.R_STORE_UNUSABLE
    assert list(store.glob("pre-*")) == []
    assert list(store.glob(".*partial")) == []
