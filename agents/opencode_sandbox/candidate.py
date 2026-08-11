"""Track D — the strict candidate-proposal adapter.

A local model's response is **data**, never authority and never a command. This module is
the deterministic boundary that decides whether that data is even a *candidate*: it parses
strictly, refuses anything malformed or out of scope, and hands what survives to the
existing :mod:`opencode_sandbox.apply` proposal schema. Nothing here writes a file, runs a
command, or acquires an approval.

Why strict where :func:`opencode_sandbox.apply.parse_proposal` is lenient: that parser reads
a proposal an operator already curated, so tolerant defaults are fine. This one reads
*untrusted generated text*, so every tolerance is an opportunity to smuggle scope. The rules:

  * **Valid JSON only.** A response with prose wrapped around the JSON is refused, not
    salvaged — "helpfully" extracting a JSON island from model text is exactly how an
    unintended object gets applied.
  * **Known fields only.** Unknown keys at either level are refused rather than ignored, so
    an invented ``command`` / ``run`` / ``exec`` field can never be silently dropped and
    later honoured by a more permissive reader. The model has no shell, and no field it
    emits can grant one.
  * **Declared scope only.** Optional ``allowed_paths`` refuses an edit touching a file the
    objective never declared.
  * **Bounded.** Oversized responses are refused before parsing.

A candidate that passes is still only a candidate: applying it continues to require the
existing owner-issued, hash-bound approval, and the sandbox's own confinement and manifest
verification still run. This module *narrows* what may be proposed; it grants nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from opencode_sandbox import apply as act

# A generated response larger than this is refused unparsed. Deliberately generous enough
# for a real multi-file change and far below anything that could exhaust memory.
MAX_CANDIDATE_BYTES = 256 * 1024

# Only these keys may appear. Anything else — notably an invented command/exec/shell field —
# is a refusal, never an ignored extra.
ALLOWED_TOP_LEVEL = frozenset({"edits", "rationale", "autonomy_level"})
ALLOWED_EDIT_FIELDS = frozenset({"path", "kind", "new_content"})

# Refusal reason codes. Stable strings so evaluation traces stay comparable over time.
R_OVERSIZE = "oversize"
R_NOT_JSON = "not_json"
R_NOT_OBJECT = "not_object"
R_UNKNOWN_FIELD = "unknown_field"
R_MISSING_EDITS = "missing_edits"
R_EMPTY_PATCH = "empty_patch"
R_MALFORMED_EDIT = "malformed_edit"
R_UNKNOWN_KIND = "unknown_kind"
R_ABSOLUTE_PATH = "absolute_path"
R_PATH_TRAVERSAL = "path_traversal"
R_UNDECLARED_FILE = "undeclared_file"
R_CONFINEMENT = "confinement_violation"


@dataclass(frozen=True)
class CandidateResult:
    """The adapter's verdict on one generated response.

    ``ok`` means "a well-formed, in-scope, confined candidate" — never "safe to apply".
    """

    ok: bool
    reason_code: str = ""
    detail: str = ""
    proposal: act.ChangeProposal | None = None
    declared_files: tuple[str, ...] = ()
    violations: tuple[str, ...] = field(default=())

    @property
    def refused(self) -> bool:
        return not self.ok


def _refuse(code: str, detail: str = "", violations=()) -> CandidateResult:
    return CandidateResult(False, code, detail, None, (), tuple(violations))


def _check_edit_shape(raw) -> str | None:
    """Structural check on one edit mapping; returns a reason code or ``None``."""
    if not isinstance(raw, dict):
        return R_MALFORMED_EDIT
    unknown = set(raw) - ALLOWED_EDIT_FIELDS
    if unknown:
        return R_UNKNOWN_FIELD
    path, kind = raw.get("path"), raw.get("kind")
    if not isinstance(path, str) or not path:
        return R_MALFORMED_EDIT
    if not isinstance(kind, str) or kind not in act.KINDS:
        return R_UNKNOWN_KIND
    content = raw.get("new_content")
    if content is not None and not isinstance(content, str):
        return R_MALFORMED_EDIT
    return None


def _path_refusal(path: str) -> str | None:
    """Absolute paths and traversal are distinct refusals so traces stay diagnosable."""
    if path.startswith("/") or path.startswith("~") or (len(path) > 1 and path[1] == ":"):
        return R_ABSOLUTE_PATH
    if ".." in path.replace("\\", "/").split("/"):
        return R_PATH_TRAVERSAL
    return None


def parse_candidate(
    text: str,
    *,
    root,
    allowed_paths=None,
    max_bytes: int = MAX_CANDIDATE_BYTES,
) -> CandidateResult:
    """Strictly parse a generated response into a candidate :class:`ChangeProposal`.

    ``root`` is the tree the candidate is validated *against* — it is only read (existence
    and path-resolution checks); nothing is written. ``allowed_paths``, when given, is the
    set of files the objective declared, and any edit outside it is refused.
    """
    if not isinstance(text, str):
        return _refuse(R_NOT_JSON, "candidate response was not text")
    if len(text.encode("utf-8", "ignore")) > max_bytes:
        return _refuse(R_OVERSIZE, f"candidate exceeds {max_bytes} bytes")

    # Valid JSON *only* — a response with prose around the JSON is refused, never salvaged.
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        return _refuse(R_NOT_JSON, f"response is not valid JSON: {exc}")
    if not isinstance(data, dict):
        return _refuse(R_NOT_OBJECT, f"top level is {type(data).__name__}, not an object")

    unknown = sorted(set(data) - ALLOWED_TOP_LEVEL)
    if unknown:
        # Notably where an invented command/exec/shell field lands. The model produces data;
        # it never gets to name an operation the adapter did not already understand.
        return _refuse(R_UNKNOWN_FIELD, f"unknown top-level field(s): {', '.join(unknown)}")

    raw_edits = data.get("edits")
    if raw_edits is None:
        return _refuse(R_MISSING_EDITS, "candidate declares no 'edits'")
    if not isinstance(raw_edits, list):
        return _refuse(R_MISSING_EDITS, "'edits' is not a list")
    if not raw_edits:
        return _refuse(R_EMPTY_PATCH, "candidate declares an empty edit list")

    for raw in raw_edits:
        code = _check_edit_shape(raw)
        if code is not None:
            return _refuse(code, f"malformed edit: {raw!r}"[:200])
        path = raw["path"]
        code = _path_refusal(path)
        if code is not None:
            return _refuse(code, f"edit path {path!r} is not confined")
        if allowed_paths is not None and path not in set(allowed_paths):
            return _refuse(R_UNDECLARED_FILE, f"edit touches undeclared file {path!r}")

    rationale = data.get("rationale", "")
    if not isinstance(rationale, str):
        return _refuse(R_MALFORMED_EDIT, "'rationale' is not a string")

    # Shape is sound: build through the *existing* proposal schema rather than a parallel
    # one, so a candidate is exactly the object the sandbox act step already understands.
    proposal = act.ChangeProposal(
        edits=[
            act.FileEdit(path=e["path"], kind=e["kind"], new_content=e.get("new_content"))
            for e in raw_edits
        ],
        rationale=rationale,
        autonomy_level=act.autonomy.parse_level(
            data.get("autonomy_level"), act.REQUIRED_APPROVAL_LEVEL
        ),
        source="local-engineering-candidate",
    )

    # Finally the sandbox's own confinement/consistency rules — one definition, reused.
    violations = act.validate(proposal, root)
    if violations:
        return _refuse(R_CONFINEMENT, "; ".join(violations)[:400], violations)

    return CandidateResult(
        ok=True,
        proposal=proposal,
        declared_files=tuple(proposal.declared_files),
    )
