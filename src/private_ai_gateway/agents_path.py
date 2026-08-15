"""Make the repo's own ``agents/`` packages win over anything installed with the same name.

``openclaw`` is not a reserved name. An unrelated package by that name installed in the
environment shadows this repo's verifier, and the failure is quiet in the worst way: the test
suite passes (conftest puts ``agents/`` on ``sys.path`` first) while a real gateway process
raises ``ImportError`` from inside the stranger's ``__init__`` and returns a 500. That is how
``/v1/trust-history`` shipped broken — green in CI, dead on a developer machine that happened
to have the other package installed.

So the repo's ``agents/`` directory is **prepended**, not appended, and the check is whether
*this* package is the one that resolves — not merely whether the name imports.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def agents_dir() -> Path | None:
    """Locate this repo's ``agents/`` directory, or ``None`` if it cannot be found."""
    candidates = []
    env = os.environ.get("PRIVATE_AI_AGENTS_PATH")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.cwd() / "agents")
    # src/private_ai_gateway/agents_path.py -> <repo>/agents
    candidates.append(Path(__file__).resolve().parents[2] / "agents")
    for candidate in candidates:
        if (candidate / "openclaw" / "evidence.py").exists():
            return candidate
    return None


def ensure_repo_agents_first() -> None:
    """Prepend the repo's ``agents/`` to ``sys.path`` and evict a shadowing import.

    Prepending alone is not enough once a same-named module is already in
    ``sys.modules`` — a later import would return the stranger from cache. Any cached
    ``openclaw`` that does not live under this repo is therefore dropped so the next import
    resolves here.
    """
    directory = agents_dir()
    if directory is None:
        return
    path = str(directory)
    if sys.path and sys.path[0] == path:
        pass
    else:
        while path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)

    cached = sys.modules.get("openclaw")
    origin = getattr(cached, "__file__", "") or ""
    if cached is not None and not origin.startswith(path):
        for name in [n for n in sys.modules if n == "openclaw" or n.startswith("openclaw.")]:
            del sys.modules[name]
