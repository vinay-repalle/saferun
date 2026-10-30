"""Path normalisation for untrusted tool output."""
from __future__ import annotations

import posixpath
from pathlib import Path

from .model import clean_text


CONTAINER_ROOT = "/workspace"   # where the analyzer container sees the project; tools running there report paths under it


def rel_path(value, root: Path) -> str | None:
    """A tool-reported path as a clean, relative, posix path inside `root` (or the container's /workspace); None if it is not one."""
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    p = value
    if posixpath.isabs(p):
        for r in (str(root.resolve()) + "/", str(root) + "/", CONTAINER_ROOT + "/"):
            if p.startswith(r):
                p = p[len(r):]
                break
        else:
            return None
    p = posixpath.normpath(p)
    if p in (".", "") or p == ".." or p.startswith("../") or posixpath.isabs(p):
        return None
    return clean_text(p, 300)
