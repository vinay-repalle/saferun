"""Path normalisation for untrusted tool output."""
from __future__ import annotations

import ntpath
import posixpath
from pathlib import Path, PureWindowsPath

from .. import hostos
from .model import clean_text


CONTAINER_ROOT = "/workspace"   # where the analyzer container sees the project; tools running there report paths under it


def rel_path(value, root: Path) -> str | None:
    """A tool-reported path as a clean, relative, posix path inside `root` (or the container's /workspace); None if it is not one."""
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    p = value
    if hostos.IS_WINDOWS and ntpath.splitdrive(p)[0]:
        # A drive-letter path can only be a host path (the analyzer container reports /workspace/...). Strip the project root, compare
        # case-insensitively like NTFS, and refuse every other drive path.
        for r in (root.resolve(), root):
            try:
                p = PureWindowsPath(p).relative_to(PureWindowsPath(r)).as_posix()
                break
            except ValueError:
                continue
        else:
            return None
    elif posixpath.isabs(p):
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
