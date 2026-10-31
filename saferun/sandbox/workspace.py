"""Temporary, sanitized copy of an untrusted project directory."""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .. import hostos
from .config import SandboxError, SensitivePolicy, SkippedEntry, WithheldEntry, WorkspaceLimits
from .secrets import Redactor

if hostos.IS_WINDOWS:
    from .copy_windows import copy_tree
else:
    import fcntl

    from .copy import copy_tree

WS_PREFIX = "saferun-ws-"
LOCK_NAME = ".lock"  # flock held for the life of a run; the kernel drops it if we die


@dataclass
class Workspace:
    root: Path
    project: Path  # the only thing ever mounted into a container
    skipped: list[SkippedEntry] = field(default_factory=list)
    withheld: list[WithheldEntry] = field(default_factory=list)
    redactor: Redactor = field(default_factory=Redactor, repr=False)  # holds secret values: never log
    entries_scanned: int = 0
    copied_files: int = 0
    copied_dirs: int = 0
    copied_bytes: int = 0
    _lock_fd: int | None = None

    def cleanup(self) -> None:
        """Delete the workspace and release the lock. Raises if it is still there."""
        try:
            if hostos.IS_WINDOWS and self._lock_fd is not None:   # an open exclusive lock file cannot be deleted on Windows
                os.close(self._lock_fd)
                self._lock_fd = None
            shutil.rmtree(hostos.long_path(self.root) if hostos.IS_WINDOWS else self.root, ignore_errors=False,
                          **({"onexc": hostos.rmtree_onexc} if hostos.IS_WINDOWS else {}))
        except FileNotFoundError:
            pass
        except OSError as e:
            raise SandboxError(f"could not delete workspace {self.root}: {e}") from e
        finally:
            if self._lock_fd is not None:
                os.close(self._lock_fd)
                self._lock_fd = None
        if self.root.exists():
            raise SandboxError(f"workspace {self.root} still exists after cleanup")


def create_workspace(src: Path, limits: WorkspaceLimits | None = None,
                     policy: SensitivePolicy | None = None) -> Workspace:
    """Copy `src` into a fresh temp dir. Symlinks, special files and external hard links are skipped, and
    sensitive files withheld; both are recorded."""
    try:
        src = Path(src).resolve()
        is_dir = src.is_dir()
    except (TypeError, ValueError, OSError, RuntimeError) as e:  # NUL byte, symlink loop, bad type...
        raise SandboxError(f"invalid project path {src!r}: {e}") from e
    if not is_dir:
        raise SandboxError(f"not a directory: {src}")
    root = Path(tempfile.mkdtemp(prefix=WS_PREFIX))
    ws = Workspace(root=root, project=root / "project")
    try:
        if hostos.IS_WINDOWS:   # POSIX: the directory is 0700 from mkdtemp; Windows: protected ACL for this user (and SYSTEM) only
            hostos.restrict_to_owner(root)
        if hostos.IS_WINDOWS:   # held with share mode 0: the Windows counterpart of the flock below (released by the OS if we die)
            ws._lock_fd = hostos.create_workspace_lock(root / LOCK_NAME)
        else:
            ws._lock_fd = os.open(root / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            fcntl.flock(ws._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ws.project.mkdir(mode=0o755)
        r = copy_tree(str(src), str(ws.project), limits or WorkspaceLimits(), policy)
        ws.skipped, ws.withheld, ws.redactor = r.skipped, r.withheld, r.redactor
        ws.entries_scanned, ws.copied_files, ws.copied_dirs, ws.copied_bytes = (
            r.entries_scanned, r.copied_files, r.copied_dirs, r.copied_bytes)
        ws.project.chmod(0o755)
        root.chmod(0o711)  # traversable by the container user, not listable
    except BaseException:
        try:
            ws.cleanup()
        except SandboxError:
            pass  # keep the original exception; the reaper will collect the leftovers
        raise
    return ws
