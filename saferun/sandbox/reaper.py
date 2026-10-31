"""Recovery of containers and workspaces abandoned by a crashed SafeRun process.

Safety rules: only objects SafeRun itself created are considered (label +
name prefix for containers; name prefix, ownership, real directory for
workspaces), and live runs are never touched: containers carry a deadline
label (timeout + grace + margin) and workspaces are protected by a flock.
"""
from __future__ import annotations

import errno
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import hostos
from . import docker as dk
from .config import CONTAINER_LABEL, DEADLINE_LABEL
from .workspace import LOCK_NAME, WS_PREFIX

if not hostos.IS_WINDOWS:
    import fcntl

NO_LOCK_MIN_AGE_S = 600  # a workspace with no lock file is only reaped once this old


@dataclass
class ReapReport:
    containers: list[str] = field(default_factory=list)
    workspaces: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _reap_containers(now: float, report: ReapReport) -> None:
    try:
        r = dk.docker("ps", "-a", "--filter", f"label={CONTAINER_LABEL}",
                      "--format", '{{.Names}}\t{{.Label "' + DEADLINE_LABEL + '"}}')
    except dk.SandboxError as e:  # daemon hung or the CLI missing: report it, but still reap workspaces
        report.errors.append(f"could not list containers: {e}")
        return
    if r.returncode != 0:  # daemon down: say so, do not pretend there was nothing to reap
        report.errors.append(f"could not list containers: {r.stderr.strip()}")
        return
    for line in r.stdout.splitlines():
        name, _, raw = line.partition("\t")
        if not name.startswith("saferun-"):
            continue
        try:
            expired = float(raw) < now
        except ValueError:
            expired = True  # our label but no usable deadline: treat as abandoned
        if not expired:
            continue
        try:
            if dk.force_remove(name):
                report.containers.append(name)
            else:
                report.errors.append(f"container {name} still present after removal")
        except Exception as e:
            report.errors.append(f"container {name}: {e}")


def _reap_workspaces_windows(now: float, tmp_root: Path, report: ReapReport) -> None:
    """Same rules as the POSIX version: our name prefix, a real directory (no reparse point) owned by this user, and a lock file that
    nobody holds (the owner keeps it open with share mode 0, so it cannot be opened while the run is alive)."""
    for entry in os.scandir(tmp_root):
        if not entry.name.startswith(WS_PREFIX):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False) or st.st_file_attributes & 0x400:
                continue
            if not hostos.owned_by_current_user(Path(entry.path)):
                continue
            state = hostos.workspace_lock_state(os.path.join(entry.path, LOCK_NAME))
            if state == "busy" or (state == "absent" and now - st.st_mtime < NO_LOCK_MIN_AGE_S):
                continue
            shutil.rmtree(hostos.long_path(entry.path), onexc=hostos.rmtree_onexc)
            report.workspaces.append(entry.name)
        except OSError as e:
            report.errors.append(f"workspace {entry.name}: {e}")


def _reap_workspaces(now: float, tmp_root: Path, report: ReapReport) -> None:
    if hostos.IS_WINDOWS:
        return _reap_workspaces_windows(now, tmp_root, report)
    for entry in os.scandir(tmp_root):
        if not entry.name.startswith(WS_PREFIX) or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
            continue
        st = entry.stat(follow_symlinks=False)
        if st.st_uid != os.getuid():
            continue
        try:
            fd = os.open(os.path.join(entry.path, LOCK_NAME), os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            if now - st.st_mtime < NO_LOCK_MIN_AGE_S:
                continue  # may be mid-creation
            fd = None
        except OSError as e:
            report.errors.append(f"workspace {entry.name}: {e}")
            continue
        try:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as e:
                    if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                        continue  # owner is alive
                    raise
            shutil.rmtree(entry.path)
            report.workspaces.append(entry.name)
        except OSError as e:
            report.errors.append(f"workspace {entry.name}: {e}")
        finally:
            if fd is not None:
                os.close(fd)


def reap_orphans(now: float | None = None, tmp_root: Path | None = None) -> ReapReport:
    """Remove abandoned SafeRun containers and workspaces. `now`/`tmp_root` are for tests."""
    now = time.time() if now is None else now
    report = ReapReport()
    _reap_containers(now, report)
    _reap_workspaces(now, Path(tmp_root or tempfile.gettempdir()), report)
    return report
