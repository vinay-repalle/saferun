"""Starting, interrupting and killing a whole process tree.

POSIX: a new session / process group, signalled as a group (exactly what SafeRun always did).
Windows: the child starts SUSPENDED, is put into a kill-on-close job object and only then resumed, so it cannot spawn a process that
escapes the job; killing the job ends the whole tree, and it also dies if SafeRun itself dies. Interrupt is CTRL_BREAK to the process group.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    from . import _win

    _CREATE_SUSPENDED = 0x00000004


def popen_kwargs() -> dict:
    if IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | _CREATE_SUSPENDED, "close_fds": True}
    return {"start_new_session": True, "close_fds": True}


def after_spawn(proc: subprocess.Popen) -> None:
    """Windows: confine `proc` to a job and let it run. Raises OSError (after killing it) if that is impossible. POSIX: nothing to do."""
    if not IS_WINDOWS:
        return
    job = None
    try:
        job = _win.create_kill_on_close_job()
        _win.assign_to_job(job, int(proc._handle))
        proc._saferun_job = job
        _win.resume_process(int(proc._handle))
    except BaseException:
        try:
            proc.kill()
        except OSError:
            pass
        if job:
            _win.close(job)
        raise


def kill_tree(proc: subprocess.Popen) -> None:
    if IS_WINDOWS:
        job = getattr(proc, "_saferun_job", None)
        if job:
            _win.terminate_job(job)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def interrupt_tree(proc: subprocess.Popen) -> None:
    if IS_WINDOWS:
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        except (OSError, ValueError):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass


def release(proc: subprocess.Popen) -> None:
    """Windows: close the job handle, which also ends anything the finished process left behind. POSIX: nothing."""
    job = getattr(proc, "_saferun_job", None)
    if IS_WINDOWS and job:
        proc._saferun_job = None
        _win.close(job)
