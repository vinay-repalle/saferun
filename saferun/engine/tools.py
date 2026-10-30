"""Controlled execution of external analysis tools (Semgrep, OSV-Scanner).

These tools are *analyzers*: they read a sanitized copy of the project, they never run project code. Even so
they parse untrusted input, so they get: argv only (no shell), an absolute executable path, a minimal
environment, a private HOME, a new process group killed as a whole on timeout, and a hard output cap.
Failure to run is reported as ToolUnavailable / a ToolRun flag - never as an empty "clean" output.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MAX_ARGS, MAX_ARG_LEN = 256, 4096
DEFAULT_MAX_OUTPUT = 8 * 1024 * 1024
_BASE_ENV = ("PATH", "LANG", "LC_ALL", "TZ")
_NET_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
            "SSL_CERT_FILE", "SSL_CERT_DIR")


class ToolUnavailable(RuntimeError):
    """The executable is missing or cannot be started."""


@dataclass
class ToolRun:
    argv: list[str]
    exit_code: int | None        # None when killed (timeout / output cap)
    stdout: str
    stderr: str
    timed_out: bool = False
    output_truncated: bool = False   # output cap hit: the process was killed, output is incomplete
    duration_s: float = 0.0
    cancelled: bool = False          # the caller's cancel event fired (server shutdown): the process was interrupted/killed


# Signature of the injectable runner; checks take one so tests can substitute canned results.
ToolRunner = Callable[..., ToolRun]


def find_tool(name: str) -> str | None:
    """Absolute path of `name` on PATH, or None."""
    p = shutil.which(name)
    return os.path.abspath(p) if p else None


def validate_argv(argv) -> list[str]:
    if (not isinstance(argv, (list, tuple)) or not argv or len(argv) > MAX_ARGS
            or not all(isinstance(a, str) and len(a) <= MAX_ARG_LEN and "\0" not in a for a in argv)
            or not argv[0] or not os.path.isabs(argv[0])):
        raise ValueError("argv must be a list of strings (NUL-free) starting with an absolute executable path")
    return list(argv)


def build_env(home: Path, network: bool = False, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal environment: no inherited credentials/tokens. Proxy/cert variables only if `network`."""
    env = {k: os.environ[k] for k in _BASE_ENV if k in os.environ}
    if network:
        env.update({k: os.environ[k] for k in _NET_ENV if k in os.environ})
    env.update(HOME=str(home), XDG_CACHE_HOME=str(home / "cache"), XDG_CONFIG_HOME=str(home / "config"),
               TMPDIR=str(home))
    env.update(extra or {})
    return env


def _drain(stream, cap: int, buf: bytearray, over: threading.Event) -> None:
    while chunk := stream.read(65536):
        room = cap - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            over.set()


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _interrupt_group(proc: subprocess.Popen) -> None:
    """SIGINT to the process group: lets a SafeRun CLI worker run its own cleanup (container, workspace) before it exits."""
    try:
        os.killpg(proc.pid, signal.SIGINT)
    except (ProcessLookupError, PermissionError):
        pass


def run_tool(argv: list[str], *, cwd: Path, env: dict[str, str], timeout_s: float,
             max_output: int = DEFAULT_MAX_OUTPUT, cancel: threading.Event | None = None,
             cancel_grace_s: float = 15.0) -> ToolRun:
    """Run `argv` (absolute executable, no shell). Raises ToolUnavailable if it cannot be started.

    `cancel` (optional): when set, the process group gets SIGINT, then SIGKILL after `cancel_grace_s`; the result
    has `cancelled=True` and no exit code (the run is never usable as a verdict)."""
    argv = validate_argv(argv)
    if not (timeout_s > 0):
        raise ValueError("timeout_s must be positive")
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    except OSError as e:
        raise ToolUnavailable(f"cannot start {argv[0]}: {e}") from e
    out, err, over = bytearray(), bytearray(), threading.Event()
    readers = [threading.Thread(target=_drain, args=(s, max_output, b, over), daemon=True)
               for s, b in ((proc.stdout, out), (proc.stderr, err))]
    for t in readers:
        t.start()
    timed_out = cancelled = False
    deadline = t0 + timeout_s
    try:
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                cancelled = True
                _interrupt_group(proc)
                grace_end = time.monotonic() + cancel_grace_s
                while proc.poll() is None and time.monotonic() < grace_end:
                    time.sleep(0.02)
                _kill_group(proc)   # also reaps anything the interrupted process left in its group
                break
            if over.is_set():
                _kill_group(proc)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _kill_group(proc)
                break
            time.sleep(0.02)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            proc.wait(timeout=10)
    finally:
        for t in readers:
            t.join(timeout=5)
        for s in (proc.stdout, proc.stderr):
            s.close()
    return ToolRun(
        argv=argv, exit_code=None if (timed_out or cancelled or over.is_set()) else proc.returncode,
        stdout=out.decode("utf-8", "replace"), stderr=err.decode("utf-8", "replace"),
        timed_out=timed_out, output_truncated=over.is_set(), duration_s=time.monotonic() - t0,
        cancelled=cancelled,
    )
