"""Cleanup and exhaustion hardening of the CLI path: cancellation of analyzer tool runs, the orphan reaper's ownership checks, and a hung Docker daemon.

(Split out of the former Phase 5D test module; the dashboard/API parts were removed together with the dashboard.)
"""
import io
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from saferun.engine.tools import run_tool
from saferun.sandbox import SandboxError, SandboxLimits, reap_orphans, run_sandboxed
from saferun.sandbox import docker as dk
from saferun.sandbox import runner
from saferun.sandbox.workspace import WS_PREFIX


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def wait_for(cond, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_cancel_interrupts_with_sigint_so_the_worker_can_clean_up(tmp_path):
    marker, ready = tmp_path / "cleaned", tmp_path / "ready"
    code = ("import signal,sys,time,pathlib\n"
            f"def h(*a):\n    pathlib.Path({str(marker)!r}).write_text('x'); sys.exit(130)\n"
            "signal.signal(signal.SIGINT, h)\n"
            f"pathlib.Path({str(ready)!r}).write_text('x')\n"
            "time.sleep(60)\n")
    cancel = threading.Event()
    threading.Thread(target=lambda: (wait_for(ready.exists), cancel.set())).start()
    run = run_tool([sys.executable, "-c", code], cwd=tmp_path, env={"PATH": os.environ["PATH"]}, timeout_s=60, cancel=cancel)
    assert run.cancelled and run.exit_code is None and not run.timed_out
    assert marker.exists()                  # the handler ran: this was an interrupt, not an immediate kill


def test_cancel_kills_a_worker_that_ignores_sigint_after_the_grace_period(tmp_path):
    ready = tmp_path / "ready"
    code = ("import signal,time,pathlib\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            f"pathlib.Path({str(ready)!r}).write_text('x')\ntime.sleep(60)\n")
    cancel = threading.Event()
    threading.Thread(target=lambda: (wait_for(ready.exists), cancel.set())).start()
    t0 = time.monotonic()
    run = run_tool([sys.executable, "-c", code], cwd=tmp_path, env={"PATH": os.environ["PATH"]}, timeout_s=60,
                   cancel=cancel, cancel_grace_s=0.5)
    assert run.cancelled and run.exit_code is None
    assert time.monotonic() - t0 < 10


def test_cancel_also_kills_grandchildren_in_the_group(tmp_path):
    pidfile = tmp_path / "pid"
    code = ("import subprocess,sys,time,pathlib\n"
            f"c = subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
            f"pathlib.Path({str(pidfile)!r}).write_text(str(c.pid))\ntime.sleep(60)\n")
    cancel = threading.Event()
    threading.Thread(target=lambda: (wait_for(pidfile.exists), time.sleep(0.2), cancel.set())).start()
    run_tool([sys.executable, "-c", code], cwd=tmp_path, env={"PATH": os.environ["PATH"]}, timeout_s=60,
             cancel=cancel, cancel_grace_s=0.3)
    assert wait_for(lambda: not alive(int(pidfile.read_text())), 5)


def test_reaper_never_removes_workspaces_owned_by_another_user(tmp_path, monkeypatch):
    ws = tmp_path / f"{WS_PREFIX}theirs"
    ws.mkdir()
    t = time.time() - 100_000
    os.utime(ws, (t, t))
    monkeypatch.setattr(dk, "docker", lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)
    rep = reap_orphans(now=time.time() + 3600, tmp_root=tmp_path)
    assert rep.workspaces == [] and ws.exists()


def test_reaper_still_reaps_workspaces_when_the_docker_daemon_hangs(tmp_path, monkeypatch):
    ws = tmp_path / f"{WS_PREFIX}stale"
    ws.mkdir()
    t = time.time() - 100_000
    os.utime(ws, (t, t))

    def hung(*a, **k):
        raise SandboxError("docker ps failed: timed out after 30 seconds")
    monkeypatch.setattr(dk, "docker", hung)
    rep = reap_orphans(now=time.time(), tmp_root=tmp_path)
    assert rep.workspaces == [ws.name] and not ws.exists()
    assert any("could not list containers" in e for e in rep.errors)


@pytest.mark.docker
def test_hung_daemon_after_timeout_kills_our_docker_client_too(tmp_path, ws_root, monkeypatch):
    killed = []

    class StuckClient:
        stdout, stderr = io.BytesIO(), io.BytesIO()

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("docker", timeout)

        def poll(self):
            return None

        def kill(self):
            killed.append(1)

    monkeypatch.setattr(runner, "subprocess", SimpleNamespace(
        Popen=lambda *a, **k: StuckClient(), PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL,
        TimeoutExpired=subprocess.TimeoutExpired))
    real_docker = dk.docker

    def docker(*args, **kw):
        if args and args[0] == "kill":
            raise SandboxError("docker kill failed: timed out after 30 seconds")   # the daemon hangs
        return real_docker(*args, **kw)
    monkeypatch.setattr(dk, "docker", docker)
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "main.py").write_text("print(1)\n")
    before = set(dk.leftover_containers())
    with pytest.raises(SandboxError, match="did not stop"):
        run_sandboxed(proj, ["python", "-I", "main.py"], SandboxLimits(timeout_s=1))
    assert killed                                  # our client process was not left running
    assert list(ws_root.iterdir()) == [] and set(dk.leftover_containers()) == before
