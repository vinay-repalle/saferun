"""Failure-path cleanup and orphan recovery (Docker required)."""
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime

import pytest

from saferun.sandbox import (
    SandboxError, SandboxLimits, WorkspaceLimits, reap_orphans, run_sandboxed,
)
from saferun.sandbox import docker as dk
from saferun.sandbox.profiles import PYTHON
from saferun.sandbox.workspace import Workspace, create_workspace

PYTHON_PINNED = PYTHON.image    # a pinned reference: creating a container from it never triggers an implicit pull

pytestmark = pytest.mark.docker


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "proj"; p.mkdir()
    (p / "main.py").write_text("print('ok')")
    return p


def _names() -> set[str]:
    r = dk.docker("ps", "-a", "--filter", "label=saferun.sandbox=1", "--format", "{{.Names}}")
    return set(r.stdout.split())


@pytest.fixture(autouse=True)
def _no_container_leaks():
    before = _names()
    yield
    for n in _names() - before:  # clean up anything a failure-injection test left behind
        dk.force_remove(n)


def run(proj, **kw):
    return run_sandboxed(proj, ["python", "-I", "main.py"], **kw)


def test_container_removal_failure_still_deletes_workspace(proj, ws_root, monkeypatch):
    real = dk.force_remove

    def flaky(name):
        real(name)  # really remove (no leak), then report a failure
        raise SandboxError("simulated docker rm failure")
    monkeypatch.setattr(dk, "force_remove", flaky)
    with pytest.raises(SandboxError, match="cleanup failed.*simulated docker rm failure"):
        run(proj)
    assert list(ws_root.iterdir()) == []


def test_original_exception_preserved_when_cleanup_also_fails(proj, ws_root, monkeypatch):
    real = dk.force_remove

    def flaky(name):
        real(name)
        raise SandboxError("simulated docker rm failure")
    monkeypatch.setattr(dk, "force_remove", flaky)
    def explode(name):  # fails after the container has run, inside the guarded section
        raise RuntimeError("boom")
    monkeypatch.setattr(dk, "inspect", explode)
    with pytest.raises(RuntimeError, match="boom") as ei:
        run(proj)
    assert any("simulated docker rm failure" in n for n in ei.value.__notes__)
    assert list(ws_root.iterdir()) == []


def test_workspace_cleanup_failure_still_removes_container(proj, ws_root, monkeypatch):
    removed, real_rm, real_cleanup = [], dk.force_remove, Workspace.cleanup

    def spy(name):
        removed.append(name); return real_rm(name)

    def bad_cleanup(self):
        real_cleanup(self)  # really delete, then fail
        raise SandboxError("simulated workspace failure")
    monkeypatch.setattr(dk, "force_remove", spy)
    monkeypatch.setattr(Workspace, "cleanup", bad_cleanup)
    with pytest.raises(SandboxError, match="simulated workspace failure"):
        run(proj)
    assert len(removed) == 1 and dk.inspect(removed[0]) == {}


def test_docker_create_failure_cleans_up(proj, ws_root):
    # Docker enforces a minimum memory limit, so `create` itself fails.
    with pytest.raises(SandboxError, match="docker create failed"):
        run(proj, limits=SandboxLimits(memory_mb=1))
    assert list(ws_root.iterdir()) == []


def test_workspace_limit_failure_leaves_no_container_or_workspace(proj, ws_root):
    (proj / "second.py").write_text("")
    before = _names()
    with pytest.raises(SandboxError, match="more than"):
        run(proj, workspace_limits=WorkspaceLimits(max_files=1))
    assert list(ws_root.iterdir()) == [] and _names() == before


def test_comma_in_temp_path_is_rejected_and_cleaned(proj, tmp_path, monkeypatch):
    bad = tmp_path / "a,b"; bad.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(bad))
    before = _names()
    with pytest.raises(SandboxError, match="unsupported characters"):
        run(proj)
    assert list(bad.iterdir()) == [] and _names() == before


# ---- orphan recovery -------------------------------------------------------

PARENT = (
    "import sys; from saferun.sandbox import SandboxLimits, run_sandboxed;"
    "run_sandboxed(sys.argv[1], ['python','-I','main.py'], SandboxLimits(timeout_s=3, container_grace_s=3))"
)


def _ts(s: str) -> datetime:
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d*Z$", r"\1+00:00", s))


def test_orphan_is_killed_by_container_timeout_then_reaped(tmp_path):
    ws_root = tmp_path / "wsroot"; ws_root.mkdir()
    proj = tmp_path / "proj"; proj.mkdir()
    (proj / "main.py").write_text("import time; time.sleep(300)")
    before = _names()
    parent = subprocess.Popen([sys.executable, "-c", PARENT, str(proj)],
                              env={**os.environ, "TMPDIR": str(ws_root)})
    try:
        deadline, name = time.time() + 30, None
        while time.time() < deadline and name is None:
            for n in _names() - before:
                if dk.inspect(n).get("State", {}).get("Status") == "running":
                    name = n
            time.sleep(0.1)
        assert name, "container never started"
    finally:
        parent.kill(); parent.wait()  # SIGKILL: no cleanup code in the parent can run

    # Parent is dead (host-side timeout can no longer fire). Container-side timeout must stop it.
    t_end = time.time() + 30
    while time.time() < t_end and dk.inspect(name)["State"]["Status"] == "running":
        time.sleep(0.2)
    st = dk.inspect(name)["State"]
    assert st["Status"] == "exited" and st["ExitCode"] == 137
    ran = (_ts(st["FinishedAt"]) - _ts(st["StartedAt"])).total_seconds()
    assert 5 <= ran <= 12, f"expected ~6s (timeout 3 + grace 3), ran {ran:.1f}s"

    # Reaper: dead owner's workspace goes at once; container is kept until its deadline passes.
    rep = reap_orphans(tmp_root=ws_root)
    assert len(rep.workspaces) == 1 and list(ws_root.iterdir()) == []
    assert name not in rep.containers and dk.inspect(name) != {}
    rep = reap_orphans(now=time.time() + 3600, tmp_root=ws_root)
    assert name in rep.containers and dk.inspect(name) == {}
    assert not rep.errors


def test_reaper_never_touches_live_workspace_or_foreign_objects(tmp_path, ws_root):
    src = tmp_path / "src"; src.mkdir()
    ws = create_workspace(src)  # this process holds the flock
    unrelated = dk.docker("create", "--name", "unrelated-saferun-test", PYTHON_PINNED, "true")
    link_target = tmp_path / "keep"; link_target.mkdir()
    (ws_root / "saferun-ws-symlink").symlink_to(link_target)
    (ws_root / "saferun-ws-young").mkdir()  # no lock file, but fresh: may be mid-creation
    (ws_root / "other-dir").mkdir()
    try:
        assert unrelated.returncode == 0
        rep = reap_orphans(now=time.time() + 5, tmp_root=ws_root)
        assert rep.workspaces == [] and rep.containers == []
        assert ws.root.exists() and link_target.exists()
        assert (ws_root / "saferun-ws-young").exists() and (ws_root / "other-dir").exists()
        assert dk.inspect("unrelated-saferun-test") != {}
        # A lock-less workspace older than the minimum age is collected; the live one still is not.
        rep = reap_orphans(now=time.time() + 3600, tmp_root=ws_root)
        assert rep.workspaces == ["saferun-ws-young"] and ws.root.exists()
    finally:
        ws.cleanup()
        dk.docker("rm", "-f", "unrelated-saferun-test")
