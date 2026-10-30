"""Phase 5D: cleanup and exhaustion hardening.

Covers: a SIGKILLed server (instance lock, orphaned workers, leftover directories), an interrupted server (running worker is
cancelled, not left behind), the sweeper/reaper ownership checks (a "second OS user" is simulated by changing the uid SafeRun
believes it has), disk-full paths of the upload, a hung Docker daemon (reaper, health probe, sandbox client).
"""
import errno
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from saferun.api import app as app_module
from saferun.api import jobs
from saferun.api.app import _AnalyzerProbe, create_app
from saferun.api.jobs import JobLimits, JobManager
from saferun.engine.tools import run_tool
from saferun.sandbox import SandboxError, SandboxLimits, reap_orphans, run_sandboxed
from saferun.sandbox import docker as dk
from saferun.sandbox import runner
from saferun.sandbox.workspace import WS_PREFIX

REPO = Path(__file__).resolve().parents[1]
REPORT = {"schema_version": 1, "verdict": "PASS", "reasons": ["ok"], "complete": True, "workspace": {}, "checks": []}
H = {"X-SafeRun-Request": "1", "Content-Type": "application/zip"}


def zip_file(path: Path) -> str:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.py", b"x = 1\n")
    return str(path)


def zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.py", b"x = 1\n")
    return buf.getvalue()


def alive(pid: int) -> bool:
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _cwd(pid) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def wait_for(cond, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def sleeper(cwd: Path) -> subprocess.Popen:
    cwd.mkdir(exist_ok=True)
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], cwd=cwd, start_new_session=True)


@pytest.fixture
def procs():
    made = []
    yield made
    for p in made:
        p.kill()
        p.wait()


# ------------------------------------------------------------------------------- run_tool cancellation

def _cancel_after(ev, delay):
    threading.Timer(delay, ev.set).start()


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


# ---------------------------------------------------------- server stop: a running scan is not left behind

def test_shutdown_interrupts_the_running_worker_and_cleans_up(tmp_path, ws_root):
    marker, ready = tmp_path / "cleaned", tmp_path / "ready"
    code = ("import signal,sys,time,pathlib\n"
            f"def h(*a):\n    pathlib.Path({str(marker)!r}).write_text('x'); sys.exit(130)\n"
            "signal.signal(signal.SIGINT, h)\n"
            f"pathlib.Path({str(ready)!r}).write_text('x')\n"
            "time.sleep(60)\n")
    m = JobManager(command_builder=lambda p, o, t: [sys.executable, "-c", code, str(p)])
    m.start()
    upload = zip_file(tmp_path / "up.zip")
    job = m.submit(upload, "disabled")
    assert wait_for(ready.exists)
    m.shutdown()
    j = m.get(job.id)
    assert j["status"] == "failed" and j["error"]["code"] == "shutdown"
    assert marker.exists()
    assert not os.path.exists(upload)
    assert [p.name for p in ws_root.iterdir()] == []        # extraction directory deleted


def test_shutdown_does_not_hang_on_a_stubborn_worker(tmp_path, ws_root, monkeypatch):
    ready = tmp_path / "ready"
    code = ("import signal,time,pathlib\nsignal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            f"pathlib.Path({str(ready)!r}).write_text('x')\ntime.sleep(60)\n")
    monkeypatch.setattr(jobs, "run_tool", lambda *a, **k: run_tool(*a, **{**k, "cancel_grace_s": 0.5}))
    m = JobManager(command_builder=lambda p, o, t: [sys.executable, "-c", code, str(p)], tool_runner=jobs.run_tool)
    m.start()
    job = m.submit(zip_file(tmp_path / "up.zip"), "disabled")
    assert wait_for(ready.exists)
    t0 = time.monotonic()
    m.shutdown()
    assert time.monotonic() - t0 < 15
    assert m.get(job.id)["error"]["code"] == "shutdown"
    assert list(ws_root.iterdir()) == []


# --------------------------------------------------------------------------------------- instance lock

def test_instance_lock_is_exclusive_and_released_on_close(tmp_path):
    a = jobs.acquire_instance_lock(tmp_path)
    assert isinstance(a, int)
    assert jobs.acquire_instance_lock(tmp_path) is None
    os.close(a)
    b = jobs.acquire_instance_lock(tmp_path)
    assert isinstance(b, int)
    os.close(b)


def test_instance_lock_is_released_when_the_holder_is_sigkilled(tmp_path):
    code = ("import sys,time\nfrom saferun.api import jobs\nfd = jobs.acquire_instance_lock(sys.argv[1])\n"
            "print('held' if fd is not None else 'no', flush=True)\ntime.sleep(60)\n")
    p = subprocess.Popen([sys.executable, "-c", code, str(tmp_path)], stdout=subprocess.PIPE, text=True, cwd=REPO)
    try:
        assert p.stdout.readline().strip() == "held"
        assert jobs.acquire_instance_lock(tmp_path) is None
        p.kill()
        p.wait()
        fd = jobs.acquire_instance_lock(tmp_path)
        assert isinstance(fd, int)
        os.close(fd)
    finally:
        p.kill()
        p.wait()


def test_instance_lock_refuses_a_symlink_planted_in_the_temp_dir(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / f"{jobs.LOCK_PREFIX}{os.getuid()}.lock").symlink_to(victim)
    assert jobs.acquire_instance_lock(tmp_path) is None
    assert victim.read_text() == "keep"


def test_instance_lock_refuses_a_lock_file_owned_by_someone_else(tmp_path, monkeypatch):
    real = os.getuid()
    (tmp_path / f"{jobs.LOCK_PREFIX}{real + 1}.lock").write_text("")   # created by "us", but we pose as another user
    monkeypatch.setattr(os, "getuid", lambda: real + 1)
    assert jobs.acquire_instance_lock(tmp_path) is None


# ---------------------------------------------------------------------------------- orphaned workers

def test_kill_orphan_workers_kills_only_our_processes_inside_extraction_dirs(tmp_path, procs):
    inside = sleeper(tmp_path / "saferun-up-abc")
    outside = sleeper(tmp_path / "unrelated")
    lookalike = sleeper(tmp_path / "xsaferun-up-abc")
    procs += [inside, outside, lookalike]
    assert wait_for(lambda: all(alive(p.pid) for p in procs))
    killed = jobs.kill_orphan_workers(tmp_path)
    assert killed == [inside.pid]
    assert wait_for(lambda: inside.poll() is not None, 5)
    assert outside.poll() is None and lookalike.poll() is None


def test_kill_orphan_workers_ignores_processes_of_another_user(tmp_path, procs, monkeypatch):
    p = sleeper(tmp_path / "saferun-up-abc")
    procs.append(p)
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)       # the process now looks foreign
    assert jobs.kill_orphan_workers(tmp_path) == []
    assert p.poll() is None


def test_kill_orphan_workers_never_signals_itself(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path / ".")
    d = tmp_path / "saferun-up-me"
    d.mkdir()
    monkeypatch.chdir(d)
    assert os.getpid() not in jobs.kill_orphan_workers(tmp_path)


def test_kill_orphan_workers_survives_an_unreadable_proc(tmp_path):
    assert jobs.kill_orphan_workers(tmp_path, proc_root=str(tmp_path / "no-proc")) == []


# ----------------------------------------------------------------------------------- startup cleanup

def _debris(root: Path):
    d = root / "saferun-up-fresh"
    (d / "project").mkdir(parents=True)
    (d / "project" / "f").write_text("x")
    u = root / "saferun-upl-fresh.zip"
    u.write_text("x")
    keep = root / "unrelated"
    keep.mkdir()
    return d, u, keep


def test_startup_cleanup_with_the_lock_removes_fresh_leftovers_too(tmp_path):
    d, u, keep = _debris(tmp_path)
    res = jobs.startup_cleanup(1800, tmp_path)
    try:
        assert res.lock_fd is not None
        assert sorted(res.removed) == ["saferun-up-fresh", "saferun-upl-fresh.zip"]
        assert not d.exists() and not u.exists() and keep.exists()
    finally:
        os.close(res.lock_fd)


def test_startup_cleanup_without_the_lock_keeps_fresh_files_of_a_live_server(tmp_path):
    d, u, keep = _debris(tmp_path)
    other_server = jobs.acquire_instance_lock(tmp_path)
    old = tmp_path / "saferun-upl-old.zip"
    old.write_text("x")
    t = time.time() - 100_000
    os.utime(old, (t, t))
    try:
        res = jobs.startup_cleanup(1800, tmp_path)
        assert res.lock_fd is None and res.killed_workers == []
        assert res.removed == ["saferun-upl-old.zip"]
        assert d.exists() and u.exists()
    finally:
        os.close(other_server)


def test_sweeper_never_touches_entries_owned_by_another_user(tmp_path, monkeypatch):
    d = tmp_path / "saferun-up-theirs"
    d.mkdir()
    f = tmp_path / "saferun-upl-theirs.zip"
    f.write_text("x")
    t = time.time() - 100_000
    os.utime(d, (t, t))
    os.utime(f, (t, t))
    real = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: real + 1)      # as a second OS user: these entries are not ours
    assert jobs.sweep_stale(60, tmp_path) == []
    assert jobs.sweep_stale(0, tmp_path) == []
    assert d.exists() and f.exists()


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


SERVER = """
import sys, tempfile, time
tempfile.tempdir = sys.argv[1]
from pathlib import Path
from saferun.api.jobs import JobManager
m = JobManager(command_builder=lambda p, o, t: [sys.executable, "-c", "import time; time.sleep(120)", str(p)])
m.start()
job = m.submit(sys.argv[2], "disabled")
while not any(Path(sys.argv[1]).glob("saferun-up-*/home")):
    time.sleep(0.02)
time.sleep(0.5)
print("running", flush=True)
time.sleep(120)
"""


def test_a_sigkilled_server_leaves_debris_that_the_next_start_removes(tmp_path):
    root = tmp_path / "tmp"
    root.mkdir()
    upload = zip_file(tmp_path / "up.zip")
    server = subprocess.Popen([sys.executable, "-c", SERVER, str(root), upload], stdout=subprocess.PIPE, text=True, cwd=REPO)
    try:
        assert server.stdout.readline().strip() == "running"
        server.kill()                       # SIGKILL: no shutdown hook runs
        server.wait()
        dirs = list(root.glob("saferun-up-*"))
        assert len(dirs) == 1               # the extraction directory is still there ...
        worker = [p for p in os.listdir("/proc") if p.isdigit() and _cwd(p) == str(dirs[0].resolve())]
        assert len(worker) == 1 and alive(int(worker[0]))   # ... and so is the orphaned worker

        res = jobs.startup_cleanup(1800, root)              # what the next `saferun-web` start does
        try:
            assert res.lock_fd is not None
            assert res.killed_workers == [int(worker[0])]
            assert wait_for(lambda: not alive(int(worker[0])), 5)
            assert list(root.glob("saferun-up-*")) == []
        finally:
            os.close(res.lock_fd)
    finally:
        server.kill()
        server.wait()


# ----------------------------------------------------------------------------------------- disk full

def _client(tmp_ws, **kw):
    mgr = JobManager(command_builder=lambda p, o, t: [sys.executable, "-c", f"import json; print(json.dumps({REPORT!r}))"])
    app = create_app(mgr, run_startup_cleanup=False, static_dir=None, **kw)
    return TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000))


def test_upload_is_refused_up_front_when_the_disk_is_nearly_full(ws_root, monkeypatch):
    monkeypatch.setattr(app_module, "_free_bytes", lambda: 10 * 1024 * 1024)
    with _client(ws_root) as c:
        r = c.post("/api/scans", content=zip_bytes(), headers=H)
    assert r.status_code == 507 and r.json()["error"]["code"] == "insufficient-storage"
    assert list(ws_root.iterdir()) == []


def test_declared_size_counts_against_free_space(ws_root, monkeypatch):
    monkeypatch.setattr(app_module, "_free_bytes", lambda: app_module.DISK_RESERVE_BYTES + 5000)
    with _client(ws_root) as c:
        big = c.post("/api/scans", content=b"x" * 20000, headers=H)
        small = c.post("/api/scans", content=zip_bytes(), headers=H)
    assert big.status_code == 507
    assert small.status_code == 202


def test_disk_full_while_writing_the_upload_is_507_and_leaves_nothing(ws_root, monkeypatch):
    real = os.fdopen

    class Full:
        def __init__(self, f):
            self.f = f

        def write(self, b):
            raise OSError(errno.ENOSPC, "No space left on device")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.f.close()

    monkeypatch.setattr(app_module.os, "fdopen", lambda fd, mode: Full(real(fd, mode)))
    with _client(ws_root) as c:
        r = c.post("/api/scans", content=zip_bytes(), headers=H)
        monkeypatch.setattr(app_module.os, "fdopen", real)
        assert r.status_code == 507 and r.json()["error"]["code"] == "insufficient-storage"
        assert list(ws_root.iterdir()) == []
        assert c.post("/api/scans", content=zip_bytes(), headers=H).status_code == 202      # the slot was released


def test_disk_full_when_creating_the_upload_file_is_507(ws_root, monkeypatch):
    def full(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(app_module.tempfile, "mkstemp", full)
    with _client(ws_root) as c:
        r = c.post("/api/scans", content=zip_bytes(), headers=H)
        assert r.status_code == 507
        monkeypatch.undo()
    # the in-flight counter was released: the app still accepts uploads afterwards
    with _client(ws_root) as c2:
        assert c2.post("/api/scans", content=zip_bytes(), headers=H).status_code == 202


def test_disk_full_during_extraction_is_a_rejected_job_not_a_crash(tmp_path, ws_root, monkeypatch):
    from saferun.api import archive
    monkeypatch.setattr(archive.shutil, "disk_usage", lambda p: SimpleNamespace(free=0, total=1, used=1))
    m = JobManager(command_builder=lambda p, o, t: [sys.executable, "-c", "pass"])
    m.start()
    try:
        job = m.submit(zip_file(tmp_path / "up.zip"), "disabled")
        assert wait_for(lambda: m.get(job.id)["status"] not in ("queued", "running"))
        j = m.get(job.id)
        assert j["status"] == "rejected" and j["error"]["code"] == "insufficient-space"
        assert list(ws_root.iterdir()) == []
    finally:
        m.shutdown()


# ------------------------------------------------------------------------------------- hung Docker

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


def test_health_probe_gives_up_on_a_hung_check_and_does_not_pile_up_threads():
    release, calls = threading.Event(), []

    def hung():
        calls.append(1)
        release.wait(30)
    probe = _AnalyzerProbe(hung, timeout_s=0.2, ttl_s=60)
    t0 = time.monotonic()
    try:
        assert probe.ok() is False
        assert probe.ok() is False
        assert probe.ok() is False
        assert time.monotonic() - t0 < 5
        assert len(calls) == 1              # one pending probe is shared, not one thread per request
    finally:
        release.set()
    assert wait_for(lambda: probe.ok() is True, 5)    # a late success is picked up (and cached)


def test_health_probe_caches_and_reports_failures():
    state = {"n": 0, "fail": True}

    def check():
        state["n"] += 1
        if state["fail"]:
            raise RuntimeError("analyzer image ID mismatch")
    probe = _AnalyzerProbe(check, timeout_s=5, ttl_s=60)
    assert probe.ok() is False and probe.ok() is False
    assert state["n"] == 1                  # cached within the TTL
    probe = _AnalyzerProbe(check, timeout_s=5, ttl_s=0.0001)
    state["fail"] = False
    time.sleep(0.01)
    assert probe.ok() is True


def test_health_endpoint_answers_promptly_while_docker_hangs(ws_root, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(app_module, "verify_analyzer_image", lambda: release.wait(30))
    monkeypatch.setattr(app_module, "HEALTH_PROBE_TIMEOUT_S", 0.3)
    try:
        with _client(ws_root) as c:
            t0 = time.monotonic()
            h = c.get("/api/health").json()
            assert time.monotonic() - t0 < 5
            assert h["analyzer"] is False and h["semgrep"] is False and h["osv_scanner"] is False
            assert set(h) == {"docker_cli", "analyzer", "semgrep", "osv_scanner", "queue", "limits"}   # schema unchanged
    finally:
        release.set()


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


# ------------------------------------------------------------------------------------ lifespan wiring

def test_server_start_runs_the_crash_recovery_and_holds_the_lock_while_serving(ws_root, monkeypatch):
    monkeypatch.setattr(app_module, "reap_orphans", lambda: None)
    d, u, keep = _debris(ws_root)
    mgr = JobManager(command_builder=lambda p, o, t: [sys.executable, "-c", "pass"])
    app = create_app(mgr, run_startup_cleanup=True, static_dir=None)
    with TestClient(app, base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000)):
        assert not d.exists() and not u.exists() and keep.exists()
        assert jobs.acquire_instance_lock() is None       # a second server would not get the lock
    fd = jobs.acquire_instance_lock()                     # released at shutdown
    assert isinstance(fd, int)
    os.close(fd)
