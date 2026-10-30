"""OSV mode plumbing through the REAL chain (API -> worker CLI -> engine -> analyzer container) (Phase 5B).

Host-side shims named `osv-scanner` and `semgrep` are placed first on PATH and record any start: they must NEVER run, i.e. the
chain has no host-side analyzer path. Offline scans use the real analyzer image and an offline OSV database; online is refused;
disabled never starts anything. Skipped visibly when the analyzer image / database is not available.
"""
import io
import os
import stat
import time
import zipfile

import pytest
from starlette.testclient import TestClient

from saferun.api.app import create_app
from saferun.api.jobs import JobLimits, JobManager
from saferun.engine import osvdb
from saferun.sandbox.analyzer import verify_analyzer_image

H = {"X-SafeRun-Request": "1", "Content-Type": "application/zip"}


def _ready() -> bool:
    try:
        verify_analyzer_image()
    except Exception:  # noqa: BLE001
        return False
    return osvdb.validate(osvdb.default_dir(), ["PyPI", "npm"]).ok


needs_real = pytest.mark.skipif(not _ready(), reason="analyzer image or offline OSV database not available")


@pytest.fixture
def setup(tmp_path, ws_root, monkeypatch):
    record = tmp_path / "host-tool-record.txt"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("osv-scanner", "semgrep"):
        exe = bindir / name
        exe.write_text(f'#!/bin/sh\necho "{name} $*" >> {record}\necho \'{{"results": [], "paths": {{"scanned": []}}}}\'\nexit 0\n')
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("SECRET_TOKEN_FOR_TEST", "must-never-reach-anything")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", "six==1.17.0\n")
    c = TestClient(create_app(JobManager(JobLimits(job_deadline_s=300)), run_startup_cleanup=False, static_dir=None),
                   base_url="http://127.0.0.1:8765", client=("127.0.0.1", 50000))
    with c:
        yield c, buf.getvalue(), record


def run(c, data, mode):
    sid = c.post(f"/api/scans?osv={mode}", content=data, headers=H).json()["id"]
    end = time.monotonic() + 240
    while time.monotonic() < end:
        j = c.get(f"/api/scans/{sid}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.3)
    raise AssertionError("timeout")


def dep(job):
    return next(c for c in job["report"]["checks"] if c["name"] == "dependency-vulnerabilities")


@pytest.mark.docker
@needs_real
def test_offline_scan_runs_in_the_analyzer_container_and_never_starts_a_host_tool(setup):
    c, data, record = setup
    job = run(c, data, "offline")
    assert job["status"] == "done" and dep(job)["status"] == "passed" and job["osv_mode"] == "offline"
    assert not record.exists(), f"a host-side analyzer was started: {record.read_text()}"


def test_online_mode_is_refused_and_starts_nothing(setup):
    c, data, record = setup
    r = c.post("/api/scans?osv=online", content=data, headers=H)
    assert r.status_code == 422 and r.json()["error"]["code"] == "osv-online-unsupported" and not record.exists()


def test_disabled_mode_never_starts_a_tool_and_is_never_a_plain_pass(setup):
    c, data, record = setup
    job = run(c, data, "disabled")
    assert job["status"] == "done" and dep(job)["status"] == "skipped" and not record.exists()
    assert job["report"]["verdict"] == "WARNING" and job["report"]["complete"] is False


def test_missing_analyzer_image_through_the_api_is_unavailable_not_a_host_fallback(setup, tmp_path, monkeypatch):
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(tmp_path / "no-such-lock"))
    c, data, record = setup
    job = run(c, data, "offline")
    assert job["status"] == "done" and dep(job)["status"] == "unavailable" and "no host fallback" in dep(job)["detail"]
    assert job["report"]["verdict"] == "WARNING" and not record.exists()
