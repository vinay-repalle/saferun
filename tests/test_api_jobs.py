"""Job runner tests (Phase 4 unit 2): bounded queue, deadline kill, cleanup, environment hygiene, CLI-output handling.

The worker is replaced by small Python snippets run as real subprocesses (so process-group kill and cleanup are
exercised for real); the parity/Docker path is covered in test_api_e2e.py.
"""
import json
import os
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

from saferun.api import jobs
from saferun.api.archive import ArchiveLimits
from saferun.api.jobs import Busy, JobLimits, JobManager, build_command, parse_report, worker_env
from saferun.engine.tools import ToolRun

REPORT = {"schema_version": 1, "verdict": "PASS", "reasons": ["ok"], "complete": True, "workspace": {}, "checks": []}


def make_zip_file(path: Path, files=None) -> str:
    with zipfile.ZipFile(path, "w") as zf:
        for n, d in (files or {"a.py": b"x = 1\n"}).items():
            zf.writestr(n, d)
    return str(path)


def snippet(code: str):
    """command_builder that ignores the project and runs `python -c code`; project dir is passed as argv[1]."""
    def build(project, osv_mode, timeout):
        return [sys.executable, "-c", code, str(project), osv_mode, f"{timeout:g}"]
    return build


PRINT_REPORT = f"import sys,json; print(json.dumps({REPORT!r})); sys.exit(0)"


def wait(mgr, job_id, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        j = mgr.get(job_id)
        if j and j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.02)
    raise AssertionError(f"job did not finish: {mgr.get(job_id)}")


@pytest.fixture
def mgr_factory(tmp_path, ws_root):
    made = []

    def make(code=PRINT_REPORT, limits=None, **kw):
        m = JobManager(limits=limits or JobLimits(), command_builder=snippet(code), **kw)
        m.start()
        made.append(m)
        return m
    yield make
    for m in made:
        m.shutdown()


def submit(mgr, tmp_path, name="up.zip", osv="disabled", files=None):
    return mgr.submit(make_zip_file(tmp_path / name, files), osv)


# ----------------------------------------------------------------------------------------- happy / mapping

def test_done_job_relays_the_report_unchanged_and_cleans_up(mgr_factory, tmp_path, ws_root):
    m = mgr_factory()
    j = submit(m, tmp_path)
    done = wait(m, j.id)
    assert done["status"] == "done" and done["report"] == REPORT and done["error"] is None
    assert done["archive"]["files"] == 1 and done["archive"]["stripped_prefix"] is None
    assert not os.path.exists(tmp_path / "up.zip")           # the upload is gone
    assert list(ws_root.iterdir()) == []                      # extraction dir (incl. worker HOME) is gone


@pytest.mark.parametrize("code,verdict", [(0, "PASS"), (1, "FAIL"), (2, "WARNING")])
def test_exit_code_and_verdict_must_agree(mgr_factory, tmp_path, code, verdict):
    rep = dict(REPORT, verdict=verdict)
    m = mgr_factory(f"import sys,json; print(json.dumps({rep!r})); sys.exit({code})")
    assert wait(m, submit(m, tmp_path).id)["report"]["verdict"] == verdict


def test_mismatching_exit_code_and_verdict_is_a_failure_not_a_verdict(mgr_factory, tmp_path):
    rep = dict(REPORT, verdict="PASS")
    m = mgr_factory(f"import sys,json; print(json.dumps({rep!r})); sys.exit(1)")     # FAIL exit, PASS body
    j = wait(m, submit(m, tmp_path).id)
    assert j["status"] == "failed" and "report" not in j and j["error"]["code"] == "bad-worker-output"


@pytest.mark.parametrize("code", [64, 70, 1 << 7, 3])
def test_no_verdict_exit_codes_are_failures_without_output_leak(mgr_factory, tmp_path, code):
    m = mgr_factory(f"import sys; print('HOST SECRET /home/x/.ssh'); sys.stderr.write('/tmp/leak'); sys.exit({code})")
    j = wait(m, submit(m, tmp_path).id)
    assert j["status"] == "failed" and "report" not in j
    assert "SECRET" not in json.dumps(j) and "/tmp/leak" not in json.dumps(j)
    if code in (64, 70):
        assert j["error"]["code"] == "no-verdict"


@pytest.mark.parametrize("body", ["not json", "[]", '{"schema_version": 2}', json.dumps(dict(REPORT, schema_version=2)),
                                  json.dumps(dict(REPORT, verdict="MAYBE")), json.dumps({k: v for k, v in REPORT.items() if k != "checks"})])
def test_malformed_worker_output_is_a_failure(mgr_factory, tmp_path, body):
    m = mgr_factory(f"import sys; print({body!r}); sys.exit(0)")
    assert wait(m, submit(m, tmp_path).id)["status"] == "failed"


def test_rejected_archive_reports_the_stable_code(mgr_factory, tmp_path, ws_root):
    m = mgr_factory()
    j = wait(m, submit(m, tmp_path, files={"../evil.py": b"x"}).id)
    assert j["status"] == "rejected" and j["error"]["code"] == "unsafe-name" and "report" not in j
    assert list(ws_root.iterdir()) == [] and not os.path.exists(tmp_path / "up.zip")


def test_worker_receives_the_extracted_project_and_options(mgr_factory, tmp_path):
    code = ("import sys,json,os; p=sys.argv[1]; rep=%r; rep['reasons']=[sorted(os.listdir(p)), sys.argv[2], sys.argv[3]]; "
            "print(json.dumps(rep))") % REPORT
    m = mgr_factory(code, limits=JobLimits(tool_timeout_s=33))
    j = wait(m, submit(m, tmp_path, osv="offline", files={"a.py": b"1", "b.py": b"2"}).id)
    assert j["report"]["reasons"] == [["a.py", "b.py"], "offline", "33"]


def test_stripped_wrapper_and_exclusions_are_disclosed(mgr_factory, tmp_path):
    m = mgr_factory()
    j = wait(m, submit(m, tmp_path, files={"repo/a.py": b"1", "__MACOSX/._a": b"x", "repo/.DS_Store": b"x"}).id)
    assert j["archive"]["stripped_prefix"] == "repo" and j["archive"]["excluded_total"] == 2


# --------------------------------------------------------------------------------------- deadline / kill

def test_deadline_kills_the_whole_process_group_and_cleans_up(mgr_factory, tmp_path, ws_root):
    pidfile = tmp_path / "child.pid"
    code = ("import subprocess,sys,time; c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']); "
            f"open({str(pidfile)!r},'w').write(str(c.pid)); time.sleep(120)")
    reaped = []
    m = mgr_factory(code, limits=JobLimits(job_deadline_s=2.5), reaper=lambda: reaped.append(1))
    t0 = time.monotonic()
    j = wait(m, submit(m, tmp_path).id, timeout=30)
    assert j["status"] == "failed" and j["error"]["code"] == "deadline" and "report" not in j
    assert time.monotonic() - t0 < 15
    child = int(pidfile.read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)                                    # the grandchild died with the group
    assert list(ws_root.iterdir()) == [] and reaped == [1]


def test_output_flood_is_stopped(mgr_factory, tmp_path):
    m = mgr_factory("import sys\nwhile True: sys.stdout.write('A'*100000)", limits=JobLimits(max_output_bytes=1_000_000))
    j = wait(m, submit(m, tmp_path).id, timeout=30)
    assert j["status"] == "failed" and j["error"]["code"] == "output-too-large"


def test_worker_that_cannot_start_is_a_failure(tmp_path, ws_root):
    m = JobManager(command_builder=lambda p, o, t: ["/nonexistent/binary"])
    m.start()
    try:
        j = wait(m, submit(m, tmp_path).id)
        assert j["status"] == "failed" and j["error"]["code"] == "worker-unavailable"
    finally:
        m.shutdown()


def test_internal_bug_ends_the_job_not_the_worker_thread(tmp_path, ws_root):
    calls = []

    def flaky(project, osv, t):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return snippet(PRINT_REPORT)(project, osv, t)
    m = JobManager(command_builder=flaky)
    m.start()
    try:
        a = wait(m, submit(m, tmp_path, "a.zip").id)
        assert a["status"] == "failed" and a["error"]["code"] == "internal-error" and "boom" not in json.dumps(a)
        assert wait(m, submit(m, tmp_path, "b.zip").id)["status"] == "done"
        assert list(ws_root.iterdir()) == []
    finally:
        m.shutdown()


# ------------------------------------------------------------------------------------- queue / TTL / delete

def test_queue_is_bounded_and_busy_is_raised(tmp_path, ws_root):
    gate = threading.Event()

    def blocking_runner(argv, **kw):
        gate.wait(20)
        return ToolRun(argv, 0, json.dumps(REPORT), "")
    m = JobManager(limits=JobLimits(max_queue=2), command_builder=snippet(PRINT_REPORT), tool_runner=blocking_runner)
    m.start()
    try:
        ids = [submit(m, tmp_path, f"{i}.zip").id for i in range(3)]       # 1 running + 2 queued
        assert not m.has_capacity()
        with pytest.raises(Busy):
            submit(m, tmp_path, "overflow.zip")
        assert os.path.exists(tmp_path / "overflow.zip")                   # the caller still owns a refused upload
        assert m.counts() == {"active": 3, "capacity": 3, "stored_results": 0}
        gate.set()
        assert all(wait(m, i)["status"] == "done" for i in ids)
        assert m.has_capacity()
    finally:
        gate.set()
        m.shutdown()


def test_only_one_job_runs_at_a_time(tmp_path, ws_root):
    running, peak, lock = [0], [0], threading.Lock()

    def runner(argv, **kw):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.15)
        with lock:
            running[0] -= 1
        return ToolRun(argv, 0, json.dumps(REPORT), "")
    m = JobManager(command_builder=snippet(PRINT_REPORT), tool_runner=runner)
    m.start()
    try:
        ids = [submit(m, tmp_path, f"{i}.zip").id for i in range(4)]
        for i in ids:
            wait(m, i)
        assert peak[0] == 1
    finally:
        m.shutdown()


def test_results_expire_and_are_capped(tmp_path, ws_root):
    now = [100.0]
    m = JobManager(limits=JobLimits(result_ttl_s=60, max_results=2), command_builder=snippet(PRINT_REPORT),
                   clock=lambda: now[0])
    m.start()
    try:
        ids = []
        for i in range(3):
            ids.append(submit(m, tmp_path, f"{i}.zip").id)
            wait(m, ids[-1])
            now[0] += 1
        assert m.get(ids[0]) is None and m.get(ids[1]) and m.get(ids[2])      # cap of 2 evicts the oldest
        now[0] += 100
        assert m.get(ids[1]) is None and m.get(ids[2]) is None                # TTL
    finally:
        m.shutdown()


def test_delete_only_finished_jobs(mgr_factory, tmp_path):
    m = mgr_factory()
    j = wait(m, submit(m, tmp_path).id)
    assert m.delete(j["id"]) is True and m.get(j["id"]) is None
    assert m.delete(j["id"]) is False and m.delete("nope") is False


def test_shutdown_drops_queued_uploads(tmp_path, ws_root):
    gate = threading.Event()
    m = JobManager(command_builder=snippet(PRINT_REPORT),
                   tool_runner=lambda argv, **kw: (gate.wait(20), ToolRun(argv, 0, json.dumps(REPORT), ""))[1])
    m.start()
    first = submit(m, tmp_path, "1.zip")
    time.sleep(0.3)
    second = submit(m, tmp_path, "2.zip")
    gate.set()
    m.shutdown()
    assert wait(m, first.id)["status"] in ("done", "failed")
    s = m.get(second.id)["status"]
    assert s in ("failed", "done") and not os.path.exists(tmp_path / "2.zip")


def test_ids_are_unguessable_and_unique(mgr_factory, tmp_path):
    m = mgr_factory()
    ids = {submit(m, tmp_path, f"{i}.zip").id for i in range(5)}
    assert len(ids) == 5 and all(len(i) >= 21 for i in ids)


def test_invalid_osv_mode_is_refused(mgr_factory, tmp_path):
    m = mgr_factory()
    with pytest.raises(ValueError):
        m.submit(make_zip_file(tmp_path / "x.zip"), "everything")


# ------------------------------------------------------------------------------------------ environment

HOSTILE = {"PATH": "/usr/bin:/bin", "HOME": "/home/victim", "AWS_SECRET_ACCESS_KEY": "s3cr3t", "GITHUB_TOKEN": "ghp_x",
           "ANTHROPIC_API_KEY": "sk-ant-x", "SSH_AUTH_SOCK": "/run/ssh", "PYTHONPATH": "/evil", "PYTHONSTARTUP": "/evil.py",
           "PYTHONHOME": "/evil", "LD_PRELOAD": "/evil.so", "LD_LIBRARY_PATH": "/evil", "BASH_ENV": "/evil", "ENV": "/evil",
           "HTTPS_PROXY": "http://proxy:3128", "SSL_CERT_FILE": "/etc/ssl/c.pem", "DOCKER_HOST": "unix:///run/docker.sock",
           "DOCKER_CONTEXT": "default", "DOCKER_CONFIG": "/cfg", "LANG": "C.UTF-8", "TZ": "UTC", "LC_ALL": "C.UTF-8"}


def test_worker_env_is_an_allow_list(tmp_path):
    env = worker_env(tmp_path, "disabled", HOSTILE)
    assert set(env) == {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                        "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "SAFERUN_ANALYZER_LOCK", "SAFERUN_OSV_DB"}
    assert env["HOME"] == str(tmp_path) != HOSTILE["HOME"] and env["TMPDIR"] == str(tmp_path)
    assert env["PATH"].endswith(HOSTILE["PATH"]) and env["PATH"].startswith(str(Path(sys.executable).parent))
    flat = json.dumps(env)
    for bad in ("s3cr3t", "ghp_x", "sk-ant", "/run/ssh", "/evil", "victim"):
        assert bad not in flat


def test_proxy_and_cert_variables_never_reach_the_worker(tmp_path):
    """Phase 5B: there is no online mode, so no network settings are forwarded in any mode."""
    for mode in ("offline", "disabled"):
        assert not ({"HTTPS_PROXY", "SSL_CERT_FILE", "HTTP_PROXY", "SSL_CERT_DIR"} & set(worker_env(tmp_path, mode, HOSTILE)))


def test_worker_gets_explicit_analyzer_and_osv_data_locations(tmp_path, monkeypatch):
    for k in ("SAFERUN_OSV_DB", "SAFERUN_ANALYZER_LOCK", "XDG_DATA_HOME"):
        monkeypatch.delenv(k, raising=False)
    env = worker_env(tmp_path, "offline", {"PATH": "/bin"})
    assert env["SAFERUN_ANALYZER_LOCK"].endswith("analyzer-image-id") and env["SAFERUN_OSV_DB"].endswith("osv-db")
    assert str(tmp_path) not in env["SAFERUN_OSV_DB"]          # resolved from the server's environment, not the private job HOME
    env = worker_env(tmp_path, "offline", {"PATH": "/bin", "SAFERUN_OSV_DB": "/data/osv", "SAFERUN_ANALYZER_LOCK": "/data/lock"})
    assert env["SAFERUN_OSV_DB"] == "/data/osv" and env["SAFERUN_ANALYZER_LOCK"] == "/data/lock"


def test_worker_env_skips_unset_and_nul_values(tmp_path):
    env = worker_env(tmp_path, "offline", {"PATH": "/bin", "DOCKER_HOST": "unix:///x\0y"})
    assert "DOCKER_HOST" not in env and "DOCKER_CONTEXT" not in env


def test_a_real_child_sees_only_the_allow_listed_environment(tmp_path, ws_root, monkeypatch):
    for k, v in HOSTILE.items():
        monkeypatch.setenv(k, v)
    dump = tmp_path / "env.json"
    code = f"import os,json; open({str(dump)!r},'w').write(json.dumps(dict(os.environ))); print(json.dumps({REPORT!r}))"
    m = JobManager(command_builder=snippet(code))
    m.start()
    try:
        wait(m, submit(m, tmp_path).id)
    finally:
        m.shutdown()
    seen = json.loads(dump.read_text())
    for bad in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "ANTHROPIC_API_KEY", "SSH_AUTH_SOCK", "PYTHONPATH", "PYTHONSTARTUP",
                "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "ENV", "HTTPS_PROXY"):
        assert bad not in seen
    assert seen["HOME"] != "/home/victim"


# --------------------------------------------------------------------------------------------- command

def test_command_is_exactly_the_documented_cli(tmp_path):
    base = build_command(tmp_path, "online", 120)
    assert base[:5] == [sys.executable, "-I", "-m", "saferun", "scan"] and base[5] == str(tmp_path)
    assert base[6:] == ["--format", "json", "--timeout", "120"]
    assert build_command(tmp_path, "offline", 5)[-1] == "--osv-offline"
    assert build_command(tmp_path, "disabled", 5)[-1] == "--no-dependency-scan"
    assert not any(a in base for a in ("--no-python-syntax", "--no-python-analysis", "--no-javascript-check"))


def test_parse_report_accepts_only_agreeing_exit_and_verdict():
    ok = ToolRun(["x"], 0, json.dumps(REPORT), "")
    assert parse_report(ok) == REPORT
    for run in (ToolRun(["x"], None, json.dumps(REPORT), ""), ToolRun(["x"], 70, "", "err"), ToolRun(["x"], 2, json.dumps(REPORT), "")):
        with pytest.raises(ValueError):
            parse_report(run)


# --------------------------------------------------------------------------------------------- sweeper

def test_sweeper_removes_only_old_owned_saferun_leftovers(tmp_path):
    root = tmp_path / "t"
    root.mkdir()
    old, fresh, other = root / "saferun-up-old", root / "saferun-up-fresh", root / "unrelated-dir"
    for d in (old, fresh, other):
        d.mkdir()
        (d / "f").write_text("x")
    upl = root / "saferun-upl-old.zip"
    upl.write_text("x")
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep").write_text("x")
    link = root / "saferun-up-link"
    link.symlink_to(victim)
    t = time.time() - 100_000
    for p in (old, upl):
        os.utime(p, (t, t))
    os.utime(link, (t, t), follow_symlinks=False)
    removed = jobs.sweep_stale(3600, tmp_root=root)
    assert sorted(removed) == ["saferun-up-link", "saferun-up-old", "saferun-upl-old.zip"]
    assert fresh.exists() and other.exists() and (victim / "keep").exists()    # symlink removed, target untouched


def test_job_limits_validate():
    for bad in ({"max_queue": 0}, {"job_deadline_s": -1}, {"result_ttl_s": float("inf")}):
        with pytest.raises(ValueError):
            JobLimits(**bad)
    assert (JobLimits().job_deadline_s, JobLimits().max_queue, JobLimits().result_ttl_s) == (600, 4, 1800)
