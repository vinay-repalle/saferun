"""Stage 2: self-provisioned cosign, Docker diagnosis, `saferun doctor`, `saferun run`, OSV retry/--if-stale. No Docker or network needed."""
import hashlib
import io
import os
import urllib.error
from types import SimpleNamespace

import pytest

from saferun import cli, doctor, dockerdiag, runcmd
from saferun import setup as st
from saferun.engine import osvdb
from saferun.engine.model import ValidationReport, Verdict
from saferun.sandbox import SandboxError, cosign_tool, images as im, signature


# ------------------------------------------------------------------------------------------------ cosign_tool
def data_home(monkeypatch, path):
    """Point SafeRun's per-user data directory at `path` on every platform (Windows ignores XDG_DATA_HOME and uses LOCALAPPDATA)."""
    monkeypatch.setenv("XDG_DATA_HOME", path)
    monkeypatch.setenv("LOCALAPPDATA", path)


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


@pytest.fixture
def tool_home(tmp_path, monkeypatch):
    data_home(monkeypatch, str(tmp_path / "data"))
    monkeypatch.setattr(cosign_tool.hostos, "IS_MACOS", False)
    return tmp_path


def pin(monkeypatch, payload: bytes):
    monkeypatch.setattr(cosign_tool, "asset_for", lambda *a: ("cosign-test", hashlib.sha256(payload).hexdigest()))


def test_pinned_table_is_complete_and_well_formed():
    assert cosign_tool.COSIGN_VERSION in cosign_tool.BASE_URL and cosign_tool.BASE_URL.startswith("https://")
    for (system, machine), (name, sha) in cosign_tool.ASSETS.items():
        assert len(sha) == 64 and set(sha) <= set("0123456789abcdef")
        assert name.endswith(".exe") == (system == "windows")
    assert cosign_tool.platform_key("Linux", "amd64") == ("linux", "x86_64")
    assert cosign_tool.platform_key("Darwin", "arm64") == ("darwin", "arm64")
    assert cosign_tool.platform_key("Linux", "arm64") == ("linux", "aarch64")
    with pytest.raises(SandboxError):
        cosign_tool.asset_for("freebsd", "x86_64")


def test_release_workflow_uses_the_same_cosign_version():
    wf = open(os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "release-analyzer.yml"), encoding="utf-8").read()
    assert f"cosign-release: v{cosign_tool.COSIGN_VERSION}" in wf


def test_download_with_matching_hash_is_installed_executable(tool_home, monkeypatch):
    data = b"fake cosign binary"
    pin(monkeypatch, data)
    path = cosign_tool.ensure_cosign(opener=lambda url, timeout: FakeResp(data))
    assert open(path, "rb").read() == data
    if os.name == "posix":
        assert os.stat(path).st_mode & 0o777 == 0o700
    assert cosign_tool.managed_cosign() == path
    assert [p.name for p in cosign_tool.tool_dir().iterdir()] == [cosign_tool.managed_path().name]   # no temp files left


def test_hash_mismatch_is_refused_and_nothing_is_installed(tool_home, monkeypatch):
    pin(monkeypatch, b"expected")
    with pytest.raises(cosign_tool.CosignFetchError, match="pinned SHA-256"):
        cosign_tool.ensure_cosign(opener=lambda url, timeout: FakeResp(b"evil"))
    assert cosign_tool.managed_cosign() is None
    assert list(cosign_tool.tool_dir().iterdir()) == []


def test_network_failure_is_a_clean_error(tool_home, monkeypatch):
    pin(monkeypatch, b"x")
    def boom(url, timeout):
        raise urllib.error.URLError("no route")
    with pytest.raises(cosign_tool.CosignFetchError, match="could not download"):
        cosign_tool.ensure_cosign(opener=boom)


def test_oversized_download_is_refused(tool_home, monkeypatch):
    pin(monkeypatch, b"x")
    monkeypatch.setattr(cosign_tool, "MAX_BYTES", 10)
    with pytest.raises(cosign_tool.CosignFetchError, match="exceeds"):
        cosign_tool.ensure_cosign(opener=lambda url, timeout: FakeResp(b"y" * 100))


def test_modified_managed_binary_is_ignored(tool_home, monkeypatch):
    data = b"good"
    pin(monkeypatch, data)
    path = cosign_tool.ensure_cosign(opener=lambda url, timeout: FakeResp(data))
    os.chmod(path, 0o700)
    with open(path, "wb") as f:
        f.write(b"tampered")
    assert cosign_tool.managed_cosign() is None


def test_find_cosign_prefers_the_verified_managed_copy(monkeypatch):
    monkeypatch.setattr(cosign_tool, "managed_cosign", lambda: "/managed/cosign")
    monkeypatch.setattr(signature.shutil, "which", lambda n: "/usr/bin/cosign")
    assert signature.find_cosign() == "/managed/cosign"
    monkeypatch.setattr(cosign_tool, "managed_cosign", lambda: None)
    assert signature.find_cosign() == os.path.abspath("/usr/bin/cosign")
    monkeypatch.setattr(signature.shutil, "which", lambda n: None)
    assert signature.find_cosign() is None


def test_signature_check_is_unchanged_without_cosign():
    rel = im.AnalyzerRelease(im.ANALYZER_REGISTRY_REPOSITORY, "sha256:" + "a" * 64, "2026-01-01")
    with pytest.raises(signature.CosignMissing):
        signature.verify_release_signature(rel, which=lambda: None)


# ------------------------------------------------------------------------------------------------ init wiring
def make_setup(**kw):
    pulled = []
    s = st.Setup(out=io.StringIO(), err=io.StringIO(), pull=lambda ref: pulled.append(ref) or 0, status=lambda k: st.Status(k, st.READY),
                 online=lambda h: True, daemon_check=lambda: None, **kw)
    return s, pulled


def test_init_never_pulls_when_cosign_cannot_be_obtained():
    def no_cosign():
        raise cosign_tool.CosignFetchError("offline")
    s, pulled = make_setup(ensure_cosign=no_cosign, verify_signature=lambda rel: pytest.fail("must not verify without cosign"))
    err = s._install_analyzer_release(im.ANALYZER_RELEASE)
    assert "Nothing was pulled" in err and pulled == []


def test_init_never_pulls_when_the_signature_is_bad():
    def bad(rel):
        raise signature.SignatureError("wrong identity")
    s, pulled = make_setup(ensure_cosign=lambda: None, verify_signature=bad)
    assert "NOT pulled" in s._install_analyzer_release(im.ANALYZER_RELEASE) and pulled == []


def test_analyzer_release_is_untouched_by_stage2():
    assert im.ANALYZER_RELEASE is not None and im.ANALYZER_RELEASE.digest.startswith("sha256:6f26c3e3")


# ------------------------------------------------------------------------------------------------ docker diagnosis
def fake_run(rc=0, out="29.0\n", err=""):
    return lambda *a, **k: SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def test_docker_not_installed_gives_platform_guidance():
    for plat, word in (("linux", "docs.docker.com/engine"), ("macos", "mac-install"), ("windows", "windows-install")):
        d = dockerdiag.diagnose(which=lambda n: None, platform=plat)
        assert d.state == dockerdiag.NOT_INSTALLED and word in d.guidance and not d.ok


def test_docker_permission_denied_and_daemon_down_and_ok_and_remote():
    w = lambda n: "/usr/bin/docker"  # noqa: E731
    d = dockerdiag.diagnose(which=w, run=fake_run(1, "", "permission denied while trying to connect to the Docker daemon socket"), platform="linux")
    assert d.state == dockerdiag.PERMISSION and "usermod" in d.guidance
    d = dockerdiag.diagnose(which=w, run=fake_run(1, "", "Cannot connect to the Docker daemon. Is the docker daemon running?"), platform="macos")
    assert d.state == dockerdiag.DAEMON_DOWN and "Docker Desktop" in d.guidance
    assert dockerdiag.diagnose(which=w, run=fake_run(), check_local=lambda: None, platform="linux").ok
    def remote():
        raise SandboxError("refusing non-local docker endpoint")
    assert dockerdiag.diagnose(which=w, run=fake_run(), check_local=remote, platform="linux").state == dockerdiag.REMOTE


def test_init_reports_docker_guidance_and_installs_nothing():
    d = dockerdiag.DockerDiagnosis(dockerdiag.NOT_INSTALLED, "Docker is not installed", "Install it: https://x")
    pulled = []
    s = st.Setup(out=io.StringIO(), err=io.StringIO(), pull=lambda r: pulled.append(r) or 0, status=lambda k: st.Status(k, st.MISSING, "x"),
                 online=lambda h: True, diagnose=lambda: d, osv_update=lambda *a: None, free_bytes=lambda p: 10**12)
    rc = s.run(["python", "analyzer"])
    out = s.out.getvalue()
    assert rc == 1 and pulled == [] and "Install it: https://x" in out


# ------------------------------------------------------------------------------------------------ doctor
def status_of(**states):
    return lambda key: st.Status(key, states.get(key, st.READY), "detail")


def ok_docker():
    return dockerdiag.DockerDiagnosis(dockerdiag.OK, "Docker 29 is running and local")


def test_doctor_all_good(tmp_path, monkeypatch):
    data_home(monkeypatch, str(tmp_path))
    checks = doctor.run_checks(status=status_of(), diagnose=ok_docker)
    assert doctor.exit_code(checks) == 0 and all(c.level in (doctor.PASS, doctor.WARN) for c in checks)


def test_doctor_levels_for_problems(tmp_path, monkeypatch):
    data_home(monkeypatch, str(tmp_path))
    checks = {c.name: c for c in doctor.run_checks(status=status_of(**{"osv-db": st.OUTDATED, "analyzer": st.INVALID, "node": st.MISSING}), diagnose=ok_docker)}
    assert checks["OSV database"].level == doctor.WARN          # stale is shown, never silently current
    assert checks["Analyzer image"].level == doctor.FAIL and "--repair" in checks["Analyzer image"].fix
    assert checks["Node.js sandbox image"].level == doctor.FAIL
    assert doctor.exit_code(list(checks.values())) == 1


def test_doctor_without_docker_fails_image_checks_instead_of_passing(tmp_path, monkeypatch):
    data_home(monkeypatch, str(tmp_path))
    d = dockerdiag.DockerDiagnosis(dockerdiag.DAEMON_DOWN, "daemon down", "start it")
    checks = {c.name: c for c in doctor.run_checks(status=status_of(), diagnose=lambda: d)}
    assert checks["Docker"].level == doctor.FAIL and checks["Analyzer image"].level == doctor.FAIL


def test_doctor_python_and_os_checks():
    assert doctor.check_python((3, 11, 0)).level == doctor.FAIL
    assert doctor.check_python((3, 12, 1)).level == doctor.PASS
    assert doctor.check_os("plan9").level == doctor.FAIL


def test_doctor_is_read_only_and_json_valid(tmp_path, monkeypatch):
    import json
    data_home(monkeypatch, str(tmp_path / "nothing"))
    checks = doctor.run_checks(status=status_of(), diagnose=ok_docker)
    assert not (tmp_path / "nothing").exists()
    assert json.loads(doctor.render_json(checks))["schema_version"] == 1
    assert "[PASS" in doctor.render_text(checks)


def test_doctor_online_signature_failure_is_fail():
    def bad(rel):
        raise signature.SignatureError("nope")
    assert doctor.check_signature_online(verify=bad).level == doctor.FAIL
    assert doctor.check_signature_online(verify=lambda rel: 1).level == doctor.PASS


def test_doctor_command_registered():
    assert cli.build_parser().parse_args(["doctor", "--format", "json", "--color", "never"]).command == "doctor"


# ------------------------------------------------------------------------------------------------ OSV
def test_osv_open_retries_transient_then_succeeds():
    calls = []
    def opener(url, timeout):
        calls.append(1)
        if len(calls) < 3:
            raise urllib.error.URLError("temporary")
        return "ok"
    assert osvdb._open(opener, "https://x/a.zip", sleep=lambda s: None) == "ok" and len(calls) == 3


def test_osv_open_gives_a_clear_error_and_does_not_retry_404():
    def down(url, timeout):
        raise urllib.error.URLError("dns")
    with pytest.raises(osvdb.OsvNetworkError, match="Existing data was left untouched"):
        osvdb._open(down, "https://x", sleep=lambda s: None)
    n = []
    def nf(url, timeout):
        n.append(1)
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)
    with pytest.raises(osvdb.OsvNetworkError, match="404"):
        osvdb._open(nf, "https://x", sleep=lambda s: None)
    assert len(n) == 1


def test_osv_update_failure_keeps_existing_data(tmp_path):
    def down(url, timeout):
        raise urllib.error.URLError("dns")
    with pytest.raises(osvdb.OsvNetworkError):
        osvdb.update(tmp_path / "db", opener=down, sleep=lambda s: None)
    assert not list((tmp_path / "db").rglob("all.zip"))


def test_osv_if_stale_flag_exists():
    a = cli.build_parser().parse_args(["osv-db", "update", "--if-stale"])
    assert a.if_stale is True


# ------------------------------------------------------------------------------------------------ run
def report(verdict):
    return ValidationReport(verdict=verdict, reasons=[], complete=verdict is Verdict.PASS, checks=[])


class Recorder:
    def __init__(self, exit_code=0, **kw):
        self.calls = []
        self.res = SimpleNamespace(exit_code=exit_code, stdout="out\n", stderr="", timed_out=False, oom_killed=False, output_truncated=False, **kw)

    def __call__(self, root, command, **kw):
        self.calls.append((root, command, kw))
        assert (root / command[2].removeprefix("/workspace/")).is_file()   # the staged script exists while the sandbox runs
        return self.res


def go(tmp_path, verdict, script_name="s.py", rec=None, **kw):
    script = tmp_path / script_name
    script.write_text("print(1)\n")
    rec = rec or Recorder()
    out, err = io.StringIO(), io.StringIO()
    rc = runcmd.run_script(str(script), kw.pop("args", []), out=out, err=err, scan=lambda root, opts: report(verdict), sandbox=rec, **kw)
    return rc, rec, out.getvalue(), err.getvalue()


def test_run_fail_verdict_never_executes(tmp_path):
    rc, rec, _, err = go(tmp_path, Verdict.FAIL)
    assert rc == runcmd.EXIT_FAIL and rec.calls == [] and "NOT run" in err


def test_run_fail_is_never_overridden_by_allow_warnings(tmp_path):
    rc, rec, _, _ = go(tmp_path, Verdict.FAIL, allow_warnings=True)
    assert rc == runcmd.EXIT_FAIL and rec.calls == []


def test_run_warning_is_refused_by_default_and_when_incomplete(tmp_path):
    rc, rec, _, _ = go(tmp_path, Verdict.WARNING)
    assert rc == runcmd.EXIT_WARNING and rec.calls == []
    rc, rec, _, _ = go(tmp_path, Verdict.WARNING, allow_warnings=True)      # this report is incomplete: never overridden
    assert rc == runcmd.EXIT_WARNING and rec.calls == []


def test_run_pass_executes_only_via_the_sandbox_with_argv_and_pinned_image(tmp_path):
    rc, rec, out, err = go(tmp_path, Verdict.PASS, args=["a b", "; rm -rf /"], timeout_s=5)
    root, command, kw = rec.calls[0]
    assert command == ["python", "-I", "/workspace/s.py", "a b", "; rm -rf /"]      # argv, never a shell
    assert kw["image"] == runcmd.PYTHON.image and "@sha256:" in kw["image"] and kw["limits"].timeout_s == 5
    assert rc == 0 and out.endswith("out\n") and "not proof of safety" in err


def test_run_stages_only_the_script_not_its_directory(tmp_path):
    (tmp_path / "secret.txt").write_text("x")
    seen = {}
    def scan(root, opts):
        seen["files"] = sorted(p.name for p in root.iterdir())
        return report(Verdict.PASS)
    script = tmp_path / "s.py"
    script.write_text("pass\n")
    runcmd.run_script(str(script), [], out=io.StringIO(), err=io.StringIO(), scan=scan, sandbox=Recorder())
    assert seen["files"] == ["s.py"]


def test_run_script_failure_exit_code(tmp_path):
    rc, *_ = go(tmp_path, Verdict.PASS, rec=Recorder(exit_code=7))
    assert rc == runcmd.EXIT_SCRIPT_FAILED
    rec = Recorder()
    rec.res.timed_out = True
    rc, *_ = go(tmp_path, Verdict.PASS, rec=rec)
    assert rc == runcmd.EXIT_SCRIPT_FAILED


def test_run_scan_error_means_no_execution(tmp_path):
    script = tmp_path / "s.py"
    script.write_text("pass\n")
    rec = Recorder()
    def boom(root, opts):
        raise SandboxError("analyzer missing")
    err = io.StringIO()
    rc = runcmd.run_script(str(script), [], out=io.StringIO(), err=err, scan=boom, sandbox=rec)
    assert rc == runcmd.EXIT_FATAL and rec.calls == []
    rc = runcmd.run_script(str(script), [], out=io.StringIO(), err=err, scan=lambda *a: 1 / 0, sandbox=rec)
    assert rc == runcmd.EXIT_FATAL and rec.calls == []


def test_run_sandbox_error_is_reported_not_run_on_host(tmp_path):
    def refuse(root, command, **kw):
        raise SandboxError("docker down")
    rc, *_ = go(tmp_path, Verdict.PASS, rec=refuse)
    assert rc == runcmd.EXIT_FATAL


def test_run_rejects_bad_scripts(tmp_path):
    for name in ("x.sh", "x.txt"):
        rc, rec, _, _ = go(tmp_path, Verdict.PASS, script_name=name)
        assert rc == runcmd.EXIT_USAGE and rec.calls == []
    for path in (tmp_path / "missing.py", tmp_path):
        rc = runcmd.run_script(str(path), [], out=io.StringIO(), err=io.StringIO(), scan=lambda *a: pytest.fail("scanned"), sandbox=Recorder())
        assert rc == runcmd.EXIT_USAGE


@pytest.mark.skipif(os.name != "posix", reason="symlinks")
def test_run_refuses_symlinked_script(tmp_path):
    real = tmp_path / "real.py"
    real.write_text("pass\n")
    link = tmp_path / "link.py"
    link.symlink_to(real)
    rc = runcmd.run_script(str(link), [], out=io.StringIO(), err=io.StringIO(), scan=lambda *a: pytest.fail("scanned"), sandbox=Recorder())
    assert rc == runcmd.EXIT_USAGE


def test_run_project_dir_must_contain_the_script(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    outside = tmp_path / "o.py"
    outside.write_text("pass\n")
    rc = runcmd.run_script(str(outside), [], project_dir=str(proj), out=io.StringIO(), err=io.StringIO(), scan=lambda *a: pytest.fail(), sandbox=Recorder())
    assert rc == runcmd.EXIT_USAGE
    (proj / "m.py").write_text("pass\n")
    rec = Recorder()
    rc = runcmd.run_script(str(proj / "m.py"), [], project_dir=str(proj), out=io.StringIO(), err=io.StringIO(), scan=lambda *a: report(Verdict.PASS), sandbox=rec)
    assert rc == 0 and rec.calls[0][0] == proj.resolve()


def test_run_command_parses_args():
    a = cli.build_parser().parse_args(["run", "--timeout", "9", "s.py", "--", "x", "--flag"])
    assert a.script == "s.py" and a.timeout == 9 and a.script_args == ["x", "--flag"]


# ------------------------------------------------------------------------------------------------ approved follow-ups
def test_package_name_is_saferun_cli_and_command_unchanged():
    import tomllib
    t = tomllib.load(open(os.path.join(os.path.dirname(__file__), "..", "pyproject.toml"), "rb"))
    assert t["project"]["name"] == "saferun-cli" and t["project"]["scripts"] == {"saferun": "saferun.cli:main"}


def report_with(verdict, *, complete=True, checks=(), findings=()):
    from saferun.engine.model import CheckResult
    return ValidationReport(verdict=verdict, reasons=[], complete=complete, checks=[CheckResult(n, s, list(findings) if n == "x" else []) for n, s in checks])


def finding(sev):
    from saferun.engine.model import Finding
    return Finding("x", "rule.id", sev, "m")


def go_report(tmp_path, rep, allow):
    script = tmp_path / "s.py"
    script.write_text("pass\n")
    rec = Recorder()
    err = io.StringIO()
    rc = runcmd.run_script(str(script), [], out=io.StringIO(), err=err, allow_warnings=allow, scan=lambda r, o: rep, sandbox=rec)
    return rc, rec, err.getvalue()


def test_allow_warnings_runs_only_a_complete_scan_with_minor_findings(tmp_path):
    from saferun.engine.model import CheckStatus as C, Severity as S
    rep = report_with(Verdict.WARNING, checks=[("x", C.FINDINGS), ("y", C.NOT_APPLICABLE)])
    rep.checks[0].findings = [finding(S.MEDIUM)]
    rc, rec, _ = go_report(tmp_path, rep, allow=True)
    assert rc == 0 and len(rec.calls) == 1
    rc, rec, _ = go_report(tmp_path, rep, allow=False)
    assert rc == runcmd.EXIT_WARNING and rec.calls == []


@pytest.mark.parametrize("status", ["INCOMPLETE", "ERROR", "TIMEOUT", "UNAVAILABLE", "SKIPPED"])
def test_allow_warnings_never_overrides_an_unfinished_check(tmp_path, status):
    from saferun.engine.model import CheckStatus as C
    rep = report_with(Verdict.WARNING, checks=[("x", getattr(C, status))])
    rc, rec, err = go_report(tmp_path, rep, allow=True)
    assert rc == runcmd.EXIT_WARNING and rec.calls == [] and "NOT run" in err


def test_allow_warnings_never_overrides_an_incomplete_scan_or_serious_finding(tmp_path):
    from saferun.engine.model import CheckStatus as C, Severity as S
    rc, rec, _ = go_report(tmp_path, report_with(Verdict.WARNING, complete=False, checks=[("x", C.PASSED)]), allow=True)
    assert rc == runcmd.EXIT_WARNING and rec.calls == []
    for sev in (S.HIGH, S.CRITICAL):
        rep = report_with(Verdict.WARNING, checks=[("x", C.FINDINGS)])
        rep.checks[0].findings = [finding(sev)]
        rc, rec, _ = go_report(tmp_path, rep, allow=True)
        assert rc == runcmd.EXIT_WARNING and rec.calls == []


def test_stale_ecosystems_only_lists_what_needs_downloading(tmp_path, monkeypatch, low_osv_floor):
    import json
    from engine_helpers import make_osv_db
    db = make_osv_db(tmp_path / "db")
    assert osvdb.stale_ecosystems(db) == []                                    # valid and fresh: nothing to download
    m = json.loads((db / "manifest.json").read_text())
    m["ecosystems"]["npm"]["updated_epoch"] -= 90 * 86400                       # only npm becomes stale
    (db / "manifest.json").write_text(json.dumps(m))
    assert osvdb.stale_ecosystems(db) == ["npm"]
    assert osvdb.stale_ecosystems(tmp_path / "missing") == list(osvdb.ECOSYSTEMS)


def test_init_osv_failure_reports_state_and_leaves_data(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "db"))
    def down(d, progress):
        raise osvdb.OsvNetworkError("cannot reach the OSV server (dns)")
    s = st.Setup(out=io.StringIO(), err=io.StringIO(), status=lambda k: st.Status(k, st.MISSING, "x"), online=lambda h: True,
                 daemon_check=lambda: None, osv_update=down, free_bytes=lambda p: 10**12)
    err = s._install_osv()
    assert "No usable local OSV data" in err and "INCOMPLETE" in err and "untouched" in err


def test_init_offline_osv_reports_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "db"))
    s = st.Setup(out=io.StringIO(), err=io.StringIO(), status=lambda k: st.Status(k, st.OUTDATED, "old"), online=lambda h: False,
                 daemon_check=lambda: None)
    assert s.run(["osv-db"], assume_yes=True) == 1
    assert "no internet access" in s.out.getvalue() and "INCOMPLETE" in s.out.getvalue()


def test_init_skips_a_current_osv_database_and_says_how_old(tmp_path):
    called = []
    s = st.Setup(out=io.StringIO(), err=io.StringIO(), status=lambda k: st.Status(k, st.READY, "3.0 days old, integrity manifest verified"),
                 online=lambda h: True, daemon_check=lambda: None, osv_update=lambda *a: called.append(a))
    assert s.run(["osv-db"]) == 0 and called == [] and "3.0 days old" in s.out.getvalue()


# ------------------------------------------------------------------------------------------------ fresh-machine regression
@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_cosign_fetch_on_a_fresh_machine_leaves_the_lock_directory_trustworthy(tool_home, monkeypatch):
    """Found by the clean-install test: the cosign step used to create <data>/saferun with the default mode (0775), after which the analyzer
    lock was refused ('accessible to others'). Whatever creates the directory first must leave it owner-only."""
    from saferun.sandbox import analyzer as sa
    monkeypatch.delenv("SAFERUN_ANALYZER_LOCK", raising=False)
    monkeypatch.setattr(os, "umask", os.umask)
    old = os.umask(0o002)
    try:
        data = b"fake cosign"
        pin(monkeypatch, data)
        cosign_tool.ensure_cosign(opener=lambda url, timeout: FakeResp(data))
    finally:
        os.umask(old)
    base = cosign_tool.tool_dir().parent
    assert base.stat().st_mode & 0o777 == 0o700
    assert sa._lock_problem(base / "analyzer-image-id") is None
    assert sa.write_lock("sha256:" + "a" * 64).parent == base


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_osv_download_first_also_leaves_the_lock_directory_trustworthy(tmp_path, monkeypatch):
    from saferun.sandbox import analyzer as sa
    data_home(monkeypatch, str(tmp_path))
    monkeypatch.delenv("SAFERUN_OSV_DB", raising=False)
    monkeypatch.delenv("SAFERUN_ANALYZER_LOCK", raising=False)
    old = os.umask(0o002)
    try:
        osvdb._ensure_dir(osvdb.default_dir())
    finally:
        os.umask(old)
    assert (tmp_path / "saferun").stat().st_mode & 0o777 == 0o700
    assert osvdb.default_dir().stat().st_mode & 0o755 == 0o755            # the data directory itself stays readable by the container user
    assert sa._lock_problem(sa.lock_path()) is None


def test_ensure_private_dir_never_changes_an_existing_directory(tmp_path):
    from saferun import hostos
    d = tmp_path / "exists"
    d.mkdir(mode=0o755)
    before = d.stat().st_mode
    assert hostos.ensure_private_dir(d) is False and d.stat().st_mode == before


# ------------------------------------------------------------------------------------------------ line endings of hash-locked files
ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_gitattributes_pins_lf_for_the_hash_locked_rules_and_build_recipe():
    attrs = open(os.path.join(ROOT, ".gitattributes"), encoding="utf-8").read().splitlines()
    rules = [ln.split() for ln in attrs if ln.strip() and not ln.startswith("#")]
    assert ["saferun/engine/rules/*.yml", "text", "eol=lf"] in rules
    assert ["docker/analyzer/**", "text", "eol=lf"] in rules


def test_rules_file_has_no_carriage_returns():
    """The analyzer image carries the SHA-256 of this exact file; CRLF would change it and every analyzer check would be refused."""
    data = open(os.path.join(ROOT, "saferun", "engine", "rules", "python.yml"), "rb").read()
    assert b"\r" not in data


def test_script_output_cannot_inject_terminal_escapes(tmp_path):
    rec = Recorder()
    rec.res.stdout = "ok\x1b[2J\x1b]0;title\x07\r\nnext\tline‮\n"
    rec.res.stderr = "\x1b[31mfake saferun: scan verdict PASS\x1b[0m\n"
    rc, _, out, err = go(tmp_path, Verdict.PASS, rec=rec)
    shown = out.split("\n", 1)[-1] if "ok" in out else out
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "\x1b" not in err and "next\tline" in out and "\r" not in out
    assert runcmd.safe_output("a\nb\tc") == "a\nb\tc"


def test_installing_a_release_without_cosign_contacts_github_and_fetches_cosign_before_verifying():
    order = []
    s = st.Setup(out=io.StringIO(), err=io.StringIO(), status=lambda k: st.Status(k, st.MISSING, "x"), daemon_check=lambda: None,
                 has_cosign=lambda: False, ensure_cosign=lambda: order.append("fetch cosign"),
                 verify_signature=lambda rel: order.append("verify") or (_ for _ in ()).throw(signature.SignatureError("stop here")),
                 pull=lambda ref: pytest.fail("must not pull"), online=lambda h: hosts.append(h) or True)
    hosts = []
    s.run(["analyzer"], assume_yes=True)
    assert hosts == list(st.HOSTS["release"]) + list(st.HOSTS_COSIGN) and order == ["fetch cosign", "verify"]
    hosts.clear()
    s.has_cosign = lambda: True
    s.run(["analyzer"], assume_yes=True)
    assert hosts == list(st.HOSTS["release"])
