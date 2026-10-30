"""Phase 5B: analyzer isolation. Unit tests with fakes first (no Docker), then real-container tests against the built analyzer image
(skipped visibly when `docker/analyzer/build.sh` has not been run)."""
import ast
import base64
import hashlib
import io
import json
import subprocess
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import REQUIRE_DOCKER
from saferun import cli
from saferun.engine import CheckStatus, ValidationOptions, Verdict, analyzer as engine_analyzer, osv, osvdb, semgrep, validate_project
from saferun.engine.tools import ToolRun
from saferun.sandbox import SandboxError, SandboxLimits, run_sandboxed
from saferun.sandbox import analyzer as sa
from saferun.sandbox import docker as dk
from saferun.sandbox import images, runner, verify
from saferun.sandbox.controls import verify_applied_config

ROOT = Path(__file__).resolve().parent.parent
GOOD_ID = "sha256:" + "c" * 64


def proc(rc=0, out="", err=""):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def good_labels():
    return {"saferun.analyzer": "1", "saferun.semgrep.version": images.SEMGREP_VERSION,
            "saferun.osv-scanner.version": images.OSV_SCANNER_VERSION, "saferun.rules.sha256": sa.rules_sha256()}


def inspect_json(image_id=GOOD_ID, labels=None):
    return json.dumps({"Id": image_id, "Config": {"Labels": good_labels() if labels is None else labels}})


@pytest.fixture
def lock(tmp_path, monkeypatch):
    d = tmp_path / "lockdir"
    d.mkdir(mode=0o700)
    d.chmod(0o700)
    p = d / "analyzer-image-id"
    p.write_text(GOOD_ID + "\n")
    p.chmod(0o600)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(p))
    return p


def fake_inspect(monkeypatch, out=None, rc=0, err=""):
    monkeypatch.setattr(dk, "docker", lambda *a, timeout=None: proc(rc, out if out is not None else inspect_json(), err))


# ---------------------------------------------------------------- analyzer image verification (fail closed)

def test_verify_analyzer_image_accepts_the_locked_image(lock, monkeypatch):
    fake_inspect(monkeypatch)
    assert sa.verify_analyzer_image() == GOOD_ID


def test_missing_lock_file_is_unavailable(tmp_path, monkeypatch):
    (tmp_path / "d").mkdir(mode=0o700)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(tmp_path / "d" / "absent"))
    fake_inspect(monkeypatch)
    with pytest.raises(sa.AnalyzerUnavailable, match="saferun init --only analyzer"):
        sa.verify_analyzer_image()


@pytest.mark.parametrize("text", ["", "garbage", "sha256:abc", GOOD_ID.upper(), GOOD_ID + "extra"])
def test_malformed_lock_file_is_an_integrity_error(lock, monkeypatch, text):
    lock.write_text(text)
    fake_inspect(monkeypatch)
    with pytest.raises(sa.AnalyzerIntegrityError):
        sa.verify_analyzer_image()


def test_image_not_present_is_unavailable(lock, monkeypatch):
    fake_inspect(monkeypatch, rc=1, err="Error response from daemon: No such image: saferun-analyzer:local")
    with pytest.raises(sa.AnalyzerUnavailable, match="not present"):
        sa.verify_analyzer_image()


def test_docker_unavailable_is_unavailable_not_a_crash(lock, monkeypatch):
    fake_inspect(monkeypatch, rc=1, err="Cannot connect to the Docker daemon")
    with pytest.raises(sa.AnalyzerUnavailable):
        sa.verify_analyzer_image()

    def boom(*a, **k):
        raise SandboxError("docker image failed: timeout")
    monkeypatch.setattr(dk, "docker", boom)
    with pytest.raises(SandboxError):
        sa.verify_analyzer_image()


def test_image_id_mismatch_is_refused(lock, monkeypatch):
    fake_inspect(monkeypatch, inspect_json("sha256:" + "d" * 64))
    with pytest.raises(sa.AnalyzerIntegrityError, match="ID mismatch"):
        sa.verify_analyzer_image()


@pytest.mark.parametrize("label", ["saferun.analyzer", "saferun.semgrep.version", "saferun.osv-scanner.version", "saferun.rules.sha256"])
def test_wrong_or_missing_label_is_refused(lock, monkeypatch, label):
    wrong = {**good_labels(), label: "tampered"}
    fake_inspect(monkeypatch, inspect_json(labels=wrong))
    with pytest.raises(sa.AnalyzerIntegrityError, match=label.replace(".", r"\.")):
        sa.verify_analyzer_image()
    missing = {k: v for k, v in good_labels().items() if k != label}
    fake_inspect(monkeypatch, inspect_json(labels=missing))
    with pytest.raises(sa.AnalyzerIntegrityError):
        sa.verify_analyzer_image()


@pytest.mark.parametrize("out", ["", "not json", "[]", "null", json.dumps({"Id": 5}), json.dumps({"Id": GOOD_ID, "Config": {"Labels": 3}})])
def test_unexpected_inspect_output_is_refused(lock, monkeypatch, out):
    fake_inspect(monkeypatch, out)
    with pytest.raises(sa.AnalyzerIntegrityError):
        sa.verify_analyzer_image()


def test_rules_change_invalidates_the_image(lock, monkeypatch):
    fake_inspect(monkeypatch, inspect_json())                       # labels computed from the real rules file now
    monkeypatch.setattr(sa, "rules_sha256", lambda: "0" * 64)       # the checkout's rules differ from the baked-in ones
    with pytest.raises(sa.AnalyzerIntegrityError, match="rules"):
        sa.verify_analyzer_image()


def test_verify_images_reports_the_analyzer(lock, monkeypatch):
    fake_inspect(monkeypatch)
    assert verify.check_analyzer().status == "verified"
    fake_inspect(monkeypatch, inspect_json("sha256:" + "d" * 64))
    assert verify.check_analyzer().status == "mismatch"
    fake_inspect(monkeypatch, rc=1, err="No such image")
    assert verify.check_analyzer().status == "missing"


# ---------------------------------------------------------------- the analyzer runner: image ID, mounts, no env, fail closed

def test_runner_uses_the_verified_image_id_mounts_and_ignores_host_env(tmp_path):
    seen = {}

    def sandbox(project, command, limits, image=None, readonly_mounts=()):
        seen.update(project=project, command=command, limits=limits, image=image, mounts=readonly_mounts)
        return SimpleNamespace(exit_code=0, stdout="{}", stderr="", timed_out=False, output_truncated=False, duration_s=0.5)
    r = engine_analyzer.analyzer_runner(["/usr/local/bin/semgrep", "scan"], cwd=tmp_path, env={"AWS_SECRET_ACCESS_KEY": "x"},
                                        timeout_s=9, max_output=1234, mounts=((tmp_path, "/osv-db"),), sandbox=sandbox, verify=lambda: GOOD_ID)
    assert seen["image"] == GOOD_ID and seen["mounts"] == ((tmp_path, "/osv-db"),) and seen["command"] == ["/usr/local/bin/semgrep", "scan"]
    assert seen["limits"].timeout_s == 9 and seen["limits"].max_output_bytes == 1234 and seen["limits"].memory_mb == 1536
    assert "AWS_SECRET_ACCESS_KEY" not in json.dumps(seen, default=str)
    assert r.exit_code == 0 and not r.timed_out and not r.output_truncated


def test_runner_maps_timeout_and_truncation_to_killed_runs(tmp_path):
    def sandbox_for(**kw):
        return lambda *a, **k: SimpleNamespace(exit_code=137, stdout="", stderr="", duration_s=1, **{"timed_out": False, "output_truncated": False, **kw})
    t = engine_analyzer.analyzer_runner(["/x"], cwd=tmp_path, timeout_s=1, max_output=1, sandbox=sandbox_for(timed_out=True), verify=lambda: GOOD_ID)
    assert t.timed_out and t.exit_code is None
    o = engine_analyzer.analyzer_runner(["/x"], cwd=tmp_path, timeout_s=1, max_output=1, sandbox=sandbox_for(output_truncated=True), verify=lambda: GOOD_ID)
    assert o.output_truncated and o.exit_code is None


def test_runner_never_reaches_the_sandbox_when_verification_fails(tmp_path):
    def sandbox(*a, **k):
        raise AssertionError("sandbox must not be called")

    def bad():
        raise sa.AnalyzerIntegrityError("mismatch")
    with pytest.raises(sa.AnalyzerIntegrityError):
        engine_analyzer.analyzer_runner(["/x"], cwd=tmp_path, timeout_s=1, max_output=1, sandbox=sandbox, verify=bad)


# ---------------------------------------------------------------- fallback prevention

def test_analyzer_checks_contain_no_host_execution_path():
    """Static: the Semgrep/OSV check modules cannot start host processes or look tools up on PATH."""
    for mod in ("semgrep.py", "osv.py", "analyzer.py"):
        tree = ast.parse((ROOT / "saferun" / "engine" / mod).read_text())
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | \
                {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
        imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
                   {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) if n.module}
        assert not ({"run_tool", "find_tool", "build_env", "Popen", "which", "system", "execv"} & names), mod
        assert not ({"subprocess", "shutil", "os.path"} & imported - {"os"}), mod


def test_no_host_process_is_started_when_the_analyzer_is_unavailable(tmp_path, ws_root, monkeypatch):
    """Dynamic: with the analyzer unavailable, a scan of a Python+npm project starts no host process at all and is never PASS."""
    def forbidden(*a, **k):
        raise AssertionError(f"host process started: {a!r}")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    p = tmp_path / "p"
    p.mkdir()
    (p / "app.py").write_text("eval(input())\n")
    (p / "package-lock.json").write_text("{}")

    def no_analyzer():
        raise sa.AnalyzerUnavailable("not built")
    from engine_helpers import smart_sandbox
    rep = validate_project(p, ctx_overrides={"sandbox": smart_sandbox(), "image_available": lambda i: None, "analyzer_available": no_analyzer})
    st = {c.name: c.status for c in rep.checks}
    assert st[semgrep.NAME] is CheckStatus.UNAVAILABLE and st[osv.NAME] is CheckStatus.UNAVAILABLE
    assert rep.verdict is Verdict.WARNING and not rep.complete and not any(f.check == semgrep.NAME for f in rep.findings)


def test_cli_with_unreachable_docker_never_falls_back_to_host_tools(tmp_path):
    """End to end in a child process: host `semgrep`/`osv-scanner` shims must not be started; analyzer checks are unavailable."""
    import os
    import stat
    import sys
    record = tmp_path / "rec"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("semgrep", "osv-scanner"):
        exe = bindir / name
        exe.write_text(f"#!/bin/sh\necho {name} >> {record}\nexit 0\n")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("eval(input())\n")
    (proj / "requirements.txt").write_text("django==2.2.0\n")
    env = {"PATH": f"{bindir}:{os.environ['PATH']}", "DOCKER_HOST": f"unix://{tmp_path}/no-docker.sock", "HOME": str(tmp_path),
           "SAFERUN_ANALYZER_LOCK": str(tmp_path / "lock")}
    p = subprocess.run([sys.executable, "-I", "-m", "saferun", "scan", str(proj), "--format", "json"], capture_output=True, text=True,
                       env=env, cwd=str(ROOT), timeout=120)
    assert p.returncode == 2, (p.returncode, p.stderr[-500:])             # WARNING: incomplete, never PASS and not FAIL from a fallback
    rep = json.loads(p.stdout)
    by = {c["name"]: c for c in rep["checks"]}
    assert by["python-static-analysis"]["status"] == "unavailable" and by["dependency-vulnerabilities"]["status"] == "unavailable"
    assert rep["verdict"] == "WARNING" and not rep["complete"] and not record.exists()


# ---------------------------------------------------------------- read-only extra mounts in the sandbox

def test_readonly_mount_validation(tmp_path):
    d = tmp_path / "db"
    d.mkdir()
    assert runner.validate_readonly_mounts([(d, "/osv-db")]) == ((d, "/osv-db"),)
    link = tmp_path / "link"
    link.symlink_to(d)
    f = tmp_path / "file"
    f.write_text("x")
    for bad in [(d, "/workspace"), (d, "/tmp"), (d, "/etc"), (d, "/"), (d, "osv-db"), (d, "/a/b"), (d, "/Osv"), (d, "/x,y"), (d, "/x;y"),
                (Path("/"), "/db"), (link, "/db"), (f, "/db"), (tmp_path / "missing", "/db"), (Path("relative"), "/db"),
                (tmp_path / "a,b", "/db"), ("only-one",), 5]:
        with pytest.raises(SandboxError):
            runner.validate_readonly_mounts([bad])
    with pytest.raises(SandboxError, match="duplicate"):
        runner.validate_readonly_mounts([(d, "/db"), (d, "/db")])


def test_create_args_mount_extra_directories_read_only_and_keep_the_network_off(tmp_path):
    d = tmp_path / "db"
    d.mkdir()
    args = runner.build_create_args("n", tmp_path, ["true"], "sha256:" + "a" * 64, SandboxLimits(), ((d, "/osv-db"),))
    mounts = [args[i + 1] for i, a in enumerate(args) if a == "--mount"]
    assert mounts == [f"type=bind,src={tmp_path},dst=/workspace,readonly", f"type=bind,src={d},dst=/osv-db,readonly"]
    assert args[args.index("--network") + 1] == "none" and "--read-only" in args and args[args.index("--cap-drop") + 1] == "ALL"
    base = runner.build_create_args("n", tmp_path, ["true"], "sha256:" + "a" * 64, SandboxLimits())
    assert len([a for a in base if a == "--mount"]) == 1                                  # unchanged without extras


def applied(mounts):
    from test_hardening import golden
    info = golden()
    info["HostConfig"]["Mounts"] = mounts
    return info


def test_applied_mount_set_is_verified_exactly():
    from test_hardening import IMAGE_ID
    ro = lambda t: {"Type": "bind", "Target": t, "ReadOnly": True}   # noqa: E731
    state = lambda mounts, extra=(): {c.name: c.state for c in verify_applied_config(applied(mounts), SandboxLimits(), IMAGE_ID, extra)}["workspace-mount-read-only"]  # noqa: E731
    assert state([ro("/workspace")]) == "verified"
    assert state([ro("/workspace"), ro("/osv-db")], ("/osv-db",)) == "verified"
    assert state([ro("/workspace"), ro("/osv-db")]) == "violated"                       # unexpected extra mount
    assert state([ro("/workspace")], ("/osv-db",)) == "violated"                         # expected mount missing
    assert state([ro("/workspace"), {"Type": "bind", "Target": "/osv-db", "ReadOnly": False}], ("/osv-db",)) == "violated"   # writable
    assert state([ro("/workspace"), {"Type": "volume", "Target": "/osv-db", "ReadOnly": True}], ("/osv-db",)) == "violated"
    assert state([ro("/workspace"), ro("/elsewhere")], ("/osv-db",)) == "violated"
    assert state([ro("/workspace"), None], ("/osv-db",)) == "violated"
    assert state([]) == "violated"


# ---------------------------------------------------------------- offline OSV data (download/validation tests: tests/test_osv_db_integrity.py)

def test_osv_db_default_dir_and_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path))
    assert osvdb.default_dir() == tmp_path
    monkeypatch.delenv("SAFERUN_OSV_DB")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert osvdb.default_dir() == tmp_path / "saferun" / "osv-db"


def test_cli_osv_db_update_exit_codes(monkeypatch, capsys, tmp_path):
    entry = {"sha256": "ab" * 32, "size": 5, "entries": 7, "md5": "verified"}
    monkeypatch.setattr(osvdb, "update", lambda d, allow_unverified=False: {"PyPI": entry, "npm": entry})
    assert cli.main(["osv-db", "update", "--dir", str(tmp_path)]) == 0
    assert "PyPI: 5 bytes, 7 advisories" in capsys.readouterr().out
    monkeypatch.setattr(osvdb, "update", lambda d, allow_unverified=False: (_ for _ in ()).throw(ValueError("boom")))
    assert cli.main(["osv-db", "update", "--dir", str(tmp_path)]) == 70
    assert "existing data left in place" in capsys.readouterr().err
    assert cli.main(["osv-db"]) == 64


def test_cli_scan_still_accepts_osv_offline(monkeypatch, tmp_path):
    seen = []
    from saferun import engine
    monkeypatch.setattr(cli, "validate_project", lambda path, options: seen.append(options) or engine.ValidationReport(
        Verdict.PASS, ["ok"], True, [], {"skipped": [], "withheld": []}))
    assert cli.main(["scan", str(tmp_path), "--osv-offline"]) == 0 and cli.main(["scan", str(tmp_path)]) == 0
    assert all(o.osv_offline for o in seen)                                # offline is the default and the only mode


# ---------------------------------------------------------------- build recipe

def test_dockerfile_bakes_pinned_rules_and_labels():
    text = (ROOT / "docker" / "analyzer" / "Dockerfile").read_text()
    assert "COPY python.yml /opt/saferun/rules/python.yml" in text and "sha256sum -c" in text and "ARG RULES_SHA256" in text
    for label in ("saferun.analyzer", "saferun.semgrep.version", "saferun.osv-scanner.version", "saferun.rules.sha256"):
        assert label in text
    sh = (ROOT / "docker" / "analyzer" / "build.sh").read_text()
    assert "verify-images --only python" in sh and sh.index("verify-images --only python") < sh.index("docker build")   # the analyzer needs only the Python base and "--pull=false" in sh and "RULES_SHA256=" in sh


# ================================================================ real analyzer container (needs docker/analyzer/build.sh)

def _built() -> bool:
    try:
        sa.verify_analyzer_image()
        return True
    except SandboxError:
        return False


BUILT = _built()
real = [pytest.mark.docker, pytest.mark.skipif(not BUILT and not REQUIRE_DOCKER, reason="analyzer image not built (docker/analyzer/build.sh)")]


def analyzer_run(tmp_path, command, limits=None, mounts=()):
    (tmp_path / "x").mkdir(exist_ok=True)
    return run_sandboxed(tmp_path / "x", command, limits or SandboxLimits(timeout_s=60), image=sa.verify_analyzer_image(), readonly_mounts=mounts)


@pytest.mark.docker
@pytest.mark.skipif(not BUILT, reason="analyzer image not built (docker/analyzer/build.sh)")
class TestRealAnalyzerContainer:
    def test_tools_run_inside_the_container_with_pinned_versions(self, tmp_path, ws_root):
        r = analyzer_run(tmp_path, ["sh", "-c", "/usr/local/bin/semgrep --version; /usr/local/bin/osv-scanner --version | head -1; id -u"])
        assert r.exit_code == 0, r.stderr
        lines = r.stdout.split("\n")
        assert lines[0] == images.SEMGREP_VERSION and lines[1] == f"osv-scanner version: {images.OSV_SCANNER_VERSION}" and lines[2] == "65534"

    def test_every_control_is_verified_for_the_analyzer_image_with_the_db_mount(self, tmp_path, ws_root):
        db = tmp_path / "db"
        db.mkdir()
        r = analyzer_run(tmp_path, ["true"], mounts=((db, "/osv-db"),))
        bad = [c for c in r.controls if c.state not in ("verified", "unavailable")]
        assert not bad and any(c.name == "workspace-mount-read-only" and c.state == "verified" for c in r.controls)
        assert any(c.name == "network-none" and c.state == "verified" for c in r.controls)

    def test_kernel_view_attestation_of_the_analyzer_image(self, tmp_path, ws_root):
        """Phase 1 attestation (reads /proc and /sys from inside) on the analyzer image: seccomp filter, no capabilities, no new
        privileges, AppArmor profile when the daemon has it. The AppArmor state is read from the host, not assumed."""
        from saferun.sandbox.attestation import attest
        rep = attest(sa.verify_analyzer_image())
        states = {c.name: c.state for c in rep.controls}
        assert rep.ok and not [n for n, s in states.items() if s == "violated"], states
        assert states["kernel-seccomp-filter"] == "verified"
        if states.get("daemon-apparmor") == "verified":
            assert states["kernel-apparmor-profile"] == "verified"

    def test_rules_and_database_are_read_only_and_root_fs_is_immutable(self, tmp_path, ws_root):
        db = tmp_path / "db"
        db.mkdir()
        (db / "f").write_text("x")
        code = ("import os\nfor p in ('/opt/saferun/rules/python.yml','/osv-db/new','/osv-db/f','/workspace/new','/usr/local/bin/semgrep','/etc/x'):\n"
                " try:\n  open(p,'w'); print('WRITABLE',p)\n except OSError as e: print('ro',p,e.errno)\n")
        r = analyzer_run(tmp_path, ["python", "-I", "-c", code], mounts=((db, "/osv-db"),))
        assert "WRITABLE" not in r.stdout and r.stdout.count("ro ") == 6, r.stdout

    def test_no_network_even_when_the_tool_is_asked_to_go_online(self, tmp_path, ws_root):
        """osv-scanner WITHOUT --offline inside the container cannot reach OSV.dev: nothing is found, and it is an error, not a clean pass."""
        x = tmp_path / "x"
        x.mkdir()
        (x / "requirements.txt").write_text("django==2.2.0\n")
        r = analyzer_run(tmp_path, ["/usr/local/bin/osv-scanner", "scan", "source", "--format", "json", "--no-resolve", "--lockfile=./requirements.txt"],
                         SandboxLimits(timeout_s=90))
        assert r.exit_code not in (0, 1), (r.exit_code, r.stdout[:200])
        assert "django" not in r.stdout.lower() or '"vulnerabilities"' not in r.stdout

    def test_socket_connections_fail(self, tmp_path, ws_root):
        code = ("import socket\nfor host in ('1.1.1.1','8.8.8.8','172.17.0.1','127.0.0.1'):\n s=socket.socket(); s.settimeout(2)\n"
                " try: s.connect((host,53)); print('CONNECTED',host)\n except OSError as e: print('blocked',host)\n")
        r = analyzer_run(tmp_path, ["python", "-I", "-c", code])
        assert "CONNECTED" not in r.stdout and r.stdout.count("blocked") == 4, r.stdout

    def test_semgrep_scans_a_project_from_the_mount_and_sees_only_it(self, tmp_path, ws_root):
        x = tmp_path / "x"
        x.mkdir()
        (x / "bad.py").write_text("eval(input())\n")
        r = analyzer_run(tmp_path, semgrep.build_argv(), SandboxLimits(timeout_s=90, memory_mb=1536, pids=256, tmpfs_mb=256))
        assert r.exit_code == 0, r.stderr[-300:]
        data = json.loads(r.stdout)
        assert [x["check_id"] for x in data["results"]] == ["saferun.python.dynamic-code-execution"] and data["paths"]["scanned"] == ["bad.py"]
