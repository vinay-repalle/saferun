"""`saferun init` / `saferun status`: detection, selection, skipping valid installs, repair/update, interrupted downloads, offline, missing requirements."""
import io
import json
import os
import stat
from types import SimpleNamespace

import pytest

from engine_helpers import make_osv_db
from saferun import cli, setup as su
from saferun.engine import osvdb
from saferun.sandbox import SandboxError
from saferun.sandbox import analyzer as sa
from saferun.sandbox import docker as dk
from saferun.sandbox import images as im

R, M, I, O, U = su.READY, su.MISSING, su.INVALID, su.OUTDATED, su.UNKNOWN


class World:
    """A fake installation: component states, and a log of every side effect the workflow performs."""

    def __init__(self, **states):
        self.state = {k: R for k in su.KEYS}
        self.state.update(states)
        self.calls = []
        self.online_hosts = []
        self.pull_rc = 0
        self.build_rc = 0
        self.osv_error = None
        self.install_makes_ready = True
        self.free = 10_000 * su.MB
        self.online_ok = True
        self.docker_error = None
        self.sig_error = None

    def verify_signature(self, rel):
        self.calls.append(("verify", rel.reference))
        if self.sig_error:
            raise self.sig_error
        return 1

    def status(self, key):
        return su.Status(key, self.state[key], "" if self.state[key] == R else f"fake {self.state[key]}")

    def pull(self, ref):
        self.calls.append(("pull", ref))
        if self.pull_rc == 0 and self.install_makes_ready:
            self.state["python" if ref.startswith("python") else "node"] = R
        return self.pull_rc

    def build(self, log):
        self.calls.append(("build",))
        if self.build_rc == 0 and self.install_makes_ready:
            self.state["analyzer"] = R
        return self.build_rc

    def osv_update(self, directory, progress):
        self.calls.append(("osv", directory))
        if self.osv_error:
            raise self.osv_error
        if self.install_makes_ready:
            self.state["osv-db"] = R

    def online(self, host):
        self.online_hosts.append(host)
        return self.online_ok

    def daemon_check(self):
        if self.docker_error:
            raise SandboxError(self.docker_error)

    def setup(self, answers=(), interactive=False, build_local=False):
        it = iter(answers)
        out = io.StringIO()

        def ask(prompt):
            out.write(prompt)
            try:
                return next(it)
            except StopIteration:
                raise EOFError from None
        s = su.Setup(out=out, err=out, ask=ask, interactive=interactive, status=self.status, online=self.online, pull=self.pull,
                     build=self.build, osv_update=self.osv_update, free_bytes=lambda p: self.free, daemon_check=self.daemon_check,
                     verify_signature=self.verify_signature, build_local=build_local)
        s.text = out
        return s

    def actions(self):
        return [c[0] for c in self.calls]


@pytest.fixture
def world(monkeypatch):
    monkeypatch.setattr(im, "ANALYZER_RELEASE", None)     # these tests describe the local-build path; release tests set their own (see `release`)
    return World()


# ============================================================ the component list is derived from the code
def test_components_cover_every_pinned_image_the_analyzer_the_database_and_every_check():
    assert {i.name for i in im.PINNED_IMAGES} <= set(su.KEYS) and {"analyzer", "osv-db"} <= set(su.KEYS)
    from saferun.engine import node, osv, pysyntax, semgrep
    assert set(su.CHECK_NEEDS) == {pysyntax.NAME, semgrep.NAME, osv.NAME, node.NAME}
    for needs in su.CHECK_NEEDS.values():
        assert set(needs) <= set(su.KEYS)
    assert all(c.purpose and c.size and c.checks for c in su.COMPONENTS)
    assert set(su.IMAGE_FOR) == {i.name for i in im.PINNED_IMAGES}


def test_the_introduction_is_short():
    assert len(su.INTRO.splitlines()) <= 3 and len(su.INTRO) < 330


# ============================================================ selection
@pytest.mark.parametrize("text,expected", [
    ("all", ["python", "node", "analyzer", "osv-db"]), ("5", ["python", "node", "analyzer", "osv-db"]), ("a", list(su.KEYS)),
    ("1", ["python"]), ("1,3", ["python", "analyzer"]), ("3 1", ["python", "analyzer"]), ("osv-db, node", ["node", "osv-db"]),
    ("NODE", ["node"]), ("all -osv-db", ["python", "node", "analyzer"]), ("-4", ["python", "node", "analyzer"]),
    ("!2,!3", ["python", "osv-db"]), ("1,2 -2", ["python"]), ("all,-1,-2,-3", ["osv-db"]),
])
def test_parse_selection(text, expected):
    assert su.parse_selection(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "0", "6", "banana", "1,x", "all -all", "-1,-2,-3,-4", "1 -1", "python;node", "../etc"])
def test_parse_selection_rejects(text):
    with pytest.raises(ValueError):
        su.parse_selection(text)


def test_flag_selection():
    assert su.select(False, None, None) is None                                   # no flag -> interactive
    assert su.select(True, None, None) == list(su.KEYS)
    assert su.select(False, "python,node", None) == ["python", "node"]
    assert su.select(False, None, "osv-db") == ["python", "node", "analyzer"]       # --skip alone excludes from everything
    assert su.select(True, None, "node,analyzer") == ["python", "osv-db"]
    assert su.select(False, "python,node,osv-db", "node") == ["python", "osv-db"]
    for bad in (("x", None), (None, "x"), ("python", "python")):
        with pytest.raises(ValueError):
            su.select(False, *bad)
    with pytest.raises(ValueError, match="nothing selected"):
        su.select(False, None, ",".join(su.KEYS))


# ============================================================ detection uses the real verification, never a tag
def fake_inspect(monkeypatch, repo_digests=None, rc=0, err=""):
    out = json.dumps(repo_digests) if repo_digests is not None else "null"
    monkeypatch.setattr(dk, "docker", lambda *a, timeout=None: SimpleNamespace(returncode=rc, stdout=out + "\n", stderr=err))


def test_an_image_whose_tag_exists_but_digest_differs_is_invalid_not_ready(monkeypatch):
    fake_inspect(monkeypatch, ["python@sha256:" + "a" * 64])
    s = su.component_status("python")
    assert s.state == I and "pinned" in s.detail
    fake_inspect(monkeypatch, None)
    assert su.component_status("python").state == I                                  # present with no registry digest at all (e.g. loaded)
    fake_inspect(monkeypatch, [f"python@{im.PYTHON_IMAGE.digest}"])
    assert su.component_status("python").state == R


def test_image_missing_and_docker_errors(monkeypatch):
    fake_inspect(monkeypatch, rc=1, err="Error response from daemon: No such image: python")
    assert su.component_status("node").state == M
    fake_inspect(monkeypatch, rc=1, err="Cannot connect to the Docker daemon")
    s = su.component_status("node")
    assert s.state == U and "docker" in s.detail.lower()


@pytest.mark.parametrize("exc,state", [(sa.AnalyzerUnavailable("not built"), M), (sa.AnalyzerIntegrityError("ID mismatch"), I), (SandboxError("daemon down"), U)])
def test_analyzer_states(monkeypatch, exc, state):
    monkeypatch.setattr(sa, "verify_analyzer_image", lambda: (_ for _ in ()).throw(exc))
    assert su.component_status("analyzer").state == state
    monkeypatch.setattr(sa, "verify_analyzer_image", lambda: "sha256:" + "b" * 64)
    assert su.component_status("analyzer").state == R


def test_osv_states_use_the_integrity_validation(tmp_path, monkeypatch, low_osv_floor):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "db"))
    assert su.component_status("osv-db").state == M                                   # nothing there
    make_osv_db(tmp_path / "db")
    assert su.component_status("osv-db").state == R
    make_osv_db(tmp_path / "db", age_days=90)
    assert su.component_status("osv-db").state == O
    (tmp_path / "db" / "osv-scalibr" / "npm" / "all.zip").write_bytes(b"tampered")
    assert su.component_status("osv-db").state == I
    (tmp_path / "db" / "manifest.json").unlink()
    assert su.component_status("osv-db").state == I                                   # data without a manifest is invalid, not "installed"


def test_a_crashing_probe_reads_as_unknown_never_ready(monkeypatch):
    monkeypatch.setattr(su.vf, "check_image", lambda img: (_ for _ in ()).throw(RuntimeError("boom")))
    assert su.component_status("python").state == U


# ============================================================ the workflow
def test_valid_components_are_skipped_and_nothing_is_touched(world):
    s = world.setup()
    assert s.run(list(su.KEYS)) == 0
    assert world.calls == [] and world.online_hosts == []                            # no download, no build, not even a connectivity probe
    assert s.text.getvalue().count("skipped (already installed and verified)") == 4


def test_missing_images_are_pulled_by_pinned_digest_and_verified(world):
    world.state.update(python=M, node=M)
    s = world.setup()
    assert s.run(["python", "node"]) == 0
    assert world.calls == [("pull", im.PYTHON_IMAGE.pull_reference), ("pull", im.NODE_IMAGE.pull_reference)]
    assert "@sha256:" in world.calls[0][1] and ":3.12" not in world.calls[0][1]      # a digest, never a floating tag
    assert "installed and verified" in s.text.getvalue()


def test_an_image_with_the_wrong_digest_is_repaired_by_pulling_the_pin(world):
    world.state["python"] = I
    assert world.setup().run(["python"]) == 0
    assert world.calls == [("pull", im.PYTHON_IMAGE.pull_reference)]


def test_failed_pull_is_reported_and_not_ready(world):
    world.state["node"] = M
    world.pull_rc = 1
    s = world.setup()
    assert s.run(["node"]) == 1
    assert "FAILED: docker pull failed (exit 1)" in s.text.getvalue() and "Not ready: node" in s.text.getvalue()


def test_installation_that_still_fails_verification_is_a_failure(world):
    world.state["node"] = M
    world.install_makes_ready = False
    s = world.setup()
    assert s.run(["node"]) == 1 and "installed but still missing" in s.text.getvalue()


def test_analyzer_missing_is_built_locally_when_no_release_is_configured(world):
    world.state["analyzer"] = M
    s = world.setup()
    assert s.run(["analyzer"]) == 0 and world.calls == [("build",)]
    assert "no signed prebuilt analyzer image has been published yet" in s.text.getvalue()
    assert world.online_hosts == ["pypi.org", "github.com"]                           # the build needs these


def test_analyzer_without_the_build_recipe_explains_what_to_do(world, monkeypatch):
    world.state["analyzer"] = M
    monkeypatch.setattr(su, "BUILD_SCRIPT", su.ROOT / "nope" / "build.sh")
    s = world.setup()
    assert s.run(["analyzer"]) == 1 and world.calls == []
    assert "does not include the build recipe" in s.text.getvalue()


def test_failed_analyzer_build_is_a_failure(world):
    world.state["analyzer"] = M
    world.build_rc = 2
    assert world.setup().run(["analyzer"]) == 1 and world.state["analyzer"] == M


def test_analyzer_that_failed_verification_is_not_rebuilt_without_consent(world):
    world.state["analyzer"] = I
    s = world.setup()
    assert s.run(["analyzer"]) == 1 and world.calls == []
    assert "left alone" in s.text.getvalue().split("Result:")[1] and "--repair" in s.text.getvalue()
    s = world.setup()
    assert s.run(["analyzer"], repair=True) == 0 and world.calls == [("build",)]


def test_analyzer_repair_interactive_confirmation(world):
    world.state["analyzer"] = I
    s = world.setup(answers=["n"], interactive=True)
    assert s.run(["analyzer"]) == 1 and world.calls == [] and "FAILED verification" in s.text.getvalue()
    s = world.setup(answers=["y"], interactive=True)
    assert s.run(["analyzer"]) == 0 and world.calls == [("build",)]
    world.state["analyzer"] = I
    s = world.setup(answers=[], interactive=True)                                    # EOF on the prompt counts as "no"
    assert s.run(["analyzer"]) == 1 and world.calls == [("build",)]


@pytest.mark.parametrize("state", [M, O, I])
def test_osv_data_is_downloaded_when_missing_stale_or_invalid(world, tmp_path, monkeypatch, state):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "db"))
    world.state["osv-db"] = state
    s = world.setup()
    assert s.run(["osv-db"]) == 0 and world.calls == [("osv", tmp_path / "db")]
    assert world.online_hosts == ["osv-vulnerabilities.storage.googleapis.com"]


def test_failed_osv_download_reports_and_keeps_old_data(world):
    world.state["osv-db"] = O
    world.osv_error = ValueError("PyPI: MD5 mismatch against the server-provided hash (corrupt download)")
    s = world.setup()
    assert s.run(["osv-db"]) == 1
    assert "MD5 mismatch" in s.text.getvalue() and "left untouched" in s.text.getvalue()


def test_not_enough_disk_space_stops_before_downloading(world):
    world.state["osv-db"] = M
    world.free = 100 * su.MB
    s = world.setup()
    assert s.run(["osv-db"]) == 1 and world.calls == [] and "not enough free disk space" in s.text.getvalue()


def test_ctrl_c_during_install_returns_130_and_trusts_nothing(world):
    world.state["python"] = M
    world.pull = lambda ref: (_ for _ in ()).throw(KeyboardInterrupt())
    s = world.setup()
    assert s.run(["python"]) == 130 and "interrupted" in s.text.getvalue()


def test_interactive_confirmation_can_decline_individual_components(world):
    world.state.update(python=M, node=M)
    s = world.setup(answers=["n", "y"], interactive=True)
    assert s.run(["python", "node"]) == 1
    assert world.calls == [("pull", im.NODE_IMAGE.pull_reference)] and "not installed (declined)" in s.text.getvalue()
    world.calls.clear()
    world.state.update(python=M)
    assert world.setup(interactive=True).run(["python"], assume_yes=True) == 0 and world.actions() == ["pull"]


# ============================================================ offline
def test_offline_installs_nothing_lists_what_is_missing_and_explains_preloading(world):
    world.state.update(python=M)
    world.state["osv-db"] = M
    world.online_ok = False
    s = world.setup()
    assert s.run(["python", "node", "osv-db"]) == 1
    text = s.text.getvalue()
    assert world.calls == [] and "no internet access" in text and "To set up without internet access" in text
    assert "saferun osv-db update --dir" in text and "docker save" in text and "Not ready: python, osv-db" in text
    assert "skipped (already installed and verified)" in text                       # the valid component is still honoured offline


def test_offline_with_everything_installed_needs_no_network_and_succeeds(world):
    world.online_ok = False
    assert world.setup().run(list(su.KEYS)) == 0 and world.online_hosts == []


def test_unusable_docker_blocks_image_components_but_not_the_database(world, tmp_path, monkeypatch):
    monkeypatch.setenv("SAFERUN_OSV_DB", str(tmp_path / "db"))
    world.state.update(python=M, analyzer=M)
    world.state["osv-db"] = M
    world.docker_error = "refusing non-local docker endpoint 'tcp://x:1'"
    s = world.setup()
    assert s.run(["python", "analyzer", "osv-db"]) == 1
    assert world.actions() == ["osv"] and s.text.getvalue().count("Docker is unusable") == 2


def test_components_that_cannot_be_examined_are_not_touched(world):
    world.state["node"] = U
    s = world.setup()
    assert s.run(["node"]) == 1 and world.calls == [] and "could not be examined" in s.text.getvalue()


# ============================================================ interactive menu
def test_menu_shows_state_purpose_and_size_and_accepts_free_form_answers(world):
    world.state["osv-db"] = M
    s = world.setup(answers=["1, 4"], interactive=True)
    assert s.choose() == ["python", "osv-db"]
    t = s.text.getvalue()
    assert su.INTRO in t and "[missing]" in t and "[ready]" in t and "All components" in t and "about 260 MB" in t
    for c in su.COMPONENTS:
        assert c.title in t and c.purpose in t


def test_menu_default_exclusion_and_invalid_answers(world):
    assert world.setup(answers=[""], interactive=True).choose() == list(su.KEYS)
    assert world.setup(answers=["all -osv-db"], interactive=True).choose() == ["python", "node", "analyzer"]
    s = world.setup(answers=["9", "x", "2"], interactive=True)
    assert s.choose() == ["node"] and s.text.getvalue().count("not a component") == 2
    with pytest.raises(ValueError):
        world.setup(answers=["9", "9", "9"], interactive=True).choose()
    with pytest.raises(ValueError):
        world.setup(answers=[], interactive=True).choose()                             # EOF


# ============================================================ interrupted downloads (real osvdb.update)
class BrokenResp(io.BytesIO):
    def __init__(self, good, fail_after):
        super().__init__(good)
        import base64
        import hashlib
        self.headers = {"Content-Length": str(len(good) * 2), "x-goog-hash": "md5=" + base64.b64encode(hashlib.md5(good).digest()).decode()}
        self._left = fail_after

    def read(self, n=-1):
        if self._left <= 0:
            raise ConnectionResetError("connection reset by peer")
        self._left -= 1
        return super().read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def test_interrupted_download_keeps_valid_data_and_leaves_no_debris(tmp_path, low_osv_floor):
    root = make_osv_db(tmp_path / "db", age_days=40)                                  # valid but stale
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    s = su.Setup(out=io.StringIO(), status=lambda k: su.component_status(k), online=lambda h: True, free_bytes=lambda p: 10**12,
                 osv_update=lambda d, progress: osvdb.update(d, ("npm",), opener=lambda url, timeout=None: BrokenResp(b"x" * 100, 0)))
    os.environ["SAFERUN_OSV_DB"] = str(root)
    try:
        assert s.run(["osv-db"]) == 1
    finally:
        del os.environ["SAFERUN_OSV_DB"]
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before     # not a byte changed, no temp files
    assert "ConnectionResetError" in s.out.getvalue() and "left untouched" in s.out.getvalue()


def test_progress_is_reported_during_the_download(tmp_path, low_osv_floor):
    import zipfile
    from email.message import Message
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("A.json", "{}")
    data = buf.getvalue()
    calls = []

    class Resp(io.BytesIO):
        headers = Message()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass
    r = Resp(data)
    r.headers = Message()
    r.headers["Content-Length"] = str(len(data))
    import base64
    import hashlib
    r.headers["x-goog-hash"] = "md5=" + base64.b64encode(hashlib.md5(data).digest()).decode()
    osvdb.update(tmp_path / "db", ("PyPI",), opener=lambda url, timeout=None: r, progress=lambda e, d, t: calls.append((e, d, t)))
    assert calls == [("PyPI", len(data), len(data))]
    out = io.StringIO()
    p = su.ProgressPrinter(out, tty=False)
    for done in (0, 10, 55, 100):
        p("npm", done * su.MB, 100 * su.MB)
    assert [line.strip() for line in out.getvalue().splitlines()] == ["npm: 0 / 100 MB (0%)", "npm: 10 / 100 MB (10%)", "npm: 55 / 100 MB (55%)", "npm: 100 / 100 MB (100%)"]


# ============================================================ prebuilt analyzer release (inactive until one is recorded; signature required)
@pytest.fixture
def release(monkeypatch, tmp_path):
    rel = im.AnalyzerRelease("registry.invalid/saferun/analyzer", "sha256:" + "d" * 64, "2026-11-01")
    monkeypatch.setattr(im, "ANALYZER_RELEASE", rel)
    d = tmp_path / "lockdir"
    d.mkdir(mode=0o700)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(d / "lock"))
    return rel


def fake_docker_for_release(monkeypatch, rel, *, repo_digest=None, labels=None, tag_rc=0):
    seen = []
    good = {"saferun.analyzer": "1", "saferun.semgrep.version": im.SEMGREP_VERSION, "saferun.osv-scanner.version": im.OSV_SCANNER_VERSION,
            "saferun.rules.sha256": sa.rules_sha256()}

    def fake(*a, timeout=None):
        seen.append(a)
        if a[:2] == ("image", "inspect") and "RepoDigests" in a[3]:
            return SimpleNamespace(returncode=0, stdout=json.dumps([f"{rel.repository}@{repo_digest or rel.digest}"]), stderr="")
        if a[:2] == ("image", "inspect"):
            return SimpleNamespace(returncode=0, stdout=json.dumps({"Id": "sha256:" + "e" * 64, "Config": {"Labels": labels if labels is not None else good}}), stderr="")
        if a[0] == "tag":
            return SimpleNamespace(returncode=tag_rc, stdout="", stderr="tag failed")
        raise AssertionError(a)
    monkeypatch.setattr(dk, "docker", fake)
    return seen


def test_published_release_is_pulled_by_digest_verified_and_locked(world, release, monkeypatch):
    world.state["analyzer"] = M
    seen = fake_docker_for_release(monkeypatch, release)
    s = world.setup()
    s.status = lambda k: su.Status(k, R if (k != "analyzer" or os.path.exists(os.environ["SAFERUN_ANALYZER_LOCK"])) else M)
    assert s.run(["analyzer"]) == 0, s.text.getvalue()
    lock = os.environ["SAFERUN_ANALYZER_LOCK"]
    assert open(lock).read().strip() == "sha256:" + "e" * 64
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(lock).st_mode) == 0o600
    else:   # the same guarantee on Windows: owner-only access control list
        from pathlib import Path
        from saferun import hostos
        assert hostos.private_path_problem(Path(lock), directory=False) is None
    assert ("tag", f"{release.repository}@{release.digest}", sa.ANALYZER_REPO_TAG) in seen
    assert world.online_hosts == list(su.HOSTS["release"])                              # the registry and Sigstore, not pip/github
    assert [c for c in world.calls if c[0] in ("verify", "pull")] == [("verify", release.reference), ("pull", release.reference)]   # verified BEFORE the pull


def test_published_release_refused_when_digest_or_labels_do_not_match(world, release, monkeypatch):
    world.state["analyzer"] = M
    pulled = []
    world.pull = lambda ref: pulled.append(ref) or 0
    fake_docker_for_release(monkeypatch, release, repo_digest="sha256:" + "f" * 64)
    s = world.setup()
    assert s.run(["analyzer"]) == 1 and pulled == [f"{release.repository}@{release.digest}"]
    assert "does not carry the published digest" in s.text.getvalue() and not os.path.exists(os.environ["SAFERUN_ANALYZER_LOCK"])
    fake_docker_for_release(monkeypatch, release, labels={"saferun.analyzer": "1", "saferun.rules.sha256": "0" * 64})
    s = world.setup()
    assert s.run(["analyzer"]) == 1 and "NOT trusted" in s.text.getvalue() and not os.path.exists(os.environ["SAFERUN_ANALYZER_LOCK"])


def test_a_bad_or_missing_signature_means_nothing_is_pulled_or_trusted(world, release, monkeypatch):
    from saferun.sandbox.signature import CosignMissing, SignatureError
    seen = fake_docker_for_release(monkeypatch, release)
    for err, expects in ((SignatureError("wrong identity"), ("signature verification failed", "NOT pulled or trusted", "wrong identity")),
                         (CosignMissing("cosign is not installed"), ("cosign is not installed", "Nothing was pulled", "--build-local"))):
        w = World()
        w.state["analyzer"] = M
        w.sig_error = err
        s = w.setup()
        assert s.run(["analyzer"]) == 1
        assert all(e in s.text.getvalue() for e in expects)
        assert [c for c in w.calls if c[0] in ("pull", "build")] == [] and seen == []      # no pull, no docker call, no build fallback
        assert not os.path.exists(os.environ["SAFERUN_ANALYZER_LOCK"])


def test_build_local_ignores_the_release_and_does_not_need_cosign_or_ghcr(world, release):
    world.state["analyzer"] = M
    s = world.setup(build_local=True)
    assert s.run(["analyzer"]) == 0
    assert world.actions().count("build") == 1 and "verify" not in world.actions()
    assert world.online_hosts == list(su.HOSTS["build"])


def test_a_release_without_a_signer_identity_cannot_be_installed(world, release, monkeypatch):
    from saferun.sandbox import signature
    monkeypatch.setattr(im, "ANALYZER_RELEASE", im.AnalyzerRelease(release.repository, release.digest, "2026-11-01", signer_identity_regexp=""))
    world.state["analyzer"] = M
    s = su.Setup(out=io.StringIO(), status=world.status, online=world.online, pull=world.pull, build=world.build,
                 daemon_check=world.daemon_check, verify_signature=lambda rel: signature.verify_release_signature(rel, which=lambda: "/x/cosign"))
    assert s.run(["analyzer"]) == 1 and [c for c in world.calls if c[0] == "pull"] == []


def test_the_recorded_release_if_any_is_well_formed():
    rel = im.ANALYZER_RELEASE
    if rel is None:
        return                                          # nothing published yet: `saferun init` builds locally
    assert rel.repository == im.ANALYZER_REGISTRY_REPOSITORY and im.DIGEST_RE.match(rel.digest)
    assert rel.signer_identity_regexp == im.ANALYZER_SIGNER_IDENTITY_REGEXP and rel.oidc_issuer == im.GITHUB_OIDC_ISSUER


# ============================================================ command line
def test_init_without_flags_needs_a_terminal(capsys):
    assert cli.main(["init"]) == 64
    assert "--all" in capsys.readouterr().err


def test_init_flag_errors_exit_64(capsys):
    for argv in (["init", "--only", "bogus"], ["init", "--skip", "x"], ["init", "--only", "node", "--skip", "node"]):
        assert cli.main(argv) == 64


def test_init_passes_the_selection_and_flags_to_the_workflow(monkeypatch):
    seen = {}

    class Stub:
        def __init__(self, **kw):
            seen["kw"] = kw

        def say(self, t=""):
            pass

        def run(self, chosen, repair=False, assume_yes=False):
            seen.update(chosen=chosen, repair=repair, yes=assume_yes)
            return 0
    monkeypatch.setattr(cli.setup_mod, "Setup", Stub)
    assert cli.main(["init", "--all", "--repair", "--yes"]) == 0 and seen["chosen"] == list(su.KEYS) and seen["repair"] and seen["yes"]
    assert seen["kw"]["interactive"] is False
    assert cli.main(["init", "--skip", "osv-db,node"]) == 0 and seen["chosen"] == ["python", "analyzer"]
    assert cli.main(["init", "--only", "node"]) == 0 and seen["chosen"] == ["node"]


def test_init_interrupt_exit_code(monkeypatch):
    class Stub:
        def __init__(self, **kw):
            pass

        def say(self, t=""):
            pass

        def run(self, *a, **k):
            raise KeyboardInterrupt
    monkeypatch.setattr(cli.setup_mod, "Setup", Stub)
    assert cli.main(["init", "--all"]) == 130


def test_status_text_json_and_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(su, "component_status", lambda k, **kw: su.Status(k, R if k != "osv-db" else O, "detail for " + k))
    assert cli.main(["status"]) == 1
    out = capsys.readouterr().out
    assert "READY" in out and "OUTDATED" in out and "fix: saferun init --only osv-db" in out and "enables: dependency-vulnerabilities" in out
    assert cli.main(["status", "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == 1 and data["ok"] is False and [c["component"] for c in data["components"]] == list(su.KEYS)
    assert set(data["components"][0]) == {"component", "title", "state", "detail", "enables"}
    assert cli.main(["status", "--only", "python,node"]) == 0
    assert cli.main(["status", "--only", "nope"]) == 64


def test_status_suggests_repair_flag_for_a_failed_analyzer(monkeypatch, capsys):
    monkeypatch.setattr(su, "component_status", lambda k, **kw: su.Status(k, I if k == "analyzer" else R, "ID mismatch"))
    assert cli.main(["status"]) == 1 and "saferun init --only analyzer --repair" in capsys.readouterr().out


def test_verify_images_only_flag(monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(cli, "verify_images", lambda images=None, analyzer=True: seen.update(images=[i.name for i in images], analyzer=analyzer) or [])
    assert cli.main(["verify-images", "--only", "python"]) == 0 and seen == {"images": ["python"], "analyzer": False}
    assert cli.main(["verify-images", "--only", "ruby"]) == 64


# ============================================================ a scan that needs a missing component says exactly what to do
def report_with(*checks):
    from saferun.engine import CheckResult, ValidationReport, Verdict, compute_verdict
    v, reasons, complete = compute_verdict(list(checks), "")
    return ValidationReport(v, reasons, complete, list(checks), {"skipped": [], "withheld": []})


def test_scan_hints_name_the_missing_component_and_the_exact_fix(monkeypatch, tmp_path, capsys):
    from saferun.engine import CheckResult, CheckStatus
    rep = report_with(CheckResult("python-static-analysis", CheckStatus.UNAVAILABLE, detail="x"), CheckResult("dependency-vulnerabilities", CheckStatus.ERROR, detail="y"),
                      CheckResult("python-syntax", CheckStatus.PASSED))
    states = {"analyzer": su.Status("analyzer", M, "not built"), "osv-db": su.Status("osv-db", O, "45 days old")}
    monkeypatch.setattr(su, "component_status", lambda k, **kw: states.get(k, su.Status(k, R)))
    monkeypatch.setattr(cli, "validate_project", lambda p, o: rep)
    code = cli.main(["scan", str(tmp_path), "--format", "json"])
    cap = capsys.readouterr()
    assert code == 2                                                                  # unchanged exit code
    assert json.loads(cap.out)["verdict"] == "WARNING"                                # unchanged report on stdout
    assert "Analyzer image" in cap.err and "saferun init --only analyzer" in cap.err and "saferun init --only osv-db" in cap.err
    assert "python-syntax" not in cap.err and "Python sandbox" not in cap.err


def test_scan_hints_are_silent_for_a_healthy_installation(monkeypatch, tmp_path, capsys):
    from saferun.engine import CheckResult, CheckStatus
    monkeypatch.setattr(su, "component_status", lambda k, **kw: (_ for _ in ()).throw(AssertionError("must not even be consulted")))
    monkeypatch.setattr(cli, "validate_project", lambda p, o: report_with(CheckResult("python-syntax", CheckStatus.PASSED)))
    assert cli.main(["scan", str(tmp_path)]) == 0 and capsys.readouterr().err == ""


def test_a_failing_hint_never_changes_the_scan_outcome(monkeypatch, tmp_path, capsys):
    from saferun.engine import CheckResult, CheckStatus
    monkeypatch.setattr(cli.setup_mod, "scan_hints", lambda r: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(cli, "validate_project", lambda p, o: report_with(CheckResult("python-syntax", CheckStatus.UNAVAILABLE)))
    assert cli.main(["scan", str(tmp_path)]) == 2


# ============================================================ real Docker: the existing installation is detected and left alone
@pytest.mark.docker
def test_real_status_of_the_pinned_images_and_init_skips_them(monkeypatch):
    s = su.component_status("python"), su.component_status("node")
    assert [x.state for x in s] == [R, R], s
    w = World()
    monkeypatch.setattr(su, "docker_pull", lambda ref: (_ for _ in ()).throw(AssertionError("must not pull a verified image")))
    setup = su.Setup(out=io.StringIO(), online=lambda h: (_ for _ in ()).throw(AssertionError("no network probe needed")),
                     pull=lambda ref: (_ for _ in ()).throw(AssertionError("no pull")))
    assert setup.run(["python", "node"]) == 0
    assert setup.out.getvalue().count("skipped (already installed and verified)") == 2


def test_recorded_release_is_the_verified_analyzer_v1_0_1_pinned_by_digest():
    rel = im.ANALYZER_RELEASE
    assert rel is not None
    assert rel.repository == "ghcr.io/vinay-repalle/saferun-analyzer" == im.ANALYZER_REGISTRY_REPOSITORY
    assert rel.digest == "sha256:6f26c3e3fed1a8b2a981bdcb920c4da3b2829bce2679709ba8880789ce6f6fa4"
    assert rel.reference == "ghcr.io/vinay-repalle/saferun-analyzer@sha256:6f26c3e3fed1a8b2a981bdcb920c4da3b2829bce2679709ba8880789ce6f6fa4" and ":" not in rel.reference.split("@")[0].rsplit("/", 1)[1]   # digest, never a tag
    assert im.digest_of(rel.reference) == rel.digest
    assert rel.signer_identity_regexp == im.ANALYZER_SIGNER_IDENTITY_REGEXP and rel.oidc_issuer == im.GITHUB_OIDC_ISSUER


def test_init_installs_the_recorded_release_unless_build_local_is_requested():
    assert su.Setup(out=io.StringIO(), build_local=False)._release() is im.ANALYZER_RELEASE
    assert su.Setup(out=io.StringIO(), build_local=True)._release() is None
