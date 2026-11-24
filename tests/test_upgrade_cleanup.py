"""Upgrade and cleanup: the `outdated` analyzer state, removal of the previous analyzer image, the OSV early warning, removal of OSV data
for ecosystems SafeRun no longer supports, and `saferun cleanup`.

Nothing here touches the real installation: Docker is faked, OSV data and lock files live in tmp_path, and the real-Docker tests build
their own throwaway `FROM scratch` images and only ever try to delete those (never the global cleanup list)."""
import io
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from engine_helpers import FakeRunner, make_ctx, make_osv_db, tool_run
from saferun import cli, doctor, ui
from saferun import cleanup as cu
from saferun import setup as su
from saferun.engine import CheckStatus, osvdb, semgrep
from saferun.sandbox import SandboxError, ReapReport, reap_orphans
from saferun.sandbox import analyzer as sa
from saferun.sandbox import docker as dk
from saferun.sandbox import images as im
from saferun.sandbox import oldimages, verify
from saferun.sandbox.workspace import WS_PREFIX

R, M, I, O = su.READY, su.MISSING, su.INVALID, su.OUTDATED
CUR, NEW, OLD, OLDER, PY, OTHER = ("sha256:" + c * 64 for c in "abcdef")
DAY = 86400


def proc(rc=0, out="", err=""):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def good_labels():
    return {"saferun.analyzer": "1", "saferun.semgrep.version": im.SEMGREP_VERSION, "saferun.osv-scanner.version": im.OSV_SCANNER_VERSION,
            "saferun.rules.sha256": sa.rules_sha256(), "saferun.gitleaks.version": im.GITLEAKS_VERSION,
            "saferun.secrets-rules.sha256": sa.secrets_rules_sha256()}


@pytest.fixture
def lock(tmp_path, monkeypatch):
    """A trusted analyzer lock naming CUR (and the place of its .bak), in tmp_path."""
    d = tmp_path / "lockdir"
    d.mkdir(mode=0o700)
    d.chmod(0o700)
    p = d / "analyzer-image-id"
    p.write_text(CUR + "\n")
    p.chmod(0o600)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(p))
    return p


def fake_tag(monkeypatch, image_id, labels):
    out = json.dumps({"Id": image_id, "Config": {"Labels": labels}})
    monkeypatch.setattr(dk, "docker", lambda *a, timeout=None: proc(0, out))


# ====================================================================== A. outdated analyzer
def test_locked_image_with_older_pins_is_outdated_not_tampered(lock, monkeypatch):
    old = {**good_labels(), "saferun.semgrep.version": "0.0.1", "saferun.rules.sha256": "0" * 64}
    fake_tag(monkeypatch, CUR, old)
    with pytest.raises(sa.AnalyzerOutdated) as e:
        sa.verify_analyzer_image()
    assert isinstance(e.value, sa.AnalyzerIntegrityError)                    # every check still treats it as "not usable"
    assert e.value.wrong == ("saferun.semgrep.version", "saferun.rules.sha256")
    with pytest.raises(sa.AnalyzerIntegrityError) as plain:
        sa.check_labels(old)
    assert str(e.value) == str(plain.value)                                  # the scan report text is unchanged


def test_without_the_analyzer_label_or_with_another_id_or_lock_problem_it_stays_invalid(lock, monkeypatch):
    unlabelled = {k: v for k, v in good_labels().items() if k != "saferun.analyzer"}
    fake_tag(monkeypatch, CUR, {**unlabelled, "saferun.semgrep.version": "0.0.1"})
    with pytest.raises(sa.AnalyzerIntegrityError) as e:
        sa.verify_analyzer_image()
    assert not isinstance(e.value, sa.AnalyzerOutdated)
    fake_tag(monkeypatch, NEW, {**good_labels(), "saferun.semgrep.version": "0.0.1"})      # ID differs from the lock
    with pytest.raises(sa.AnalyzerIntegrityError, match="ID mismatch") as e:
        sa.verify_analyzer_image()
    assert not isinstance(e.value, sa.AnalyzerOutdated)
    fake_tag(monkeypatch, CUR, {**good_labels(), "saferun.semgrep.version": "0.0.1"})
    lock.chmod(0o644)                                                                       # lock no longer trusted
    with pytest.raises(sa.AnalyzerIntegrityError) as e:
        sa.verify_analyzer_image()
    assert not isinstance(e.value, sa.AnalyzerOutdated)


def test_status_hint_and_fix_say_update_without_repair(monkeypatch):
    def verify_outdated():
        raise sa.AnalyzerOutdated("labels differ", ["saferun.rules.sha256"])
    monkeypatch.setattr(sa, "verify_analyzer_image", verify_outdated)
    s = su.component_status("analyzer")
    assert s.state == O and "saferun.rules.sha256" in s.detail and "saferun init --only analyzer" in s.detail
    monkeypatch.setattr(su, "component_status", lambda k, **kw: s if k == "analyzer" else su.Status(k, R))
    report = SimpleNamespace(checks=[SimpleNamespace(name="python-static-analysis", status=CheckStatus.ERROR)])
    hints = su.scan_hints(report)
    assert hints and hints[0].endswith("fix: saferun init --only analyzer")
    assert "fix: saferun init --only analyzer\n" in su.status_report([s]) + "\n" and "--repair" not in su.status_report([s])
    assert "--repair" in su.status_report([su.Status("analyzer", I, "ID mismatch")])            # invalid: unchanged


def test_scans_with_an_outdated_analyzer_behave_as_before(tmp_path, monkeypatch):
    runner = FakeRunner(tool_run("{}"))

    def outdated():
        raise sa.AnalyzerOutdated("analyzer image labels do not match the pinned tools/rules: saferun.rules.sha256; rebuild it")
    res = semgrep.run_check(make_ctx(tmp_path, ["app.py"], runner, analyzer_available=outdated))
    assert res.status is CheckStatus.ERROR and runner.calls == []
    monkeypatch.setattr(verify, "verify_analyzer_image", outdated)
    assert verify.check_analyzer().status == verify.MISMATCH                                      # verify-images: unchanged


def test_doctor_keeps_an_outdated_analyzer_a_failure_with_the_plain_fix():
    ok = SimpleNamespace(ok=True, detail="Docker 29", guidance="")
    for state, repair in ((O, False), (I, True)):
        checks = {c.name: c for c in doctor.run_checks(status=lambda k, st=state: su.Status(k, st if k == "analyzer" else R, "d"),
                                                       diagnose=lambda: ok)}
        a = checks["Analyzer image"]
        assert a.level == doctor.FAIL and a.fix.startswith("run: saferun init --only analyzer") and ("--repair" in a.fix) is repair


# ---- init: update an outdated analyzer, then remove the previous image
class Inst:
    """A fake installation for Setup.run: component states, the trusted lock, and a log of deletions."""

    def __init__(self, analyzer=O, osv=R, previous=OLD):
        self.state = {"python": R, "analyzer": analyzer, "osv-db": osv}
        self.lock = previous
        self.build_rc = 0
        self.removed, self.pruned = [], []
        self.remove_result = (True, "")

    def status(self, k):
        return su.Status(k, self.state[k], "" if self.state[k] == R else f"fake {self.state[k]}")

    def build(self, log):
        if self.build_rc == 0:
            self.state["analyzer"], self.lock = R, NEW
        return self.build_rc

    def remove(self, image_id, keep=()):
        self.removed.append((image_id, tuple(keep)))
        if isinstance(self.remove_result, Exception):
            raise self.remove_result
        return self.remove_result

    def prune(self, d):
        self.pruned.append(d)
        return [("npm", 219_396_119)], []

    def setup(self, interactive=False, answers=()):
        it, out = iter(answers), io.StringIO()

        def ask(q):
            out.write(q)
            try:
                return next(it)
            except StopIteration:
                raise EOFError from None
        s = su.Setup(out=out, err=out, ask=ask, interactive=interactive, status=self.status, online=lambda h: True, pull=lambda r: 0,
                     build=self.build, osv_update=lambda d, p: None, free_bytes=lambda p: 10 ** 12, daemon_check=lambda: None,
                     build_local=True, ensure_cosign=lambda: None, has_cosign=lambda: True,
                     locked_id=lambda: self.lock, remove_old=self.remove, prune_osv=self.prune)
        s.text = out
        return s


@pytest.fixture
def local_build(monkeypatch):
    monkeypatch.setattr(im, "ANALYZER_RELEASE", None)


def test_init_all_updates_an_outdated_analyzer_without_repair_and_removes_the_previous_image(local_build):
    inst = Inst()
    s = inst.setup()
    assert s.run(["analyzer"]) == 0                                       # `init --all/--only`: no --repair, no --yes
    out = s.text.getvalue()
    assert "FAILED verification" not in out and "Update Analyzer image" in out and "installed and verified" in out
    assert inst.removed == [(OLD, (NEW,))] and f"previous analyzer image {OLD[:19]}… removed" in out


def test_interactive_update_is_a_normal_question(local_build):
    inst = Inst()
    s = inst.setup(interactive=True, answers=[""])
    assert s.run(["analyzer"]) == 0 and "Update Analyzer image" in s.text.getvalue() and "Rebuild?" not in s.text.getvalue()


def test_invalid_still_needs_repair_and_repair_also_removes_the_previous_image(local_build):
    inst = Inst(analyzer=I)
    s = inst.setup()
    assert s.run(["analyzer"]) == 1 and inst.removed == [] and "--repair" in s.text.getvalue()
    s = inst.setup()
    assert s.run(["analyzer"], repair=True) == 0 and inst.removed == [(OLD, (NEW,))]


@pytest.mark.parametrize("result", [(False, "it is used by 1 container(s)"), RuntimeError("boom")])
def test_a_kept_or_failed_delete_is_a_note_never_an_init_failure(local_build, result):
    inst = Inst()
    inst.remove_result = result
    s = inst.setup()
    assert s.run(["analyzer"]) == 0
    out = s.text.getvalue()
    assert "was kept" in out and "Analyzer image (Semgrep, OSV-Scanner, gitleaks, rules): installed and verified" in out


def test_nothing_is_removed_without_a_previous_lock_a_new_image_or_a_successful_install(local_build):
    inst = Inst(analyzer=M, previous=None)
    assert inst.setup().run(["analyzer"]) == 0 and inst.removed == []
    inst = Inst()
    inst.build_rc = 1
    assert inst.setup().run(["analyzer"]) == 1 and inst.removed == []
    inst = Inst(previous=NEW)                                     # the "new" lock equals the previous one: nothing to remove
    assert inst.setup().run(["analyzer"]) == 0 and inst.removed == []


def test_init_prunes_unsupported_osv_data_whenever_osv_db_is_selected():
    inst = Inst(analyzer=R)
    s = inst.setup()
    assert s.run(["osv-db"]) == 0 and inst.pruned == [su._osv_dir()]           # osv-db already ready: still pruned
    assert "Removed OSV data SafeRun no longer supports: npm (219 MB)" in s.text.getvalue()
    inst = Inst(analyzer=R)
    assert inst.setup().run(["python"]) == 0 and inst.pruned == []

    def broken(d):
        raise OSError("disk")
    s = su.Setup(out=io.StringIO(), status=lambda k: su.Status(k, R), daemon_check=lambda: None, prune_osv=broken)
    assert s.run(["osv-db"]) == 0 and "not fully removed" in s.out.getvalue()


# ====================================================================== A3. guarded removal of old images (fake Docker)
class FakeDocker:
    def __init__(self):
        self.images = {CUR: {"saferun.analyzer": "1"}, OLD: {"saferun.analyzer": "1"}, OLDER: {"saferun.analyzer": "1"},
                       PY: {}, OTHER: {"maintainer": "someone"}}
        self.refs = {sa.ANALYZER_REPO_TAG: CUR, im.PYTHON_IMAGE.reference: PY}
        self.users = {}
        self.calls = []
        self.fail = set()
        self.rmi_rc = 0

    def __call__(self, *a, timeout=None):
        self.calls.append(a)
        if a[:2] == ("image", "inspect"):
            target = a[-1]
            iid = self.refs.get(target, target if target in self.images else None)
            if iid is None:
                return proc(1, "", f"Error response from daemon: No such image: {target}")
            if a[3] == "{{.Id}}":
                return proc(0, iid + "\n")
            return proc(0, json.dumps(self.images[iid]) + "\t123000000\n")
        if a[:2] == ("image", "ls"):
            if "ls" in self.fail:
                return proc(1, "", "Cannot connect to the Docker daemon")
            key, _, val = a[-1].partition("=")[2].partition("=")
            return proc(0, "".join(f"{i}\n{i}\n" for i, lab in self.images.items() if lab.get(key) == val))   # one line per name
        if a[0] == "ps":
            if "ps" in self.fail:
                return proc(1, "", "Cannot connect to the Docker daemon")
            return proc(0, "".join(c + "\n" for c in self.users.get(a[-1].partition("=")[2], [])))
        if a[0] == "rmi":
            assert not {"-f", "--force"} & set(a), "an image is never force-deleted"
            if self.rmi_rc:
                return proc(1, "", "Error response from daemon: conflict: unable to delete (must be forced)")
            self.images.pop(a[1])
            return proc(0, f"Deleted: {a[1]}\n")
        raise AssertionError(a)

    def rmi_calls(self):
        return [c for c in self.calls if c[0] == "rmi"]


@pytest.fixture
def fd(lock, monkeypatch):
    f = FakeDocker()
    monkeypatch.setattr(dk, "docker", f)
    return f


def test_an_old_unused_analyzer_image_is_removed_without_force(fd):
    assert oldimages.remove_old_image(OLD) == (True, "")
    assert fd.rmi_calls() == [("rmi", OLD)] and OLD not in fd.images


@pytest.mark.parametrize("target,keep,why", [
    (CUR, (), "current analyzer image"),                 # the trusted lock's image
    (PY, (), "current analyzer image or the python"),     # the pinned python sandbox image
    (OLD, (OLD,), "current analyzer image"),              # an ID the caller keeps (init: the new lock)
    (OTHER, (), "no saferun.analyzer label"),            # not a SafeRun analyzer image
    ("sha256:abc", (), "not a full image ID"),
])
def test_protected_unlabelled_and_malformed_images_are_never_removed(fd, target, keep, why):
    removed, reason = oldimages.remove_old_image(target, keep=keep)
    assert not removed and why in reason and fd.rmi_calls() == []


def test_the_python_image_is_protected_even_if_it_carried_the_label(fd):
    fd.images[PY] = {"saferun.analyzer": "1"}
    assert not oldimages.remove_old_image(PY)[0] and fd.rmi_calls() == []
    assert PY not in [i.image_id for i in oldimages.find_old_images()]


def test_the_image_behind_the_current_tag_is_protected_even_if_the_lock_differs(fd):
    fd.refs[sa.ANALYZER_REPO_TAG] = OLDER
    assert not oldimages.remove_old_image(OLDER)[0] and fd.rmi_calls() == []


def test_an_image_used_by_any_container_is_never_removed(fd):
    fd.users[OLD] = ["c" * 64]
    removed, reason = oldimages.remove_old_image(OLD)
    assert not removed and "used by 1 container" in reason and fd.rmi_calls() == []


def test_an_untrusted_lock_or_a_docker_error_removes_nothing(fd, lock):
    lock.chmod(0o644)
    removed, reason = oldimages.remove_old_image(OLD)
    assert not removed and "cannot be trusted" in reason and fd.rmi_calls() == []
    lock.chmod(0o600)
    fd.fail.add("ps")
    assert not oldimages.remove_old_image(OLD)[0] and fd.rmi_calls() == []
    fd.fail.clear()
    fd.rmi_rc = 1
    removed, reason = oldimages.remove_old_image(OLD)
    assert not removed and "docker rmi refused" in reason and OLD in fd.images


def test_without_any_lock_the_tag_and_python_image_stay_protected(fd, lock):
    lock.unlink()
    assert not oldimages.remove_old_image(CUR)[0] and not oldimages.remove_old_image(PY)[0]
    assert oldimages.remove_old_image(OLD) == (True, "")


def test_find_old_images_lists_only_other_saferun_analyzer_images_with_reasons(fd):
    fd.users[OLDER] = ["x" * 64]
    found = {i.image_id: i for i in oldimages.find_old_images()}
    assert set(found) == {OLD, OLDER}                                    # never CUR, PY or OTHER; duplicates per name collapsed
    assert found[OLD].problem == "" and found[OLD].size == 123000000 and "container" in found[OLDER].problem
    assert fd.rmi_calls() == []
    fd.fail.add("ls")
    with pytest.raises(SandboxError):
        oldimages.find_old_images()


# ---- the same guards against the real Docker daemon, on throwaway images only
def _docker():
    return shutil.which("docker")


def _build(analyzer_label: bool) -> str:
    tag = f"saferun-test-oldimage:{uuid.uuid4().hex[:12]}"
    df = f"FROM scratch\nLABEL saferun.test.id={uuid.uuid4().hex}\n" + ("LABEL saferun.analyzer=1\n" if analyzer_label else "")
    subprocess.run([_docker(), "build", "-q", "-t", tag, "-"], input=df, text=True, check=True, capture_output=True, timeout=120)
    return subprocess.run([_docker(), "image", "inspect", "--format", "{{.Id}}", tag], text=True, check=True,
                          capture_output=True).stdout.strip()


def _exists(image_id: str) -> bool:
    return subprocess.run([_docker(), "image", "inspect", image_id], capture_output=True).returncode == 0


@pytest.mark.docker
def test_real_docker_guards_on_throwaway_images():
    made, container = [], None
    try:
        old, plain, used = _build(True), _build(False), _build(True)
        made += [old, plain, used]
        container = subprocess.run([_docker(), "create", used, "/nothing"], text=True, check=True, capture_output=True).stdout.strip()
        listed = {i.image_id: i for i in oldimages.find_old_images()}            # read-only listing of the real daemon
        assert old in listed and used in listed and plain not in listed and listed[old].problem == ""
        assert "container" in listed[used].problem
        locked = sa.read_trusted_lock()
        assert locked not in listed
        assert not oldimages.remove_old_image(plain)[0] and _exists(plain)       # no analyzer label
        assert not oldimages.remove_old_image(used)[0] and _exists(used)         # used by a (stopped) container
        assert not oldimages.remove_old_image(old, keep=(old,))[0] and _exists(old)
        assert oldimages.remove_old_image(old) == (True, "") and not _exists(old)
    finally:
        if container:
            subprocess.run([_docker(), "rm", "-f", container], capture_output=True)
        for i in made:
            subprocess.run([_docker(), "rmi", "-f", i], capture_output=True)    # our own test images only


# ====================================================================== B5. OSV early warning
@pytest.mark.parametrize("age,limit,warns", [(24.9, 30, False), (25.0, 30, True), (29.9, 30, True), (30.0, 30, True), (30.1, 30, False),
                                             (5.5, 10, True), (4.9, 10, False), (None, 30, False)])
def test_expiry_warning_threshold(age, limit, warns):
    assert bool(osvdb.expiry_warning(age, limit)) is warns


@pytest.fixture
def osv_dir(tmp_path, monkeypatch, low_osv_floor):
    def make(age, ecosystems=("PyPI",)):
        root = make_osv_db(tmp_path / f"db-{age}-{len(ecosystems)}", ecosystems=ecosystems, age_days=age)
        monkeypatch.setenv("SAFERUN_OSV_DB", str(root))
        return root
    return make


def test_validate_warns_before_stale_and_never_changes_usability(osv_dir):
    rep = osvdb.validate(osv_dir(26), ["PyPI"])
    assert rep.ok and not rep.stale and "becomes stale in 4.0 day(s)" in rep.expires_soon
    assert osvdb.validate(osv_dir(10), ["PyPI"]).expires_soon == ""
    old = osvdb.validate(osv_dir(31), ["PyPI"])
    assert old.stale and old.expires_soon == ""


def test_status_and_doctor_warn_but_stay_ready(osv_dir):
    osv_dir(26)
    s = su.component_status("osv-db")
    assert s.state == R and s.warning and "becomes stale in 4.0 day(s)" in s.detail and "saferun osv-db update" in s.detail
    ok = SimpleNamespace(ok=True, detail="Docker 29", guidance="")
    checks = doctor.run_checks(status=lambda k: s if k == "osv-db" else su.Status(k, R, "ok"), diagnose=lambda: ok)
    c = next(c for c in checks if c.name == "OSV database")
    assert c.level == doctor.WARN and c.fix == "run: saferun osv-db update" and doctor.exit_code(checks) == 0
    osv_dir(10)
    assert not su.component_status("osv-db").warning


def test_osv_db_status_warns_checks_pypi_only_and_points_at_cleanup(osv_dir, capsys):
    root = osv_dir(26, ecosystems=("PyPI", "npm"))
    (root / "osv-scalibr" / "npm" / "all.zip").write_bytes(b"changed")          # broken npm data no longer fails the status
    assert cli.main(["osv-db", "status", "--dir", str(root)]) == 0
    out = capsys.readouterr().out
    assert "WARNING: the OSV database is 26 days old" in out and "usable and fresh" in out
    assert "no longer supports: npm" in out and "saferun cleanup" in out and "PROBLEM" not in out


def test_scan_hint_only_when_the_dependency_check_used_ageing_data(osv_dir):
    osv_dir(26)
    report = lambda st: SimpleNamespace(checks=[SimpleNamespace(name="dependency-vulnerabilities", status=st)])   # noqa: E731
    assert cli._osv_expiry_hint(report(CheckStatus.PASSED)).startswith("warning: the OSV database is 26 days old")
    assert cli._osv_expiry_hint(report(CheckStatus.FINDINGS))
    assert cli._osv_expiry_hint(report(CheckStatus.SKIPPED)) == ""
    assert cli._osv_expiry_hint(report(CheckStatus.NOT_APPLICABLE)) == ""
    osv_dir(10)
    assert cli._osv_expiry_hint(report(CheckStatus.PASSED)) == ""


def test_manifest_age_reads_supported_ecosystems_only(osv_dir, tmp_path):
    root = osv_dir(26, ecosystems=("PyPI", "npm"))
    assert 25.9 < osvdb.manifest_age_days(root) < 26.1
    assert osvdb.manifest_age_days(tmp_path / "nothing") is None
    m = json.loads((root / "manifest.json").read_text())
    del m["ecosystems"]["PyPI"]
    (root / "manifest.json").write_text(json.dumps(m))
    assert osvdb.manifest_age_days(root) is None


# ====================================================================== B6. unsupported OSV data
@pytest.fixture
def with_npm(tmp_path, low_osv_floor):
    root = make_osv_db(tmp_path / "db", ecosystems=("PyPI", "npm"))
    (root / "osv-scalibr" / "npm" / ".dl-abc").write_bytes(b"x" * 10)           # an interrupted download
    return root


def manifest(root):
    return json.loads((root / "manifest.json").read_text())


def test_prune_removes_npm_data_leftovers_folder_and_manifest_entry_only(with_npm):
    zip_size = (with_npm / "osv-scalibr" / "npm" / "all.zip").stat().st_size
    assert osvdb.unsupported_data(with_npm) == [("npm", zip_size)]
    assert osvdb.prune_unsupported(with_npm) == ([("npm", zip_size + 10)], [])
    assert not (with_npm / "osv-scalibr" / "npm").exists() and "npm" not in manifest(with_npm)["ecosystems"]
    assert osvdb.validate(with_npm, ["PyPI"]).ok and osvdb.validate(with_npm).ok        # PyPI untouched and still valid
    assert osvdb.prune_unsupported(with_npm) == ([], []) and osvdb.unsupported_data(with_npm) == []


def test_prune_never_follows_symlinks(with_npm, tmp_path):
    npm = with_npm / "osv-scalibr" / "npm"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "all.zip").write_bytes(b"keep me")
    (npm / "all.zip").unlink()
    (npm / "all.zip").symlink_to(elsewhere / "all.zip")
    removed, problems = osvdb.prune_unsupported(with_npm)
    assert removed == [] and "not a regular file" in problems[0] and (elsewhere / "all.zip").read_bytes() == b"keep me"
    assert "npm" in manifest(with_npm)["ecosystems"]
    shutil.rmtree(npm)
    npm.symlink_to(elsewhere, target_is_directory=True)
    removed, problems = osvdb.prune_unsupported(with_npm)
    assert removed == [] and "not a real directory" in problems[0] and (elsewhere / "all.zip").exists()


def test_prune_keeps_unknown_files_and_handles_a_missing_archive(with_npm):
    npm = with_npm / "osv-scalibr" / "npm"
    (npm / "mine.txt").write_text("not SafeRun's")
    removed, problems = osvdb.prune_unsupported(with_npm)
    assert removed and "left in place" in problems[0] and (npm / "mine.txt").exists() and not (npm / "all.zip").exists()
    assert "npm" not in manifest(with_npm)["ecosystems"]
    m = manifest(with_npm)
    m["ecosystems"]["npm"] = {"sha256": "0" * 64, "size": 1, "entries": 1, "updated_epoch": 1, "updated_at": "x", "md5": "verified"}
    (with_npm / "manifest.json").write_text(json.dumps(m))
    (npm / "mine.txt").unlink()
    npm.rmdir()
    assert osvdb.prune_unsupported(with_npm) == ([("npm", 0)], []) and "npm" not in manifest(with_npm)["ecosystems"]


def test_prune_touches_only_retired_ecosystems_recorded_in_the_manifest(tmp_path, low_osv_floor):
    root = make_osv_db(tmp_path / "db", ecosystems=("PyPI", "Go"))
    assert osvdb.prune_unsupported(root) == ([], []) and (root / "osv-scalibr" / "Go" / "all.zip").exists()
    other = make_osv_db(tmp_path / "db2", ecosystems=("PyPI", "npm"))
    m = manifest(other)
    del m["ecosystems"]["npm"]
    (other / "manifest.json").write_text(json.dumps(m))
    assert osvdb.prune_unsupported(other) == ([], []) and (other / "osv-scalibr" / "npm" / "all.zip").exists()
    assert osvdb.prune_unsupported(tmp_path / "missing") == ([], [])


def test_osv_db_update_prunes_before_downloading(with_npm, monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(osvdb, "update", lambda d, **kw: seen.append((d / "osv-scalibr" / "npm").exists()) or {})
    assert cli.main(["osv-db", "update", "--dir", str(with_npm)]) == 0
    assert seen == [False] and "Removed OSV data SafeRun no longer supports: npm" in capsys.readouterr().out
    make_osv_db(with_npm, ecosystems=("PyPI", "npm"))
    assert cli.main(["osv-db", "update", "--if-stale", "--dir", str(with_npm)]) == 0      # fresh: no download, still pruned
    assert not (with_npm / "osv-scalibr" / "npm").exists() and seen == [False]


# ====================================================================== C. saferun cleanup
class Leftovers:
    """Fakes for every probe and delete `saferun cleanup` uses."""

    def __init__(self, tmp_path, docker_ok=True):
        self.docker_ok = docker_ok
        self.images = [oldimages.OldImage(OLD, 709_000_000), oldimages.OldImage(OLDER, 5, "it is used by 1 container(s)")]
        self.removed, self.pruned, self.reaps = [], [], []
        self.remove_ok = True
        self.backup = tmp_path / "analyzer-image-id.bak"
        self.backup.write_text(CUR + "\n")
        self.osv = tmp_path / "osv"

    def diagnose(self):
        return SimpleNamespace(ok=self.docker_ok, message=lambda: "Docker is installed but its daemon is not running")

    def find_images(self):
        assert self.docker_ok, "images must not be listed while Docker is unusable"
        return self.images

    def remove_image(self, image_id):
        self.removed.append(image_id)
        return (True, "") if self.remove_ok else (False, "docker rmi refused: conflict")

    def reap(self, dry_run=False, only=None):
        self.reaps.append((dry_run, only))
        errors = [] if self.docker_ok else ["could not list containers: daemon down"]
        names = (["saferun-abc"] if self.docker_ok else []), ["saferun-ws-1"]
        if only is not None:
            names = [n for n in names[0] if n in only], [n for n in names[1] if n in only]
        return ReapReport(containers=list(names[0]), workspaces=list(names[1]), errors=errors)

    def unsupported(self, d):
        return [] if self.pruned else [("npm", 219_396_119)]

    def prune(self, d):
        self.pruned.append(d)
        return [("npm", 219_396_119)], []

    def cleanup(self, interactive=False, answers=()):
        it, out = iter(answers), io.StringIO()

        def ask(q):
            out.write(q)
            try:
                return next(it)
            except StopIteration:
                raise EOFError from None
        c = cu.Cleanup(out=out, ask=ask, interactive=interactive, osv_dir=self.osv, diagnose=self.diagnose, find_images=self.find_images,
                       remove_image=self.remove_image, reap=self.reap, backup_path=self.backup, unsupported=self.unsupported, prune=self.prune)
        c.text = out
        return c

    def nothing_removed(self):
        return self.removed == [] and self.pruned == [] and all(dry for dry, _ in self.reaps) and self.backup.exists()


def test_without_a_terminal_cleanup_only_lists(tmp_path):
    lo = Leftovers(tmp_path)
    c = lo.cleanup()
    assert c.run() == 0 and lo.nothing_removed()
    out = c.text.getvalue()
    assert "Found 5 item(s) to remove" in out and OLD[:19] in out and "709 MB" in out and "npm" in out and "saferun-ws-1" in out
    assert "Kept:" in out and "used by 1 container" in out and "saferun cleanup --yes" in out and cu.NEVER in out


def test_yes_removes_exactly_the_listed_items(tmp_path):
    lo = Leftovers(tmp_path)
    c = lo.cleanup()
    assert c.run(assume_yes=True) == 0
    assert lo.removed == [OLD] and lo.pruned == [lo.osv] and not lo.backup.exists()      # never OLDER (kept: in use)
    assert lo.reaps[-1] == (False, {"saferun-abc", "saferun-ws-1"})
    assert "Done: 5 removed." in c.text.getvalue()


@pytest.mark.parametrize("answers,removes", [([""], False), (["n"], False), ([], False), (["y"], True), (["yes"], True)])
def test_on_a_terminal_it_asks_and_the_default_is_no(tmp_path, answers, removes):
    lo = Leftovers(tmp_path)
    c = lo.cleanup(interactive=True, answers=answers)
    assert c.run() == 0
    assert "Remove these 5 item(s)? [y/N]" in c.text.getvalue() and lo.nothing_removed() is not removes


def test_docker_unusable_is_reported_and_the_rest_still_works(tmp_path):
    lo = Leftovers(tmp_path, docker_ok=False)
    c = lo.cleanup()
    assert c.run(assume_yes=True) == 1
    out = c.text.getvalue()
    assert "Not checked:" in out and "daemon is not running" in out and "could not list containers" not in out
    assert lo.removed == [] and lo.pruned == [lo.osv] and not lo.backup.exists()


def test_a_failed_removal_is_reported_and_exits_1(tmp_path):
    lo = Leftovers(tmp_path)
    lo.remove_ok = False
    c = lo.cleanup()
    assert c.run(assume_yes=True) == 1 and "FAILED   analyzer image" in c.text.getvalue()


def test_a_backup_that_is_a_symlink_is_kept(tmp_path):
    lo = Leftovers(tmp_path)
    target = tmp_path / "precious"
    target.write_text("keep")
    lo.backup.unlink()
    lo.backup.symlink_to(target)
    c = lo.cleanup()
    assert c.run(assume_yes=True) == 0 and lo.backup.is_symlink() and target.read_text() == "keep"
    assert "not a regular file" in c.text.getvalue()


def test_nothing_to_clean_up(tmp_path):
    lo = Leftovers(tmp_path)
    lo.images, lo.pruned = [], ["already"]
    lo.backup.unlink()
    lo.reap = lambda dry_run=False, only=None: ReapReport()
    c = lo.cleanup()
    assert c.run() == 0 and "Nothing to clean up." in c.text.getvalue()


def test_cli_cleanup_lists_then_removes_with_yes(tmp_path, monkeypatch, low_osv_floor, capsys):
    root = make_osv_db(tmp_path / "db", ecosystems=("PyPI", "npm"))
    monkeypatch.setenv("SAFERUN_OSV_DB", str(root))
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(tmp_path / "lockdir" / "analyzer-image-id"))
    (tmp_path / "lockdir").mkdir()
    (tmp_path / "lockdir" / "analyzer-image-id.bak").write_text(CUR)
    monkeypatch.setattr(cu.dockerdiag, "diagnose", lambda: SimpleNamespace(ok=True, message=lambda: ""))
    monkeypatch.setattr(oldimages, "find_old_images", lambda: [])
    monkeypatch.setattr(cu, "reap_orphans", lambda dry_run=False, only=None: ReapReport())
    assert cli.main(["cleanup"]) == 0                                         # pytest's stdin is not a terminal: list only
    assert (root / "osv-scalibr" / "npm").exists() and "saferun cleanup --yes" in capsys.readouterr().out
    assert cli.main(["cleanup", "--yes"]) == 0
    assert not (root / "osv-scalibr" / "npm").exists() and not (tmp_path / "lockdir" / "analyzer-image-id.bak").exists()
    assert osvdb.validate(root, ["PyPI"]).ok


# ---- reaper: list without removing, remove only the confirmed names
def test_reaper_dry_run_and_only(tmp_path, monkeypatch):
    removed = []
    now = time.time()
    monkeypatch.setattr(dk, "docker", lambda *a, timeout=None: proc(0, f"saferun-dead\t{now - 10}\nsaferun-live\t{now + 999}\nother\t1\n"))
    monkeypatch.setattr(dk, "force_remove", lambda name: removed.append(name) or True)
    ws = tmp_path / f"{WS_PREFIX}old"
    ws.mkdir()
    os.utime(ws, (now - 7200, now - 7200))                                     # no lock file and old: abandoned
    rep = reap_orphans(now=now, tmp_root=tmp_path, dry_run=True)
    assert rep.containers == ["saferun-dead"] and rep.workspaces == [ws.name] and removed == [] and ws.exists()
    rep = reap_orphans(now=now, tmp_root=tmp_path, only={"something-else"})
    assert rep.containers == [] and rep.workspaces == [] and ws.exists()
    rep = reap_orphans(now=now, tmp_root=tmp_path, only={"saferun-dead", ws.name})
    assert removed == ["saferun-dead"] and not ws.exists()


def test_size_text():
    assert [ui.size_text(n) for n in (None, 72, 4_500, 219_396_119, 1_230_000_000)] == ["", "72 bytes", "4 kB", "219 MB", "1.2 GB"]


def test_cleanup_command_is_parsed():
    a = cli.build_parser().parse_args(["cleanup", "--yes"])
    assert a.command == "cleanup" and a.yes
