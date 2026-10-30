"""The analyzer image lock is only trusted when it and its directory are owner-only and owned by the current user (fail closed)."""
import json
import os
import stat
from types import SimpleNamespace

import pytest

from saferun.sandbox import SandboxError
from saferun.sandbox import analyzer as sa
from saferun.sandbox import docker as dk
from saferun.sandbox import images

ID = "sha256:" + "c" * 64


def good_inspect():
    labels = {"saferun.analyzer": "1", "saferun.semgrep.version": images.SEMGREP_VERSION,
              "saferun.osv-scanner.version": images.OSV_SCANNER_VERSION, "saferun.rules.sha256": sa.rules_sha256()}
    return json.dumps({"Id": ID, "Config": {"Labels": labels}})


@pytest.fixture
def docker_calls(monkeypatch):
    calls = []
    out = good_inspect()                       # labels computed now, before any test patches rules_sha256

    def fake(*a, timeout=None):
        calls.append(a)
        return SimpleNamespace(returncode=0, stdout=out, stderr="")
    monkeypatch.setattr(dk, "docker", fake)
    return calls


def make_lock(tmp_path, monkeypatch, dir_mode=0o700, file_mode=0o600, text=ID + "\n", name="locks"):
    d = tmp_path / name
    d.mkdir()
    d.chmod(dir_mode)
    p = d / "analyzer-image-id"
    p.write_text(text)
    p.chmod(file_mode)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(p))
    return p


def test_owner_only_lock_is_trusted(tmp_path, monkeypatch, docker_calls):
    make_lock(tmp_path, monkeypatch)
    assert sa.verify_analyzer_image() == ID


@pytest.mark.parametrize("file_mode", [0o644, 0o664, 0o666, 0o640, 0o604, 0o660, 0o606, 0o601])
def test_lock_file_accessible_to_others_is_refused_before_docker_is_asked(tmp_path, monkeypatch, docker_calls, file_mode):
    make_lock(tmp_path, monkeypatch, file_mode=file_mode)
    with pytest.raises(sa.AnalyzerIntegrityError, match="accessible to others.*chmod 600"):
        sa.verify_analyzer_image()
    assert docker_calls == []                                        # nothing is trusted, so nothing is even inspected


@pytest.mark.parametrize("dir_mode", [0o755, 0o775, 0o777, 0o750, 0o705, 0o770, 0o701])
def test_lock_directory_accessible_to_others_is_refused(tmp_path, monkeypatch, docker_calls, dir_mode):
    make_lock(tmp_path, monkeypatch, dir_mode=dir_mode)
    with pytest.raises(sa.AnalyzerIntegrityError, match="lock directory.*accessible to others.*chmod 700"):
        sa.verify_analyzer_image()
    assert docker_calls == []


def test_lock_owned_by_someone_else_is_refused(tmp_path, monkeypatch, docker_calls):
    make_lock(tmp_path, monkeypatch)
    real = os.geteuid()
    monkeypatch.setattr(sa.os, "geteuid", lambda: real + 1)         # pretend we are a different user than the owner
    with pytest.raises(sa.AnalyzerIntegrityError, match="owned by uid"):
        sa.verify_analyzer_image()
    assert docker_calls == []


def test_symlinked_lock_file_is_refused(tmp_path, monkeypatch, docker_calls):
    real = make_lock(tmp_path, monkeypatch, name="real")
    d = tmp_path / "linkdir"
    d.mkdir(mode=0o700)
    link = d / "analyzer-image-id"
    link.symlink_to(real)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(link))
    with pytest.raises(sa.AnalyzerIntegrityError, match="symlink"):
        sa.verify_analyzer_image()
    assert docker_calls == []


def test_symlinked_lock_directory_is_refused(tmp_path, monkeypatch, docker_calls):
    real = make_lock(tmp_path, monkeypatch, name="real")
    link_dir = tmp_path / "linked"
    link_dir.symlink_to(real.parent)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(link_dir / "analyzer-image-id"))
    with pytest.raises(sa.AnalyzerIntegrityError, match="not a real directory"):
        sa.verify_analyzer_image()
    assert docker_calls == []


def test_lock_that_is_not_a_regular_file_is_refused(tmp_path, monkeypatch, docker_calls):
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    (d / "analyzer-image-id").mkdir()
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(d / "analyzer-image-id"))
    with pytest.raises(sa.AnalyzerIntegrityError):
        sa.verify_analyzer_image()
    assert docker_calls == []


def test_missing_lock_is_still_unavailable_not_integrity(tmp_path, monkeypatch, docker_calls):
    d = tmp_path / "d"
    d.mkdir(mode=0o700)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(d / "absent"))
    with pytest.raises(sa.AnalyzerUnavailable):
        sa.verify_analyzer_image()


def test_existing_image_id_tool_and_rules_checks_are_unchanged(tmp_path, monkeypatch, docker_calls):
    make_lock(tmp_path, monkeypatch, text="sha256:" + "d" * 64 + "\n")
    with pytest.raises(sa.AnalyzerIntegrityError, match="ID mismatch"):
        sa.verify_analyzer_image()
    make_lock(tmp_path, monkeypatch, name="again")
    monkeypatch.setattr(sa, "rules_sha256", lambda: "0" * 64)
    with pytest.raises(sa.AnalyzerIntegrityError, match="rules"):
        sa.verify_analyzer_image()


# ---------------------------------------------------------------- write_lock (used by docker/analyzer/build.sh)
def test_write_lock_creates_private_directory_and_file(tmp_path, monkeypatch, docker_calls):
    p = tmp_path / "new" / "state" / "analyzer-image-id"
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(p))
    old = os.umask(0o002)
    try:
        assert sa.write_lock(ID) == p
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700 and stat.S_IMODE(p.stat().st_mode) == 0o600
    assert p.read_text() == ID + "\n" and sa.verify_analyzer_image() == ID
    assert [x.name for x in p.parent.iterdir()] == ["analyzer-image-id"]


def test_write_lock_refuses_an_existing_loose_directory_and_does_not_chmod_it(tmp_path, monkeypatch):
    d = tmp_path / "shared"
    d.mkdir()
    d.chmod(0o775)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(d / "analyzer-image-id"))
    with pytest.raises(SandboxError, match="not writing the analyzer lock.*chmod 700"):
        sa.write_lock(ID)
    assert stat.S_IMODE(d.stat().st_mode) == 0o775 and list(d.iterdir()) == []


def test_write_lock_replaces_atomically_and_tightens_the_file_mode(tmp_path, monkeypatch, docker_calls):
    p = make_lock(tmp_path, monkeypatch, text="sha256:" + "e" * 64 + "\n")
    sa.write_lock(ID)
    assert p.read_text() == ID + "\n" and stat.S_IMODE(p.stat().st_mode) == 0o600 and len(list(p.parent.iterdir())) == 1


def test_write_lock_refuses_symlinked_directories_and_bad_ids(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(link / "analyzer-image-id"))
    with pytest.raises(SandboxError, match="symlink"):
        sa.write_lock(ID)
    monkeypatch.setenv("SAFERUN_ANALYZER_LOCK", str(real / "analyzer-image-id"))
    for bad in ("", "sha256:short", ID.upper(), ID + "x", None, 5):
        with pytest.raises(SandboxError, match="not an image ID"):
            sa.write_lock(bad)
    assert list(real.iterdir()) == []
