"""Offline OSV database: validation before every scan, download verification, manifest, freshness, directory permissions.
The invariant under test: an invalid, incomplete, unverifiable or stale database NEVER produces a clean (`passed`) dependency check."""
import base64
import hashlib
import io
import json
import os
import stat
import time
import zipfile
from email.message import Message

import pytest

from engine_helpers import FakeRunner, make_ctx, make_osv_db, tool_run
from saferun import cli
from saferun.engine import CheckStatus, osv, osvdb

CLEAN = json.dumps({"results": []})
DAY = 86400


def run_check(tmp_path, runner, files=("package-lock.json",), **opts):
    ctx = make_ctx(tmp_path, files, runner, options=opts)
    return osv.run_check(ctx)


@pytest.fixture
def db(tmp_path, monkeypatch, low_osv_floor):
    root = make_osv_db(tmp_path / "db")
    monkeypatch.setenv("SAFERUN_OSV_DB", str(root))
    return root


def manifest(root):
    return json.loads((root / "manifest.json").read_text())


def save(root, m):
    (root / "manifest.json").write_text(json.dumps(m))


# ============================================================ validation: invalid states are never clean
def test_a_valid_fresh_database_passes_and_reports_its_freshness(tmp_path, db):
    r = FakeRunner(tool_run(CLEAN))
    res = run_check(tmp_path, r)
    assert res.status is CheckStatus.PASSED and r.calls
    notes = "\n".join(res.notes)
    assert "OSV database npm: updated" in notes and "days ago" in notes and "sha256" in notes and "download MD5 verified" in notes
    assert "does not authenticate the original download" in notes


def mutate(fn):
    def apply(root):
        m = manifest(root)
        fn(root, m)
        save(root, m)
    return apply


def replace_with_empty_zip(root):
    p = root / "osv-scalibr" / "npm" / "all.zip"
    buf = io.BytesIO()
    zipfile.ZipFile(buf, "w").close()
    p.write_bytes(buf.getvalue())
    m = manifest(root)
    m["ecosystems"]["npm"].update(sha256=hashlib.sha256(buf.getvalue()).hexdigest(), size=len(buf.getvalue()), entries=0)
    save(root, m)


def replace_content_keep_manifest(root):
    p = root / "osv-scalibr" / "npm" / "all.zip"
    p.write_bytes(p.read_bytes() + b"x")                      # size and hash no longer match


def flip_a_byte_same_size(root):
    p = root / "osv-scalibr" / "npm" / "all.zip"
    b = bytearray(p.read_bytes())
    b[5] ^= 0xFF
    p.write_bytes(bytes(b))


def swap_for_symlink(root):
    p = root / "osv-scalibr" / "npm" / "all.zip"
    real = root / "real.zip"
    p.rename(real)
    p.symlink_to(real)


def unreadable_for_others(root):
    (root / "osv-scalibr" / "npm" / "all.zip").chmod(0o600)


def directory_not_traversable(root):
    (root / "osv-scalibr" / "npm").chmod(0o700)


BAD_STATES = {
    "no-manifest": lambda root: (root / "manifest.json").unlink(),
    "manifest-not-json": lambda root: (root / "manifest.json").write_text("{not json"),
    "manifest-is-a-list": lambda root: save(root, []),
    "manifest-wrong-schema": mutate(lambda r, m: m.update(schema=99)),
    "manifest-no-ecosystems": mutate(lambda r, m: m.update(ecosystems={})),
    "ecosystem-missing-from-manifest": mutate(lambda r, m: m["ecosystems"].pop("npm")),
    "entry-not-an-object": mutate(lambda r, m: m["ecosystems"].update(npm="x")),
    "sha-not-hex": mutate(lambda r, m: m["ecosystems"]["npm"].update(sha256="z" * 64)),
    "sha-too-short": mutate(lambda r, m: m["ecosystems"]["npm"].update(sha256="ab")),
    "size-zero": mutate(lambda r, m: m["ecosystems"]["npm"].update(size=0)),
    "size-bool": mutate(lambda r, m: m["ecosystems"]["npm"].update(size=True)),
    "entries-negative": mutate(lambda r, m: m["ecosystems"]["npm"].update(entries=-1)),
    "entries-string": mutate(lambda r, m: m["ecosystems"]["npm"].update(entries="3")),
    "timestamp-missing": mutate(lambda r, m: m["ecosystems"]["npm"].pop("updated_epoch")),
    "timestamp-nan": mutate(lambda r, m: m["ecosystems"]["npm"].update(updated_epoch=float("nan"))),
    "timestamp-in-the-future": mutate(lambda r, m: m["ecosystems"]["npm"].update(updated_epoch=int(time.time()) + 30 * DAY)),
    "md5-status-unknown": mutate(lambda r, m: m["ecosystems"]["npm"].update(md5="maybe")),
    "empty-zip-with-matching-manifest": replace_with_empty_zip,
    "file-size-changed": replace_content_keep_manifest,
    "file-same-size-different-content": flip_a_byte_same_size,
    "data-file-is-a-symlink": swap_for_symlink,
    "data-file-unreadable-for-the-sandbox-user": unreadable_for_others,
    "ecosystem-dir-not-traversable-for-the-sandbox-user": directory_not_traversable,
    "data-file-missing": lambda root: (root / "osv-scalibr" / "npm" / "all.zip").unlink(),
}


@pytest.mark.parametrize("state", sorted(BAD_STATES))
def test_every_invalid_database_state_is_an_error_never_clean_and_nothing_runs(tmp_path, db, state):
    BAD_STATES[state](db)
    r = FakeRunner(tool_run(CLEAN))
    res = run_check(tmp_path, r)
    assert res.status is CheckStatus.ERROR and not r.calls and not res.findings, (state, res.status, res.detail)
    assert "NOT checked" in res.detail and "saferun osv-db update" in res.detail


def test_database_directory_that_is_a_symlink_or_missing_is_an_error(tmp_path, db, monkeypatch):
    link = tmp_path / "link"
    link.symlink_to(db)
    for target in (link, tmp_path / "nowhere"):
        monkeypatch.setenv("SAFERUN_OSV_DB", str(target))
        r = FakeRunner(tool_run(CLEAN))
        res = run_check(tmp_path, r)
        assert res.status is CheckStatus.ERROR and not r.calls


def test_database_directory_unreadable_by_others_is_an_error(tmp_path, db):
    db.chmod(0o700)
    res = run_check(tmp_path, FakeRunner(tool_run(CLEAN)))
    assert res.status is CheckStatus.ERROR and "uid 65534" in res.detail


def test_incomplete_database_missing_the_needed_ecosystem(tmp_path, monkeypatch, low_osv_floor):
    only_pypi = make_osv_db(tmp_path / "pypi-only", ecosystems=("PyPI",))
    monkeypatch.setenv("SAFERUN_OSV_DB", str(only_pypi))
    r = FakeRunner(tool_run(CLEAN))
    assert run_check(tmp_path, r, files=["package-lock.json"]).status is CheckStatus.ERROR        # needs npm
    assert not r.calls
    assert run_check(tmp_path, FakeRunner(tool_run(CLEAN)), files=["requirements.txt"]).status is CheckStatus.PASSED   # needs only PyPI


def test_stub_database_below_the_real_floors_is_an_error(tmp_path, monkeypatch):
    """The production floors, not the lowered test ones: a 3-advisory archive is a stub, however consistent its manifest."""
    stub = make_osv_db(tmp_path / "stub", entries=3)
    monkeypatch.setenv("SAFERUN_OSV_DB", str(stub))
    r = FakeRunner(tool_run(CLEAN))
    res = run_check(tmp_path, r)
    assert res.status is CheckStatus.ERROR and not r.calls and "minimum" in res.detail


def test_validation_never_raises_on_hostile_directories(tmp_path):
    for target in (tmp_path / "a-file", tmp_path / "missing", tmp_path):
        (tmp_path / "a-file").write_text("x")
        rep = osvdb.validate(target)
        assert not rep.ok and rep.problems


# ============================================================ staleness
def test_stale_database_is_incomplete_never_passed_and_findings_are_kept(tmp_path, db, low_osv_floor):
    make_osv_db(db, age_days=45)
    clean = run_check(tmp_path, FakeRunner(tool_run(CLEAN)))
    assert clean.status is CheckStatus.INCOMPLETE and "45 days old" in clean.detail and "limit 30" in clean.detail
    assert any("45." in n and "days ago" in n for n in clean.notes)
    from engine_helpers import OSV_JSON
    found = run_check(tmp_path, FakeRunner(tool_run(OSV_JSON, exit_code=1)))
    assert found.status is CheckStatus.INCOMPLETE and found.findings                                  # findings are not discarded


def test_age_limit_is_configurable_and_the_boundary_is_exclusive(tmp_path, db):
    make_osv_db(db, age_days=10)
    assert run_check(tmp_path, FakeRunner(tool_run(CLEAN))).status is CheckStatus.PASSED
    assert run_check(tmp_path, FakeRunner(tool_run(CLEAN)), osv_db_max_age_days=5).status is CheckStatus.INCOMPLETE
    entry_time = manifest(db)["ecosystems"]["npm"]["updated_epoch"]
    assert osvdb.validate(db, ["npm"], max_age_days=10, now=entry_time + 10 * DAY).stale == ""           # exactly at the limit: fresh
    assert "days old" in osvdb.validate(db, ["npm"], max_age_days=10, now=entry_time + 10 * DAY + 3600).stale   # just beyond: stale


def test_the_oldest_needed_ecosystem_decides_freshness(tmp_path, db, low_osv_floor):
    m = manifest(db)
    m["ecosystems"]["PyPI"]["updated_epoch"] = int(time.time()) - 60 * DAY
    save(db, m)
    assert osvdb.validate(db, ["npm"]).stale == ""
    assert "60 days old" in osvdb.validate(db, ["PyPI", "npm"]).stale
    assert run_check(tmp_path, FakeRunner(tool_run(CLEAN)), files=["requirements.txt"]).status is CheckStatus.INCOMPLETE


def test_unverified_download_is_reported_in_the_notes(tmp_path, db, low_osv_floor):
    make_osv_db(db, md5="unverified")
    res = run_check(tmp_path, FakeRunner(tool_run(CLEAN)))
    assert res.status is CheckStatus.PASSED
    assert any("WITHOUT a server-provided hash" in n for n in res.notes)


# ============================================================ download verification
class Resp(io.BytesIO):
    def __init__(self, data, goog=()):
        super().__init__(data)
        self.headers = Message()
        for v in goog:
            self.headers["x-goog-hash"] = v          # one header line per value, like the real server

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def archive(n=3, extra=()):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for i in range(n):
            z.writestr(f"A-{i}.json", "{}")
        for name in extra:
            z.writestr(name, "x")
    return b.getvalue()


def md5_header(data, wrong=False):
    d = hashlib.md5(data).digest() if not wrong else b"\0" * 16
    return "md5=" + base64.b64encode(d).decode()


def opener(data, goog=None, urls=None):
    goog = (["crc32c=AAAAAA==", md5_header(data)] if goog is None else goog)

    def op(url, timeout=None):
        if urls is not None:
            urls.append(url)
        return Resp(data, goog)
    return op


def test_update_installs_verified_data_with_a_full_manifest(tmp_path, low_osv_floor):
    data, urls = archive(5), []
    root = tmp_path / "db"
    res = osvdb.update(root, ("PyPI", "npm"), opener=opener(data, urls=urls), clock=lambda: 1_700_000_000)
    assert urls == [f"{osvdb.BASE_URL}/PyPI/all.zip", f"{osvdb.BASE_URL}/npm/all.zip"]
    e = manifest(root)["ecosystems"]["npm"]
    assert e == res["npm"] and e["sha256"] == hashlib.sha256(data).hexdigest() and e["size"] == len(data)
    assert e["entries"] == 5 and e["updated_epoch"] == 1_700_000_000 and e["md5"] == "verified" and e["updated_at"].endswith("UTC")
    assert osvdb.validate(root, now=1_700_000_000 + DAY).ok
    assert stat.S_IMODE((root / "osv-scalibr" / "npm" / "all.zip").stat().st_mode) == 0o644
    assert [p.name for p in (root / "osv-scalibr" / "npm").iterdir()] == ["all.zip"]               # no temp debris


def test_md5_is_found_when_the_server_sends_crc32c_and_md5_as_separate_headers(tmp_path, low_osv_floor):
    """Regression: the real server sends two x-goog-hash headers; reading only the first made the MD5 check a silent no-op."""
    data = archive(2)
    r = Resp(data, ["crc32c=AAAAAA==", md5_header(data)])
    assert osvdb._goog_md5(osvdb._header_values(r.headers, "x-goog-hash")) == hashlib.md5(data).hexdigest()
    with pytest.raises(ValueError, match="MD5 mismatch"):
        osvdb.update(tmp_path / "db", ("npm",), opener=opener(data, ["crc32c=AAAAAA==", md5_header(data, wrong=True)]))


@pytest.mark.parametrize("goog", [[], ["crc32c=AAAAAA=="], ["md5="], ["md5=%%%notbase64"], ["md5=" + base64.b64encode(b"short").decode()]])
def test_missing_or_unusable_md5_header_is_refused_by_default(tmp_path, low_osv_floor, goog):
    root = tmp_path / "db"
    with pytest.raises(ValueError, match="cannot be integrity-checked.*--allow-unverified"):
        osvdb.update(root, ("npm",), opener=opener(archive(3), goog))
    assert not (root / "osv-scalibr" / "npm" / "all.zip").exists() and not (root / "manifest.json").exists()


def test_allow_unverified_installs_but_records_and_reports_it(tmp_path, low_osv_floor):
    root = tmp_path / "db"
    res = osvdb.update(root, ("npm",), opener=opener(archive(3), []), allow_unverified=True)
    assert res["npm"]["md5"] == "unverified" and manifest(root)["ecosystems"]["npm"]["md5"] == "unverified"
    rep = osvdb.validate(root)
    assert rep.ok and any("WITHOUT a server-provided hash" in n for n in rep.notes)


def test_a_wrong_md5_is_refused_even_with_allow_unverified(tmp_path, low_osv_floor):
    with pytest.raises(ValueError, match="MD5 mismatch"):
        osvdb.update(tmp_path / "db", ("npm",), opener=opener(archive(3), [md5_header(archive(3), wrong=True)]), allow_unverified=True)


def test_empty_incomplete_and_corrupt_archives_are_never_installed(tmp_path):
    """Production floors (no low_osv_floor): even a correctly hashed tiny archive is rejected as a stub."""
    root = tmp_path / "db"
    for data, match in ((archive(0), "only 0 advisories"), (archive(3), "only 3 advisories"), (archive(0, extra=["notes.txt"] * 1), "only 0"),
                        (b"", "empty download"), (b"not a zip at all", "not a readable zip"), (archive(3)[:-10], "not a readable zip")):
        with pytest.raises(ValueError, match=match):
            osvdb.update(root, ("PyPI",), opener=opener(data, [md5_header(data)]))
        assert not (root / "osv-scalibr" / "PyPI" / "all.zip").exists() and not (root / "manifest.json").exists()


def test_failed_update_keeps_the_previous_data_and_manifest_consistent(tmp_path, low_osv_floor):
    root = tmp_path / "db"
    osvdb.update(root, ("npm",), opener=opener(archive(4)))
    before = (root / "osv-scalibr" / "npm" / "all.zip").read_bytes(), manifest(root)
    with pytest.raises(ValueError):
        osvdb.update(root, ("npm",), opener=opener(archive(5), [md5_header(archive(5), wrong=True)]))
    assert ((root / "osv-scalibr" / "npm" / "all.zip").read_bytes(), manifest(root)) == before and osvdb.validate(root).ok


def test_a_partial_update_still_validates_for_the_ecosystems_that_succeeded(tmp_path, low_osv_floor):
    root = tmp_path / "db"
    calls = []

    def op(url, timeout=None):
        calls.append(url)
        if "npm" in url:
            raise OSError("network down")
        d = archive(3)
        return Resp(d, [md5_header(d)])
    with pytest.raises(OSError):
        osvdb.update(root, ("PyPI", "npm"), opener=op)
    assert osvdb.validate(root, ["PyPI"]).ok and not osvdb.validate(root, ["npm"]).ok


def test_http_unknown_ecosystem_and_oversize_are_refused(tmp_path, monkeypatch, low_osv_floor):
    with pytest.raises(ValueError, match="https"):
        osvdb.update(tmp_path / "d", ("npm",), base_url="http://osv.example", opener=opener(archive(3)))
    with pytest.raises(ValueError, match="unsupported ecosystem"):
        osvdb.update(tmp_path / "d", ("../../etc",), opener=opener(archive(3)))
    monkeypatch.setattr(osvdb, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="exceeds"):
        osvdb.update(tmp_path / "d", ("npm",), opener=opener(archive(3)))
    assert not list((tmp_path / "d" / "osv-scalibr" / "npm").glob("*"))


# ============================================================ directory permissions
def test_update_never_changes_the_permissions_of_an_existing_directory(tmp_path, low_osv_floor):
    home = tmp_path / "home"
    home.mkdir()
    home.chmod(0o700)
    osvdb.update(home, ("npm",), opener=opener(archive(3)))                    # `--dir ~`-style: the directory already exists
    assert stat.S_IMODE(home.stat().st_mode) == 0o700                           # untouched
    assert stat.S_IMODE((home / "osv-scalibr").stat().st_mode) == 0o755         # only what SafeRun created is made readable
    assert not osvdb.validate(home).ok                                          # ...and the unreadable root is REPORTED, not silently fixed
    assert "chmod o+rx" in " ".join(osvdb.validate(home).problems)


def test_existing_group_writable_and_world_readable_directories_keep_their_modes(tmp_path, low_osv_floor):
    for mode in (0o775, 0o755, 0o750, 0o700):
        d = tmp_path / f"d{mode:o}"
        d.mkdir()
        d.chmod(mode)
        (d / "osv-scalibr").mkdir()
        (d / "osv-scalibr").chmod(mode)
        osvdb.update(d, ("PyPI",), opener=opener(archive(3)))
        assert stat.S_IMODE(d.stat().st_mode) == mode and stat.S_IMODE((d / "osv-scalibr").stat().st_mode) == mode


def test_directories_created_by_update_are_readable_by_the_sandbox_user_whatever_the_umask(tmp_path, low_osv_floor):
    old = os.umask(0o077)
    try:
        root = tmp_path / "fresh" / "db"
        osvdb.update(root, ("npm",), opener=opener(archive(3)))
    finally:
        os.umask(old)
    for p in (root, root / "osv-scalibr", root / "osv-scalibr" / "npm"):
        assert stat.S_IMODE(p.stat().st_mode) == 0o755
    assert stat.S_IMODE((root / "manifest.json").stat().st_mode) == 0o644 and osvdb.validate(root).ok
    assert stat.S_IMODE(root.parent.stat().st_mode) == 0o700                    # the created parent follows the umask: SafeRun does not chmod it


def test_symlinked_database_directories_are_refused(tmp_path, low_osv_floor):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        osvdb.update(link, ("npm",), opener=opener(archive(3)))
    root = tmp_path / "db"
    root.mkdir()
    (root / "osv-scalibr").symlink_to(real)
    with pytest.raises(ValueError, match="symlink"):
        osvdb.update(root, ("npm",), opener=opener(archive(3)))
    assert list(real.iterdir()) == []


# ============================================================ CLI
def test_cli_update_refuses_unverified_downloads_unless_allowed(tmp_path, monkeypatch, capsys, low_osv_floor):
    monkeypatch.setattr(osvdb.urllib.request, "urlopen", opener(archive(3), []))    # no network in this test: urlopen is replaced
    assert cli.main(["osv-db", "update", "--dir", str(tmp_path / "a")]) == 70
    assert "--allow-unverified" in capsys.readouterr().err
    assert cli.main(["osv-db", "update", "--dir", str(tmp_path / "b"), "--allow-unverified"]) == 0
    cap = capsys.readouterr()
    assert "MD5 unverified" in cap.out and "WITHOUT a server-provided hash" in cap.err


def test_cli_status_reports_problems_staleness_and_freshness(tmp_path, capsys, low_osv_floor):
    good = make_osv_db(tmp_path / "good")
    assert cli.main(["osv-db", "status", "--dir", str(good)]) == 0
    out = capsys.readouterr().out
    assert "usable and fresh" in out and "days ago" in out and "sha256" in out
    old = make_osv_db(tmp_path / "old", age_days=90)
    assert cli.main(["osv-db", "status", "--dir", str(old)]) == 1
    assert "STALE" in capsys.readouterr().out
    assert cli.main(["osv-db", "status", "--dir", str(old), "--max-age-days", "365"]) == 0
    assert cli.main(["osv-db", "status", "--dir", str(tmp_path / "nothing")]) == 1
    assert "PROBLEM" in capsys.readouterr().out
    assert cli.main(["osv-db", "status", "--dir", str(good), "--max-age-days", "0"]) == 64
