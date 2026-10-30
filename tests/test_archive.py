"""Adversarial tests for the hostile-ZIP extractor (saferun/api/archive.py, Phase 4 step 1).

Archives are built in memory with `zipfile` and, where zipfile will not write the hostile thing, patched at the
byte level (offsets in the helpers below). No binary fixtures, no Docker, no network. Every rejection test also
proves the extractor left nothing behind: the whole temp area is snapshotted before and after.
"""
import io
import os
import stat
import struct
import subprocess
import sys
import types
import unicodedata
import warnings
import zipfile
from pathlib import Path

import pytest

from saferun.api import archive
from saferun.api.archive import ArchiveError, ArchiveLimits, MiB, extract_zip

# ------------------------------------------------------------------------------------------- builders

REG = (stat.S_IFREG | 0o644) << 16
DIR = ((stat.S_IFDIR | 0o755) << 16) | 0x10


def make_zip(members, compression=zipfile.ZIP_DEFLATED, comment=b"") -> bytes:
    """members: (name, data) or (name, data, external_attr) or (name, data, external_attr, compress_type)."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # zipfile warns on duplicate names; that is the point of some tests
        with zipfile.ZipFile(buf, "w", compression) as zf:
            for m in members:
                name, data, *rest = m
                zi = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                zi.external_attr = rest[0] if rest and rest[0] is not None else (DIR if name.endswith("/") else REG)
                zi.compress_type = rest[1] if len(rest) > 1 else compression
                zf.writestr(zi, data)
            zf.comment = comment
    return buf.getvalue()


def sigs(data: bytes, sig: bytes) -> list[int]:
    out, i = [], data.find(sig)
    while i >= 0:
        out.append(i)
        i = data.find(sig, i + 1)
    return out


def local_hdrs(data): return sigs(data, b"PK\x03\x04")
def central_hdrs(data): return sigs(data, b"PK\x01\x02")
def eocd(data): return data.rfind(b"PK\x05\x06")


def put(data: bytes, pos: int, fmt: str, value) -> bytes:
    raw = struct.pack(fmt, value)
    return data[:pos] + raw + data[pos + len(raw):]


def set_flag_bit(data: bytes, bit: int) -> bytes:
    for p in local_hdrs(data):
        data = put(data, p + 6, "<H", struct.unpack_from("<H", data, p + 6)[0] | bit)
    for p in central_hdrs(data):
        data = put(data, p + 8, "<H", struct.unpack_from("<H", data, p + 8)[0] | bit)
    return data


def rename_raw(data: bytes, old: bytes, new: bytes) -> bytes:
    """Replace a member name by raw bytes of the same length in every header (local and central)."""
    assert len(old) == len(new)
    return data.replace(old, new)


@pytest.fixture
def env(tmp_path, ws_root):
    """tmp_path/in.zip is where archives are written; extraction goes to ws_root (= tempfile.tempdir)."""
    class Env:
        root = tmp_path
        wsroot = ws_root

        def write(self, data: bytes) -> Path:
            p = tmp_path / "in.zip"
            p.write_bytes(data)
            return p

        def snap(self):
            return sorted((str(p.relative_to(tmp_path)), p.is_symlink()) for p in tmp_path.rglob("*"))

        def reject(self, data: bytes, code, limits=None):
            """Extraction must raise ArchiveError(code) and must leave the filesystem exactly as it was."""
            p = self.write(data)
            before = self.snap()
            with pytest.raises(ArchiveError) as ei:
                extract_zip(p, limits)
            codes = (code,) if isinstance(code, str) else code
            assert ei.value.code in codes, f"got {ei.value!r}, expected {codes}"
            assert self.snap() == before, "the extractor left files behind"
            assert list(ws_root.iterdir()) == []
            return ei.value

        def accept(self, data: bytes, limits=None):
            return extract_zip(self.write(data), limits)

    return Env()


def tree(project: Path) -> dict[str, bytes | None]:
    out = {}
    for p in sorted(project.rglob("*")):
        out[p.relative_to(project).as_posix()] = None if p.is_dir() else p.read_bytes()
    return out


# --------------------------------------------------------------------------------- the accepting path

def test_defaults_match_the_approved_limits():
    d = ArchiveLimits()
    assert (d.max_archive_bytes, d.max_total_bytes, d.max_entries, d.max_file_bytes) == (100 * MiB, 400 * MiB, 5000, 25 * MiB)


def test_limits_must_be_positive():
    for bad in ({"max_entries": 0}, {"max_total_bytes": -1}, {"max_seconds": float("nan")}, {"max_ratio": True}):
        with pytest.raises(ValueError):
            ArchiveLimits(**bad)


def test_ordinary_archive_is_extracted_exactly(env):
    r = env.accept(make_zip([("src/", b""), ("src/app.py", b"print(1)\n"), ("src/pkg/mod.py", b"x = 1\n"),
                             ("README.md", b"hi"), ("empty.txt", b""), ("data/", b"")]))
    try:
        assert tree(r.project) == {"src": None, "src/app.py": b"print(1)\n", "src/pkg": None,
                                   "src/pkg/mod.py": b"x = 1\n", "README.md": b"hi", "empty.txt": b"",
                                   "data": None}
        assert (r.files, r.dirs, r.bytes, r.archive_entries) == (4, 3, 9 + 6 + 2, 6)
        assert r.stripped_prefix is None and r.excluded == () and r.excluded_total == 0
        assert r.project.parent == r.workdir and r.workdir.parent == env.wsroot
        assert r.workdir.name.startswith("saferun-up-")
    finally:
        r.cleanup()
    assert list(env.wsroot.iterdir()) == []


def test_modes_are_normalised_and_workdir_is_private_even_under_a_hostile_umask(env):
    hostile = ((stat.S_IFREG | 0o4777) << 16)           # setuid + world-writable + executable in the archive
    old = os.umask(0o077)
    try:
        r = env.accept(make_zip([("d/x.sh", b"#!/bin/sh\n", hostile), ("d/y.py", b"1", REG), ("top.txt", b"t")]))
    finally:
        os.umask(old)
    try:
        assert stat.S_IMODE(r.workdir.stat().st_mode) == 0o700
        assert stat.S_IMODE((r.project / "d").stat().st_mode) == 0o755
        for f in ("d/x.sh", "d/y.py"):
            assert stat.S_IMODE((r.project / f).stat().st_mode) == 0o644
    finally:
        r.cleanup()


def test_extraction_survives_the_phase1_sanitizer_with_nothing_withheld(env):
    """Regression for the gotcha that 0600 files would be withheld: a hostile umask must not matter."""
    from saferun.sandbox.workspace import create_workspace
    old = os.umask(0o077)
    try:
        r = env.accept(make_zip([("a.py", b"x=1\n"), ("sub/b.py", b"y=2\n"), ("sub/deeper/c.txt", b"z")]))
    finally:
        os.umask(old)
    try:
        ws = create_workspace(r.project)
        try:
            assert ws.withheld == [] and ws.skipped == []
            assert ws.copied_files == 3
        finally:
            ws.cleanup()
    finally:
        r.cleanup()


def test_control_private_files_would_indeed_be_withheld(tmp_path, ws_root):
    """Shows the previous test is meaningful: a 0600 file IS withheld by the Phase 1 copier."""
    from saferun.sandbox.workspace import create_workspace
    src = tmp_path / "p"
    src.mkdir()
    (src / "a.py").write_text("x")
    os.chmod(src / "a.py", 0o600)
    ws = create_workspace(src)
    try:
        assert len(ws.withheld) == 1 and ws.copied_files == 0
    finally:
        ws.cleanup()


def test_nothing_is_executed_or_imported(env, tmp_path):
    marker = tmp_path / "pwned"
    code = f"open({str(marker)!r}, 'w').write('x')\n"
    r = env.accept(make_zip([("conftest.py", code.encode()), ("setup.py", code.encode()),
                             ("__init__.py", code.encode()), ("run.sh", f"touch {marker}".encode())]))
    r.cleanup()
    assert not marker.exists()


def test_nested_archives_are_just_files(env):
    inner = make_zip([("inner.py", b"1")])
    r = env.accept(make_zip([("inner.zip", inner), ("a.txt", b"a")]))
    try:
        assert (r.project / "inner.zip").read_bytes() == inner and r.files == 2
    finally:
        r.cleanup()


def test_non_ascii_utf8_names_with_flag_are_fine(env):
    r = env.accept(make_zip([("naïve/日本.py", b"1"), ("top.txt", b"t")]))
    try:
        assert (r.project / "naïve" / "日本.py").read_bytes() == b"1"
    finally:
        r.cleanup()


def test_utf8_name_without_the_utf8_flag_is_recovered(env):
    # "é.py" is 5 bytes in UTF-8 (c3 a9 2e 70 79); the flag bit is not set, so zipfile decodes it as cp437
    data = rename_raw(make_zip([("ab.py", b"1")]), b"ab.py", "é.py".encode("utf-8"))
    r = env.accept(data)
    try:
        assert tree(r.project) == {"é.py": b"1"}
    finally:
        r.cleanup()


def test_depth_and_length_boundaries_are_accepted(env):
    deep = "/".join(["d"] * 32) + "/f.txt"                      # exactly 32 directories
    comp = "c" * 255 + "/f"                                     # exactly the component limit
    r = env.accept(make_zip([(deep, b"1"), (comp, b"2")]))
    r.cleanup()


# ------------------------------------------------------------------ wrapper directory and exclusions

def test_single_wrapper_directory_is_stripped(env):
    r = env.accept(make_zip([("repo-main/", b""), ("repo-main/a.py", b"1"), ("repo-main/sub/b.py", b"2")]))
    try:
        assert r.stripped_prefix == "repo-main"
        assert tree(r.project) == {"a.py": b"1", "sub": None, "sub/b.py": b"2"}
    finally:
        r.cleanup()


@pytest.mark.parametrize("members", [
    [("a.py", b"1"), ("repo/b.py", b"2")],                     # a top-level file
    [("one/a.py", b"1"), ("two/b.py", b"2")],                  # two top-level directories
    [("README", b"1")],                                       # a single top-level file
])
def test_wrapper_is_not_stripped_when_ambiguous(env, members):
    r = env.accept(make_zip(members))
    try:
        assert r.stripped_prefix is None and r.project == r.workdir / "project"
    finally:
        r.cleanup()


def test_only_one_wrapper_level_is_stripped(env):
    r = env.accept(make_zip([("outer/inner/a.py", b"1")]))
    try:
        assert r.stripped_prefix == "outer" and tree(r.project) == {"inner": None, "inner/a.py": b"1"}
    finally:
        r.cleanup()


def test_macosx_and_ds_store_are_excluded_and_disclosed(env):
    r = env.accept(make_zip([("proj/", b""), ("proj/a.py", b"1"), ("proj/.DS_Store", b"junk"),
                             ("proj/sub/.DS_Store", b"junk"), ("__MACOSX/", b""), ("__MACOSX/proj/._a.py", b"junk")]))
    try:
        assert r.stripped_prefix == "proj"                   # exclusion happens before the wrapper decision
        assert tree(r.project) == {"a.py": b"1"}             # nothing of the excluded members, not even sub/
        assert r.excluded == ("__MACOSX/", "__MACOSX/proj/._a.py", "proj/.DS_Store", "proj/sub/.DS_Store")
        assert r.excluded_total == 4
        assert not (r.workdir / "__MACOSX").exists()
    finally:
        r.cleanup()


def test_macosx_only_matches_at_the_top_level(env):
    r = env.accept(make_zip([("a/__MACOSX/x.py", b"1"), ("b.py", b"2")]))
    try:
        assert "a/__MACOSX/x.py" in tree(r.project) and r.excluded_total == 0
    finally:
        r.cleanup()


def test_excluded_members_are_still_validated(env):
    env.reject(make_zip([("a.py", b"1"), ("__MACOSX/../evil", b"x")]), "unsafe-name")
    env.reject(make_zip([("a.py", b"1"), ("__MACOSX/link", b"x", (stat.S_IFLNK | 0o777) << 16)]), "unsafe-member-type")
    env.reject(make_zip([("a.py", b"1"), ("sub/.DS_Store", b"x", (stat.S_IFCHR | 0o666) << 16)]), "unsafe-member-type")


@pytest.mark.parametrize("members", [
    [("__MACOSX/", b""), ("__MACOSX/._a", b"x"), (".DS_Store", b"x")],
    [("only-dir/", b"")],
])
def test_archives_with_nothing_to_scan_are_rejected(env, members):
    env.reject(make_zip(members), "empty-archive")


# --------------------------------------------------------------------------------------- unsafe names

UNSAFE_NAMES = [
    "../x", "a/../../x", "a/..", "..", "/etc/passwd", "//x", "C:/x", "C:\\x", "a\\b", "..\\x", "a/./b", "./a", "a//b",
    "a:b", "a/b:stream", "a\x01b", "a\nb", "a\x7fb", "a\x85b", "a\u202eb.py", "a\u2066b", "a\u200bb", "a\u2028b",
    "x" * 256, "/".join(["d" * 200] * 6) + "/f", "/".join(["d"] * 33) + "/f.txt", "/", "a/",
]


@pytest.mark.parametrize("name", [n for n in UNSAFE_NAMES if n != "a/"], ids=lambda n: repr(n)[:40])
def test_unsafe_names_reject_the_whole_archive(env, name):
    # a harmless, valid member comes first: it must not be left extracted
    env.reject(make_zip([("good.py", b"1"), (name, b"x")]), "unsafe-name")


def test_dir_named_with_dotdot_component_is_rejected(env):
    env.reject(make_zip([("good.py", b"1"), ("a/../", b"")]), "unsafe-name")


def test_nul_byte_in_a_name_is_rejected_not_truncated(env):
    data = rename_raw(make_zip([("good.py", b"1"), ("aXb.py", b"2")]), b"aXb.py", b"a\x00b.py")
    assert zipfile.ZipFile(io.BytesIO(data)).namelist()[1] == "a"   # zipfile silently truncates: why we check
    env.reject(data, "unsafe-name")


def test_invalid_utf8_name_without_flag_is_rejected(env):
    data = rename_raw(make_zip([("good.py", b"1"), ("ab.py", b"2")]), b"ab.py", b"\xff\xfe.py")
    env.reject(data, "unsafe-name")


# ---------------------------------------------------------------------------- member types / encryption

@pytest.mark.parametrize("fmt", [stat.S_IFLNK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK],
                         ids=["symlink", "chardev", "blockdev", "fifo", "socket"])
def test_special_unix_file_types_are_rejected(env, fmt):
    env.reject(make_zip([("good.py", b"1"), ("special", b"/etc/passwd", (fmt | 0o777) << 16)]), "unsafe-member-type")


def test_symlink_pointing_outside_is_rejected_and_never_created(env, tmp_path):
    data = make_zip([("link", b"../../../../etc/passwd", (stat.S_IFLNK | 0o777) << 16), ("link/evil.py", b"x")])
    env.reject(data, "unsafe-member-type")


def test_windows_reparse_point_is_rejected(env):
    env.reject(make_zip([("good.py", b"1"), ("junction", b"x", 0x400)]), "unsafe-member-type")


def test_type_contradicting_name_is_rejected(env):
    env.reject(make_zip([("d/", b"", REG), ("a.py", b"1")]), "unsafe-member-type")          # regular mode on a dir name
    env.reject(make_zip([("f", b"x", (stat.S_IFDIR | 0o755) << 16), ("a.py", b"1")]), "unsafe-member-type")


def test_encrypted_entries_are_rejected(env):
    env.reject(set_flag_bit(make_zip([("a.py", b"1")]), 0x1), "encrypted")
    env.reject(set_flag_bit(make_zip([("a.py", b"1")]), 0x40), "encrypted")


@pytest.mark.parametrize("method", [zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA])
def test_exotic_compression_is_rejected(env, method):
    env.reject(make_zip([("good.py", b"1"), ("a.py", b"x" * 100, REG, method)]), "unsupported-compression")


# ------------------------------------------------------------------------------- duplicates / conflicts

def test_exact_duplicate_names_are_rejected(env):
    env.reject(make_zip([("a.py", b"safe"), ("a.py", b"overwrite")]), "duplicate-path")


def test_duplicate_directory_entries_are_rejected(env):
    env.reject(make_zip([("d/", b""), ("d/", b""), ("d/a.py", b"1")]), "duplicate-path")


def test_case_collisions_are_rejected(env):
    env.reject(make_zip([("App.py", b"1"), ("app.py", b"2")]), "duplicate-path")
    env.reject(make_zip([("Dir/a.py", b"1"), ("dir/a.py", b"2")]), "duplicate-path")


def test_unicode_normalisation_collisions_are_rejected(env):
    nfc, nfd = unicodedata.normalize("NFC", "é.py"), unicodedata.normalize("NFD", "é.py")
    assert nfc != nfd
    env.reject(make_zip([(nfc, b"1"), (nfd, b"2")]), "duplicate-path")


def test_file_and_directory_with_same_name_are_rejected(env):
    env.reject(make_zip([("a", b"file"), ("a/b.py", b"x")]), "path-conflict")
    env.reject(make_zip([("a/b", b"file"), ("a/b/", b"")]), "duplicate-path")       # same path, file and dir
    env.reject(make_zip([("a/b/c.py", b"x"), ("a/b", b"file")]), "path-conflict")


# ----------------------------------------------------------------------------- size / count / bombs

def test_per_file_cap_uses_the_declared_size_before_reading(env):
    env.reject(make_zip([("big.bin", b"\0" * (2 * MiB))]), ("entry-too-large",), ArchiveLimits(max_file_bytes=MiB))


def test_total_cap(env):
    members = [(f"f{i}.bin", os.urandom(MiB), REG, zipfile.ZIP_STORED) for i in range(4)]
    env.reject(make_zip(members), "total-too-large", ArchiveLimits(max_total_bytes=3 * MiB))


def test_compression_ratio_cap_per_entry(env):
    data = make_zip([("zeros.bin", b"\0" * (8 * MiB))])
    assert len(data) < 20_000                                   # a real ~1000:1 bomb
    env.reject(data, "compression-ratio", ArchiveLimits(max_file_bytes=10 * MiB))


def test_per_entry_ratio_cap_alone(env):
    """Diluted with incompressible data so only the per-entry rule (not the overall ratio) can fire."""
    data = make_zip([("noise.bin", os.urandom(2 * MiB), REG, zipfile.ZIP_STORED), ("zeros.bin", b"\0" * (4 * MiB))])
    assert sum(1 for _ in zipfile.ZipFile(io.BytesIO(data)).infolist()) == 2 and len(data) > 2 * MiB
    env.reject(data, "compression-ratio")


def test_declared_size_rules_fire_before_any_byte_is_decompressed(env, monkeypatch):
    def reached(*a, **k): raise AssertionError("extraction started although the declared sizes already violate a limit")
    monkeypatch.setattr(archive, "_extract", reached)
    env.reject(make_zip([("f%d.bin" % i, os.urandom(MiB), REG, zipfile.ZIP_STORED) for i in range(4)]),
               "total-too-large", ArchiveLimits(max_total_bytes=3 * MiB))
    env.reject(make_zip([("big.bin", b"\0" * (2 * MiB))]), "entry-too-large", ArchiveLimits(max_file_bytes=MiB))
    env.reject(make_zip([("zeros.bin", b"\0" * (8 * MiB))]), "compression-ratio")


def test_compression_ratio_cap_overall(env):
    data = make_zip([(f"z{i}.bin", b"\0" * (900 * 1024)) for i in range(8)])    # each below the per-entry threshold
    env.reject(data, "compression-ratio")


def test_default_limits_stop_a_real_100mib_plus_bomb(env):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(12):                                     # 12 x 10 MiB = 120 MiB of zeros, ~120 KiB archive
            with zf.open(f"z{i}.bin", "w") as w:
                for _ in range(10):
                    w.write(b"\0" * MiB)
    assert len(buf.getvalue()) < MiB
    env.reject(buf.getvalue(), ("compression-ratio", "total-too-large", "entry-too-large"))


def test_header_lying_about_a_smaller_size_is_caught_while_extracting(env):
    """The header claims 100 bytes, the stream holds 200 000: no check on declared sizes can see this."""
    data = make_zip([("a.py", b"ok"), ("b.py", b"\0" * 200_000)])
    lh, ch = local_hdrs(data)[1], central_hdrs(data)[1]
    data = put(put(data, lh + 22, "<I", 100), ch + 24, "<I", 100)
    env.reject(data, ("corrupt-entry", "size-mismatch"))      # a.py was already written: it must be gone too


def test_header_lying_about_a_larger_size_is_caught(env):
    data = make_zip([("a.py", b"ok"), ("b.py", b"\0" * 200_000)])
    lh, ch = local_hdrs(data)[1], central_hdrs(data)[1]
    data = put(put(data, lh + 22, "<I", 300_000), ch + 24, "<I", 300_000)
    env.reject(data, ("corrupt-entry", "size-mismatch"))


def test_corrupt_deflate_stream_and_bad_crc_are_rejected(env):
    data = bytearray(make_zip([("a.py", b"hello world " * 100)]))
    data[local_hdrs(bytes(data))[0] + 30 + 4 + 5] ^= 0xFF
    env.reject(bytes(data), "corrupt-entry")
    stored = bytearray(make_zip([("a.py", b"hello world")], zipfile.ZIP_STORED))
    stored[local_hdrs(bytes(stored))[0] + 30 + 4] ^= 0xFF       # flip a data byte: CRC no longer matches
    env.reject(bytes(stored), "corrupt-entry")


def test_copy_limiter_stops_an_endless_reader_even_if_the_library_would_not():
    class Endless:                        # ignores the requested size, like a misbehaving decompressor might
        def read(self, n): return b"A" * 1000

    sink = io.BytesIO()
    with pytest.raises(ArchiveError) as e:
        archive._copy_limited(Endless(), sink, expected=10, remaining_total=10**4, deadline=float("inf"))
    assert e.value.code == "size-mismatch" and sink.getvalue() == b""      # stopped before writing anything
    with pytest.raises(ArchiveError) as e:
        archive._copy_limited(Endless(), io.BytesIO(), expected=10**9, remaining_total=5000, deadline=float("inf"))
    assert e.value.code == "total-too-large"
    with pytest.raises(ArchiveError) as e:
        archive._copy_limited(io.BytesIO(b"abc"), io.BytesIO(), expected=10, remaining_total=100, deadline=float("inf"))
    assert e.value.code == "size-mismatch"


def test_entry_count_cap_with_the_default_limit(env):
    members = [(f"f{i}.txt", b"") for i in range(5001)]
    err = env.reject(make_zip(members, zipfile.ZIP_STORED), "too-many-entries")
    assert "5000" in err.message


def test_entry_count_cap_cannot_be_dodged_by_a_lying_end_record(env):
    data = make_zip([(f"f{i}.txt", b"x") for i in range(11)], zipfile.ZIP_STORED)
    e = eocd(data)
    data = put(put(data, e + 8, "<H", 1), e + 10, "<H", 1)       # end record claims one entry
    env.reject(data, "too-many-entries", ArchiveLimits(max_entries=10))


def test_entry_count_counts_excluded_members_too(env):
    members = [("a.py", b"1")] + [(f"__MACOSX/{i}", b"") for i in range(10)]
    env.reject(make_zip(members), "too-many-entries", ArchiveLimits(max_entries=10))


def test_archive_size_cap_symlink_and_non_files(env, tmp_path):
    data = make_zip([("a.py", b"x" * 5000)], zipfile.ZIP_STORED)
    env.reject(data, "archive-too-large", ArchiveLimits(max_archive_bytes=1000))
    p = env.write(data)
    link = tmp_path / "link.zip"
    link.symlink_to(p)
    with pytest.raises(ArchiveError) as e:
        extract_zip(link)
    assert e.value.code == "unreadable-archive"
    for bad in (tmp_path, tmp_path / "missing.zip"):
        with pytest.raises(ArchiveError) as e:
            extract_zip(bad)
        assert e.value.code == "unreadable-archive"
    assert list(env.wsroot.iterdir()) == []


# ------------------------------------------------------------------------------ container structure

def test_garbage_empty_and_truncated_inputs(env):
    env.reject(os.urandom(4096), "not-a-zip")
    env.reject(b"", "not-a-zip")
    env.reject(b"PK\x03\x04" + b"\0" * 100, "not-a-zip")
    env.reject(make_zip([("a.py", b"x" * 500)])[:-10], "not-a-zip")      # end record cut off


def test_empty_zip_is_rejected(env):
    env.reject(make_zip([]), "empty-archive")


def test_corrupt_central_directory(env):
    data = make_zip([("a.py", b"1"), ("b.py", b"2")])
    c = central_hdrs(data)[0]
    env.reject(data[:c] + b"XXXX" + data[c + 4:], "bad-structure")


def test_junk_before_the_first_entry_is_rejected_although_zipfile_accepts_it(env):
    good = make_zip([("a.py", b"1")])
    polyglot = b"MZ" + b"\x90" * 62 + good                              # e.g. a self-extractor stub
    assert zipfile.ZipFile(io.BytesIO(polyglot)).namelist() == ["a.py"]   # the library alone would take it
    env.reject(polyglot, "bad-structure")


def test_data_after_the_end_record_is_rejected(env):
    env.reject(make_zip([("a.py", b"1")]) + b"trailing garbage", "bad-structure")


def test_oversized_comment_is_rejected(env):
    env.reject(make_zip([("a.py", b"1")], comment=b"c" * 5000), "comment-too-large")
    env.accept(make_zip([("a.py", b"1")], comment=b"c" * 4096)).cleanup()


def test_multi_disk_archives_are_rejected(env):
    data = make_zip([("a.py", b"1")])
    env.reject(put(data, eocd(data) + 4, "<H", 1), "multi-disk")


def test_local_header_name_must_match_the_central_directory(env):
    data = make_zip([("good.py", b"1"), ("evil.py", b"2")], zipfile.ZIP_STORED)
    lh = local_hdrs(data)[1]
    data = data[:lh + 30] + b"EVIL" + data[lh + 34:]                   # local says EVIL.py, central says evil.py
    env.reject(data, "bad-structure")


def test_overlapping_entries_zip_quine_style_are_rejected(env):
    """`inner.py`'s local header + data live inside the data of `outer.bin`; a central-directory record points there."""
    inner = make_zip([("inner.py", b"x = 1\n")], zipfile.ZIP_STORED)
    inner_local = inner[:central_hdrs(inner)[0]]
    inner_cd = inner[central_hdrs(inner)[0]:eocd(inner)]
    outer = make_zip([("outer.bin", b"AAAA" + inner_local + b"BBBB")], zipfile.ZIP_STORED)
    off = outer.find(inner_local)
    cd0 = central_hdrs(outer)[0]
    evil_cd = put(inner_cd, 42, "<I", off)
    body = outer[:cd0] + outer[cd0:eocd(outer)] + evil_cd
    end = bytearray(outer[eocd(outer):])
    end[8:12] = struct.pack("<HH", 2, 2)
    end[12:16] = struct.pack("<I", len(body) - cd0)
    evil = body + bytes(end)
    assert zipfile.ZipFile(io.BytesIO(evil)).namelist() == ["outer.bin", "inner.py"]   # accepted by the library
    env.reject(evil, "bad-structure")


def test_entry_offset_outside_the_archive_is_rejected(env):
    data = make_zip([("a.py", b"1"), ("b.py", b"2")])
    data = put(data, central_hdrs(data)[1] + 42, "<I", 10**7)
    env.reject(data, "bad-structure")


# ------------------------------------------------------------------------ failure handling / cleanup

def test_failure_in_the_middle_removes_everything_already_written(env):
    data = bytearray(make_zip([("a.py", b"first"), ("b.py", os.urandom(2000), REG, zipfile.ZIP_STORED),
                               ("c.py", b"third")]))
    data[local_hdrs(bytes(data))[1] + 30 + 4 + 1000] ^= 0xFF           # one data byte of b.py: CRC mismatch
    env.reject(bytes(data), "corrupt-entry")                           # a.py had already been written


def test_low_disk_space_is_refused_up_front(env, monkeypatch):
    monkeypatch.setattr(archive.shutil, "disk_usage", lambda p: types.SimpleNamespace(free=10))
    env.reject(make_zip([("a.py", b"x" * 100)]), "insufficient-space")


def test_write_error_is_reported_and_cleaned_up(env, monkeypatch):
    def boom(*a, **k): raise OSError(28, "No space left on device")
    monkeypatch.setattr(archive, "_copy_limited", boom)
    env.reject(make_zip([("a.py", b"1")]), "insufficient-space")


def test_extraction_deadline(env):
    env.reject(make_zip([("a.py", b"x" * 100_000)]), "timeout", ArchiveLimits(max_seconds=0))


def test_unexpected_exception_still_cleans_up(env, monkeypatch):
    def boom(*a, **k): raise KeyboardInterrupt
    monkeypatch.setattr(archive, "_extract", boom)
    p = env.write(make_zip([("a.py", b"1")]))
    with pytest.raises(KeyboardInterrupt):
        extract_zip(p)
    assert list(env.wsroot.iterdir()) == []


def test_error_messages_never_echo_member_names(env):
    secret = "SENSITIVE-NAME-\x1b[31m"
    e = env.reject(make_zip([("ok.py", b"1"), (f"../{secret}", b"x")]), "unsafe-name")
    assert "SENSITIVE" not in str(e) and "\x1b" not in str(e)


def test_directory_walk_refuses_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(OSError):
            archive._ensure_dir_fd(fd, ("link", "sub"))
    finally:
        os.close(fd)
    assert list(outside.iterdir()) == []


def test_extractions_do_not_interfere(env):
    a = extract_zip(env.write(make_zip([("a.py", b"A")])))
    b = extract_zip(env.write(make_zip([("a.py", b"B")])))
    try:
        assert a.workdir != b.workdir and (a.project / "a.py").read_bytes() == b"A" and (b.project / "a.py").read_bytes() == b"B"
    finally:
        a.cleanup()
        b.cleanup()


def test_module_has_no_web_framework_or_engine_dependency():
    code = ("import sys, saferun.api.archive; "
            "bad = [m for m in ('fastapi', 'starlette', 'uvicorn', 'saferun.engine', 'saferun.sandbox') if m in sys.modules]; "
            "sys.exit(1 if bad else 0)")
    assert subprocess.run([sys.executable, "-I", "-c", code]).returncode == 0


# ------------------------------------------------------------- review regression: central-directory memory bound

def test_central_directory_is_walked_and_counted_before_zipfile_builds_objects(env, monkeypatch):
    """A lying end record (claims 1 entry) in front of a 20 000-record central directory must be refused BEFORE
    zipfile instantiates a ZipInfo per record (a 25 MiB archive can carry ~500 000 of them = hundreds of MiB)."""
    data = make_zip([(f"f{i}.txt", b"") for i in range(20_000)], zipfile.ZIP_STORED)
    e = eocd(data)
    data = put(put(data, e + 8, "<H", 1), e + 10, "<H", 1)

    def boom(*a, **k):
        raise AssertionError("zipfile.ZipFile was constructed for an over-limit central directory")
    monkeypatch.setattr(archive.zipfile, "ZipFile", boom)
    env.reject(data, "too-many-entries")


def test_central_directory_that_does_not_end_at_the_end_record_is_rejected(env):
    data = make_zip([("a.py", b"1"), ("b.py", b"2")], zipfile.ZIP_STORED)
    e = eocd(data)
    env.reject(put(data, e + 12, "<I", struct.unpack_from("<I", data, e + 12)[0] + 7), "bad-structure")   # cd_size too big
    env.reject(put(data, e + 12, "<I", 5), "bad-structure")                                               # cd_size too small
    env.reject(put(data, e + 12, "<I", len(data) + 1000), "bad-structure")                                # beyond the file


def test_zip64_end_record_markers_are_refused_not_followed(env):
    data = make_zip([("a.py", b"1")], zipfile.ZIP_STORED)
    e = eocd(data)
    env.reject(put(data, e + 12, "<I", 0xFFFFFFFF), "bad-structure")
    env.reject(put(put(data, e + 8, "<H", 0xFFFF), e + 10, "<H", 0xFFFF), "bad-structure")
