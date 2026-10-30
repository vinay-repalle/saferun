"""Safe extraction of an untrusted ZIP archive into a private directory (Phase 4, step 1).

The archive is hostile. The rule is: validate the WHOLE archive before writing a single byte, reject the
whole archive on any unsafe or invalid member (no skip-and-continue), and extract with our own code - never
`ZipFile.extractall`/`extract`.

Rejected (each with a stable `ArchiveError.code`, never echoing raw member names):
  * archive: unreadable / not a regular file / over the size cap / no end record / data after the end record /
    junk before the first entry / multi-disk / oversized comment / central-directory problems / no entries
  * entries: more than `max_entries`; encrypted; compression other than STORED/DEFLATE; any member that is not a
    regular file or directory (symlink, device, fifo, socket, Windows reparse point); a local header that does
    not match the central directory; overlapping entries (zip quines, overlapping bombs)
  * names: absolute, `..`/`.`/empty components, backslash, colon (drive letters, streams), NUL, control,
    bidi/format and line-separator characters, names that are not valid UTF-8, over-long components/paths,
    too deep
  * collisions: duplicate paths, paths equal after Unicode (NFKC) normalisation + case folding, a name used both
    as a file and as a directory
  * size: per-file / total byte caps and a compression-ratio cap on the *declared* sizes, and the same caps
    again on the bytes *actually produced* while decompressing (headers can lie); declared != actual is rejected.

Only `__MACOSX/` (top level) and `.DS_Store` files are excluded from extraction; they are still fully validated
and are listed in `ExtractResult.excluded`. A single top-level wrapper directory is stripped only when every
extracted entry lives under it (no top-level files, exactly one top-level directory).

Output: a fresh 0700 directory `saferun-up-*` holding `project/`. Files are written 0644 and directories 0755
whatever the archive says (setuid/exec bits are ignored). 0644 matters: the Phase 1 copier withholds files that
are not world-readable, so 0600 files would silently vanish from the scan. The 0700 parent keeps other host
users out. Nothing in the archive is executed or imported. The caller must call `ExtractResult.cleanup()`.
Failure at any point removes the directory before the error propagates.
"""
from __future__ import annotations

import errno
import os
import shutil
import stat
import struct
import tempfile
import time
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

MiB = 1024 * 1024
WORKDIR_PREFIX = "saferun-up-"
UPLOAD_PREFIX = "saferun-upl-"   # temp files holding a raw upload (created by the API layer, swept at startup)
PROJECT_DIRNAME = "project"
EXCLUDED_DIRNAME = "__MACOSX"
EXCLUDED_FILENAME = ".DS_Store"
MAX_LISTED_EXCLUSIONS = 50
_CHUNK = 64 * 1024
_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})   # control, format (bidi, ZWJ...), surrogate, separators
_ALLOWED_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)


class ArchiveError(Exception):
    """The archive was rejected. `code` is stable and machine-readable; `message` never contains member names."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ArchiveLimits:
    max_archive_bytes: int = 100 * MiB
    max_total_bytes: int = 400 * MiB      # uncompressed, all extracted files
    max_entries: int = 5000               # every central-directory entry, excluded ones included
    max_file_bytes: int = 25 * MiB        # uncompressed, per file
    max_ratio: int = 100                  # uncompressed : compressed
    ratio_min_bytes: int = MiB            # the ratio rule only applies above this uncompressed size
    max_depth: int = 32                   # directory levels
    max_path_bytes: int = 1024
    max_component_bytes: int = 255
    max_comment_bytes: int = 4096
    max_seconds: float = 60.0             # extraction wall clock

    def __post_init__(self):
        for k, v in vars(self).items():
            ok = (isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and v < float("inf")
                  and (v >= 0 if k == "max_seconds" else v > 0))
            if not ok:
                raise ValueError(f"ArchiveLimits.{k} must be a positive finite number, got {v!r}")


@dataclass
class ExtractResult:
    workdir: Path                   # private 0700 directory; the caller deletes it with cleanup()
    project: Path                   # what to hand to the validation engine (inside workdir)
    archive_entries: int            # entries in the central directory
    files: int                      # regular files written
    dirs: int                       # directories created
    bytes: int                      # uncompressed bytes written
    stripped_prefix: str | None     # the wrapper directory that was removed, if any
    excluded: tuple[str, ...]       # validated paths not extracted (capped list)
    excluded_total: int             # how many were excluded (may exceed len(excluded))

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir)


@dataclass
class _Member:
    info: zipfile.ZipInfo
    parts: tuple[str, ...]
    is_dir: bool
    excluded: bool


# --------------------------------------------------------------------------------------- archive level

def _open_archive(archive, limits: ArchiveLimits):
    try:
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, TypeError, ValueError):
        raise ArchiveError("unreadable-archive", "the archive file cannot be opened") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ArchiveError("unreadable-archive", "the archive is not a regular file")
        if st.st_size > limits.max_archive_bytes:
            raise ArchiveError("archive-too-large", f"the archive exceeds {limits.max_archive_bytes} bytes")
        if st.st_size < 22:
            raise ArchiveError("not-a-zip", "the file is too short to be a ZIP archive")
        return os.fdopen(fd, "rb"), st.st_size
    except BaseException:
        os.close(fd)   # fdopen did not take ownership if we get here
        raise


def _read_end_record(f, size: int, limits: ArchiveLimits) -> tuple[int, int, int]:
    """Parse the end-of-central-directory record ourselves. Returns (claimed entry count, central directory size,
    offset of the end record). ZIP64 markers are refused: nothing within our limits (100 MiB archive, 5 000 entries,
    25 MiB files) needs ZIP64, and following its indirection would let the archive hide the real directory size."""
    n = min(size, 22 + 65535)
    f.seek(size - n)
    tail = f.read(n)
    i = tail.rfind(b"PK\x05\x06")
    if i < 0 or len(tail) - i < 22:
        raise ArchiveError("not-a-zip", "no ZIP end record found")
    _sig, disk, cd_disk, n_disk, n_total, cd_size, cd_off, clen = struct.unpack("<4sHHHHIIH", tail[i:i + 22])
    if len(tail) - i - 22 != clen:
        raise ArchiveError("bad-structure", "data after the ZIP end record or inconsistent comment length")
    if clen > limits.max_comment_bytes:
        raise ArchiveError("comment-too-large", "the archive comment is too large")
    if disk not in (0, 0xFFFF) or cd_disk not in (0, 0xFFFF) or (0xFFFF not in (n_disk, n_total) and n_disk != n_total):
        raise ArchiveError("multi-disk", "multi-disk archives are not supported")
    if n_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
        raise ArchiveError("bad-structure", "ZIP64 archives are not supported")
    if n_total > limits.max_entries:
        raise ArchiveError("too-many-entries", f"more than {limits.max_entries} entries")
    return n_total, cd_size, size - n + i


def _walk_central_directory(f, cd_size: int, end_pos: int, limits: ArchiveLimits) -> int:
    """Count the central-directory records by walking them ourselves, BEFORE zipfile builds an object per record.
    The count in the end record is attacker-controlled; the directory's byte size must fit the file and the records
    must tile it exactly. Returns the real number of records."""
    start = end_pos - cd_size
    if cd_size < 0 or start < 0:
        raise ArchiveError("bad-structure", "the central directory does not fit in the archive")
    f.seek(start)
    cd = f.read(cd_size)
    pos = count = 0
    while pos < len(cd):
        if cd[pos:pos + 4] != b"PK\x01\x02" or pos + 46 > len(cd):
            raise ArchiveError("bad-structure", "the central directory is malformed")
        count += 1
        if count > limits.max_entries:
            raise ArchiveError("too-many-entries", f"more than {limits.max_entries} entries")
        n, m, k = struct.unpack_from("<HHH", cd, pos + 28)
        pos += 46 + n + m + k
    if pos != len(cd):
        raise ArchiveError("bad-structure", "the central directory is malformed")
    return count


# ------------------------------------------------------------------------------------------ member level

def _decode_name(zi: zipfile.ZipInfo) -> str:
    name = zi.orig_filename   # zipfile truncates `.filename` at a NUL byte; the original keeps it
    if "\0" in name:
        raise ArchiveError("unsafe-name", "a member name contains a NUL byte")
    if not (zi.flag_bits & 0x800) and not name.isascii():
        # no UTF-8 flag: zipfile decoded the bytes as cp437. Accept only if the raw bytes are valid UTF-8.
        try:
            name = name.encode("cp437").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            raise ArchiveError("unsafe-name", "a member name is not valid UTF-8") from None
    return name


def _split_name(name: str, limits: ArchiveLimits) -> tuple[tuple[str, ...], bool]:
    is_dir = name.endswith("/")
    body = name[:-1] if is_dir else name
    bad = lambda why: ArchiveError("unsafe-name", f"a member name is unsafe ({why})")  # noqa: E731
    if not body or body.startswith("/"):
        raise bad("empty or absolute")
    if "\\" in body or ":" in body:
        raise bad("backslash or colon")
    parts = tuple(body.split("/"))
    for p in parts:
        if p in ("", ".", ".."):
            raise bad("empty, '.' or '..' component")
        if any(unicodedata.category(ch) in _BAD_CATEGORIES for ch in p):
            raise bad("control, format or separator character")
        if len(p.encode("utf-8")) > limits.max_component_bytes:
            raise bad("component too long")
    if len(body.encode("utf-8")) > limits.max_path_bytes:
        raise bad("path too long")
    if (len(parts) if is_dir else len(parts) - 1) > limits.max_depth:
        raise bad("too deep")
    return parts, is_dir


def _check_type(zi: zipfile.ZipInfo, is_dir: bool) -> None:
    if zi.flag_bits & (0x1 | 0x40):
        raise ArchiveError("encrypted", "encrypted entries are not supported")
    if zi.compress_type not in _ALLOWED_METHODS:
        raise ArchiveError("unsupported-compression", "only STORED and DEFLATE entries are supported")
    fmt = stat.S_IFMT(zi.external_attr >> 16)
    if fmt not in (0, stat.S_IFREG, stat.S_IFDIR) or zi.external_attr & 0x400:
        raise ArchiveError("unsafe-member-type", "a member is a symlink, device, fifo, socket or reparse point")
    if (fmt == stat.S_IFREG and is_dir) or (fmt == stat.S_IFDIR and not is_dir) or (is_dir and zi.file_size):
        raise ArchiveError("unsafe-member-type", "a member's type contradicts its name or size")


def _norm_key(parts: tuple[str, ...]) -> str:
    n = lambda s: unicodedata.normalize("NFKC", s)  # noqa: E731
    return "/".join(n(n(p).casefold()) for p in parts)


def _check_structure(f, zf: zipfile.ZipFile, members: list[_Member], size: int) -> None:
    """Local headers must match the central directory and entries must not overlap."""
    prev_end = 0
    ordered = sorted(members, key=lambda m: m.info.header_offset)
    if ordered[0].info.header_offset != 0:
        raise ArchiveError("bad-structure", "data before the first entry")
    for m in ordered:
        zi = m.info
        if not 0 <= zi.header_offset < size:
            raise ArchiveError("bad-structure", "an entry offset is outside the archive")
        f.seek(zi.header_offset)
        h = f.read(30)
        if len(h) < 30 or h[:4] != b"PK\x03\x04":
            raise ArchiveError("bad-structure", "an entry has no valid local header")
        fnlen, exlen = struct.unpack("<HH", h[26:30])
        raw = zi.orig_filename.encode("utf-8" if zi.flag_bits & 0x800 else "cp437")
        if f.read(fnlen) != raw:
            raise ArchiveError("bad-structure", "a local header does not match the central directory")
        if zi.header_offset < prev_end:
            raise ArchiveError("bad-structure", "entries overlap")
        prev_end = zi.header_offset + 30 + fnlen + exlen + zi.compress_size
    if prev_end > zf.start_dir:
        raise ArchiveError("bad-structure", "entry data overlaps the central directory")


def _plan(zf: zipfile.ZipFile, f, size: int, limits: ArchiveLimits) -> tuple[list[_Member], int, str | None]:
    """Validate everything; write nothing. Returns (members, declared extractable bytes, wrapper to strip)."""
    infos = zf.infolist()
    if len(infos) > limits.max_entries:
        raise ArchiveError("too-many-entries", f"more than {limits.max_entries} entries")
    if not infos:
        raise ArchiveError("empty-archive", "the archive has no entries")
    members: list[_Member] = []
    for zi in infos:
        parts, is_dir = _split_name(_decode_name(zi), limits)
        _check_type(zi, is_dir)
        excluded = parts[0] == EXCLUDED_DIRNAME or (not is_dir and parts[-1] == EXCLUDED_FILENAME)
        members.append(_Member(zi, parts, is_dir, excluded))
    _check_structure(f, zf, members, size)

    seen: set[str] = set()
    file_keys: set[str] = set()
    dir_keys: set[str] = set()
    for m in members:
        key = _norm_key(m.parts)
        if key in seen:
            raise ArchiveError("duplicate-path", "two members have the same path (after case/Unicode folding)")
        seen.add(key)
        (dir_keys if m.is_dir else file_keys).add(key)
        for i in range(1, len(m.parts)):
            dir_keys.add(_norm_key(m.parts[:i]))
    if file_keys & dir_keys:
        raise ArchiveError("path-conflict", "a path is used both as a file and as a directory")

    total = 0
    for m in members:
        if m.excluded or m.is_dir:
            continue
        zi = m.info
        if zi.file_size > limits.max_file_bytes:
            raise ArchiveError("entry-too-large", f"a file exceeds {limits.max_file_bytes} bytes")
        if zi.file_size > limits.ratio_min_bytes and zi.file_size > limits.max_ratio * max(zi.compress_size, 1):
            raise ArchiveError("compression-ratio", "a file has a suspicious compression ratio")
        total += zi.file_size
    if total > limits.max_total_bytes:
        raise ArchiveError("total-too-large", f"the extracted size exceeds {limits.max_total_bytes} bytes")
    if total > limits.ratio_min_bytes and total > limits.max_ratio * size:
        raise ArchiveError("compression-ratio", "the archive has a suspicious overall compression ratio")

    keep = [m for m in members if not m.excluded]
    if not any(not m.is_dir for m in keep):
        raise ArchiveError("empty-archive", "the archive contains no extractable files")
    tops = {m.parts[0] for m in keep}
    strip = next(iter(tops)) if len(tops) == 1 and all(m.is_dir or len(m.parts) > 1 for m in keep) else None
    return members, total, strip


# ----------------------------------------------------------------------------------------------- writing

def _open_dir(parent_fd: int, name: str) -> int:
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)


def _ensure_dir_fd(root_fd: int, parts: tuple[str, ...]) -> int:
    """Walk/create `parts` below `root_fd` fd-relatively, refusing symlinks. Returns an fd the caller closes."""
    fd = os.dup(root_fd)
    try:
        for p in parts:
            try:
                os.mkdir(p, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            nfd = _open_dir(fd, p)   # fails on a symlink or a non-directory
            os.close(fd)
            fd = nfd
            os.fchmod(fd, 0o755)     # independent of the process umask
        return fd
    except BaseException:
        os.close(fd)
        raise


def _copy_limited(src, out, expected: int, remaining_total: int, deadline: float) -> int:
    """Copy exactly `expected` bytes. Never trusts the reader to stop: aborts as soon as a count is exceeded."""
    n = 0
    while True:
        chunk = src.read(min(_CHUNK, expected - n + 1))
        if not chunk:
            break
        n += len(chunk)
        if n > expected:
            raise ArchiveError("size-mismatch", "an entry is larger than its header declares")
        if n > remaining_total:
            raise ArchiveError("total-too-large", "the extracted size exceeds the limit")
        if time.monotonic() > deadline:
            raise ArchiveError("timeout", "extraction took too long")
        out.write(chunk)
    if n != expected:
        raise ArchiveError("size-mismatch", "an entry is smaller than its header declares")
    return n


def _extract(zf: zipfile.ZipFile, members: list[_Member], root: Path, limits: ArchiveLimits
             ) -> tuple[int, int, int]:
    deadline = time.monotonic() + limits.max_seconds
    written = files = 0
    dirs: set[tuple[str, ...]] = set()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for m in sorted((m for m in members if not m.excluded), key=lambda m: m.parts):
            dirs.update(m.parts[:i] for i in range(1, len(m.parts) + (1 if m.is_dir else 0)))
            if m.is_dir:
                os.close(_ensure_dir_fd(root_fd, m.parts))
                continue
            pfd = _ensure_dir_fd(root_fd, m.parts[:-1])
            try:
                fd = os.open(m.parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o644, dir_fd=pfd)
            finally:
                os.close(pfd)
            with os.fdopen(fd, "wb") as out:
                os.fchmod(out.fileno(), 0o644)
                with zf.open(m.info) as src:
                    written += _copy_limited(src, out, m.info.file_size, limits.max_total_bytes - written, deadline)
            files += 1
    finally:
        os.close(root_fd)
    return files, len(dirs), written


def extract_zip(archive, limits: ArchiveLimits | None = None) -> ExtractResult:
    """Validate and extract `archive` (a path to a ZIP file). Raises ArchiveError; leaves nothing behind on error."""
    limits = limits or ArchiveLimits()
    f, size = _open_archive(archive, limits)
    with f:
        n_claimed, cd_size, end_pos = _read_end_record(f, size, limits)
        if n_claimed != _walk_central_directory(f, cd_size, end_pos, limits):
            raise ArchiveError("bad-structure", "the entry count in the end record is wrong")
        try:
            zf = zipfile.ZipFile(f, "r")
        except (zipfile.BadZipFile, UnicodeDecodeError, ValueError, OSError, EOFError, struct.error, OverflowError):
            raise ArchiveError("bad-structure", "the ZIP central directory is invalid") from None
        with zf:
            try:
                members, total, strip = _plan(zf, f, size, limits)
            except ArchiveError:
                raise
            except (zipfile.BadZipFile, UnicodeDecodeError, ValueError, OSError, EOFError, struct.error, OverflowError):
                raise ArchiveError("bad-structure", "the ZIP structure is invalid") from None
            if shutil.disk_usage(tempfile.gettempdir()).free < 2 * total:   # extraction + the engine's own copy
                raise ArchiveError("insufficient-space", "not enough free disk space")
            workdir = Path(tempfile.mkdtemp(prefix=WORKDIR_PREFIX))
            try:
                root = workdir / PROJECT_DIRNAME
                root.mkdir(mode=0o755)
                os.chmod(root, 0o755)
                try:
                    files, dirs, written = _extract(zf, members, root, limits)
                except ArchiveError:
                    raise
                except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError):
                    raise ArchiveError("corrupt-entry", "an entry is corrupt (bad data or checksum)") from None
                except OSError as e:
                    code = "insufficient-space" if e.errno in (errno.ENOSPC, errno.EDQUOT) else "extraction-failed"
                    raise ArchiveError(code, "an entry could not be written") from None
            except BaseException:
                shutil.rmtree(workdir, ignore_errors=True)
                raise
            excluded = sorted("/".join(m.parts) + ("/" if m.is_dir else "") for m in members if m.excluded)
            return ExtractResult(
                workdir=workdir, project=root / strip if strip else root, archive_entries=len(members),
                files=files, dirs=dirs, bytes=written, stripped_prefix=strip,
                excluded=tuple(excluded[:MAX_LISTED_EXCLUSIONS]), excluded_total=len(excluded))
