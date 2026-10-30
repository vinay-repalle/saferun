"""Race-safe, limit-enforcing, exposure-aware copy of an untrusted directory tree.

Two passes over the tree, both relative to already-open directory fds with O_NOFOLLOW:

1. Pre-scan (stat only for files): records a *signature* (type/mode, dev, ino, size, mtime_ns,
   ctime_ns) for every visited entry and the name set of every directory it lists.
2. Copy: every entry's lstat, and the object actually opened, must match its recorded
   signature before anything is read; every directory listing must equal the recorded name set;
   after reading, the file must be unchanged.
3. Final validation: the whole tree is walked once more and every directory (identity,
   metadata, listing) and every entry must still match the pre-scan records, so changes made
   after an entry was copied, or after its directory was listed, are caught too.
Any replaced, added, removed or modified entry found by any step aborts the whole copy with
WorkspaceChangedError (nothing is kept); the caller can simply retry.

This is *detection on a live filesystem, not an atomic snapshot*: a change made after the final
validation cannot affect the already-copied files (each was verified when read), but without
filesystem snapshot support SafeRun cannot make the tree stand still while it is read, and a
modification that leaves every recorded field identical (e.g. within one coarse timestamp tick on
kernels without fine-grained timestamps) is not detectable.

ctime cannot be set from user space and changes on rename, chmod, link/unlink and content
writes, so a restored mtime or a reused inode number does not hide a replacement.

Exposure rules (see SensitivePolicy / secrets.py):
- not world-readable in the source  -> withheld, never opened or read
- credential signature in content   -> withheld (written copy deleted)
- hard link whose inode has a name outside the scanned tree -> skipped
"""
from __future__ import annotations

import errno
import os
import stat
from collections import Counter
from dataclasses import dataclass

from .config import (
    SensitivePolicy, SkippedEntry, WithheldEntry, WorkspaceChangedError, WorkspaceLimitError,
    WorkspaceLimits,
)
from .secrets import LEARN_MAX, Redactor, SignatureScanner

_RD = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
CHUNK = 1024 * 1024
_GONE = (errno.ELOOP, errno.ENOTDIR, errno.ENOENT)  # opening failed because the entry was replaced/removed
_SIZE = 3  # index of st_size inside a signature


def _sig(st: os.stat_result) -> tuple:
    return (st.st_mode, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _changed(path: str, what: str) -> WorkspaceChangedError:
    return WorkspaceChangedError(
        f"{path or '.'}: {what} while SafeRun was copying; the copy was abandoned (retry on a quiescent tree)")


@dataclass
class CopyResult:
    skipped: list[SkippedEntry]
    withheld: list[WithheldEntry]
    entries_scanned: int  # every directory entry visited; == copied_files + copied_dirs + len(skipped) + len(withheld)
    copied_files: int     # regular files written and kept
    copied_dirs: int
    copied_bytes: int     # bytes of the kept files only (discarded/withheld content is not counted)
    redactor: Redactor


class _Budget:
    def __init__(self, lim: WorkspaceLimits):
        self.lim, self.files, self.bytes = lim, 0, 0

    def entry(self) -> None:
        self.files += 1
        if self.files > self.lim.max_files:
            raise WorkspaceLimitError(f"project has more than {self.lim.max_files} entries")

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.lim.max_bytes:
            raise WorkspaceLimitError(f"project is larger than {self.lim.max_bytes} bytes")

    def depth(self, d: int) -> None:
        if d > self.lim.max_depth:
            raise WorkspaceLimitError(f"project is nested deeper than {self.lim.max_depth} directories")


class _Sink:
    """Writes the copy under `dest` (a directory we own and created; mode 0700 until the copy is done)."""

    def __init__(self, dest: str):
        self.dest = dest

    def mkdir(self, rel: str) -> None:
        p = os.path.join(self.dest, rel)
        os.mkdir(p, 0o755)
        os.chmod(p, 0o755)

    def write(self, rel: str, src_fd: int, want: tuple, budget: _Budget, redactor: Redactor,
              withhold_on_match: bool) -> tuple[str | None, int]:
        """Copy one file. Returns (signature kind, bytes kept); kind is set iff the copy was removed."""
        dest, scanner, kind = os.path.join(self.dest, rel), SignatureScanner(), None
        head: bytearray | None = bytearray()
        written = read = 0
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        try:
            os.fchmod(fd, 0o644)  # executable bits intentionally dropped
            while chunk := os.read(src_fd, CHUNK):
                read += len(chunk)
                budget.add_bytes(len(chunk))  # real bytes: files may grow after the pre-scan
                kind = kind or scanner.feed(chunk)
                if kind and withhold_on_match:
                    break
                if head is not None:
                    head += chunk
                    head = head if len(head) <= LEARN_MAX else None
                view = memoryview(chunk)
                while view:
                    n = os.write(fd, view)
                    written += n
                    view = view[n:]
        finally:
            os.close(fd)
        if kind and withhold_on_match:
            os.unlink(dest)
            return kind, 0
        # Fully read: the file must be the very object and state the pre-scan recorded.
        if read != want[_SIZE] or _sig(os.fstat(src_fd)) != want:
            raise _changed(rel, "file was modified while being read")
        if head is not None:
            redactor.learn(bytes(head))
        return None, written


class _Walker:
    """One traversal. sink=None is the pre-scan: stat only for files, nothing is read or written.

    Pre-scan fills `records` / `listings`; the copy pass is given them as `expected*` and verifies.
    """

    def __init__(self, lim: WorkspaceLimits, policy: SensitivePolicy, sink: _Sink | None,
                 seen_links: Counter | None = None, expected: dict | None = None,
                 expected_listings: dict | None = None):
        self.budget, self.policy, self.sink = _Budget(lim), policy, sink
        self.skipped: list[SkippedEntry] = []
        self.withheld: list[WithheldEntry] = []
        self.redactor = Redactor()
        self.copied_files = self.copied_dirs = self.copied_bytes = 0
        self.links: Counter = Counter()          # pre-scan: names seen per multi-link inode
        self.seen_links = seen_links or Counter()  # copy pass: result of the pre-scan
        self.records: dict[str, tuple] = {}      # pre-scan: path -> signature
        self.listings: dict[str, frozenset] = {}  # pre-scan: dir path -> names
        self.expected, self.expected_listings = expected, expected_listings

    def _private(self, path: str, mode: int, other_bits: int) -> bool:
        if (self.policy.honor_private_modes and path not in self.policy.allow_paths
                and not mode & other_bits):
            self.withheld.append(WithheldEntry(path, "private-mode"))
            return True
        return False

    def _verify(self, path: str, want: tuple) -> None:
        """Pre-scan: record. Copy pass: the entry must be exactly what was recorded."""
        if self.expected is None:
            self.records[path] = want
        elif self.expected.get(path) != want:
            raise _changed(path, "entry was replaced, added or modified")

    def _list(self, dir_fd: int, rel: str) -> list[str]:
        """List a directory, counting entries against the budget *as they are read*, so a huge
        directory is rejected without being read in full. The copy pass must see the recorded names."""
        exp = None
        if self.expected_listings is not None:
            exp = self.expected_listings.get(rel)
            if exp is None:
                raise _changed(rel, "directory was not part of the pre-scan")
        names: list[str] = []
        with os.scandir(dir_fd) as it:
            for e in it:
                self.budget.entry()
                if exp is not None and e.name not in exp:
                    raise _changed(f"{rel}/{e.name}" if rel else e.name, "entry was added")
                names.append(e.name)
        if exp is not None:
            if len(names) != len(exp):
                raise _changed(rel, "an entry was removed")
        else:
            self.listings[rel] = frozenset(names)
        return sorted(names)

    def walk(self, dir_fd: int, rel: str, depth: int) -> None:
        for name in self._list(dir_fd, rel):
            path = f"{rel}/{name}" if rel else name
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                raise _changed(path, "entry was removed") from None
            except OSError:
                self.skipped.append(SkippedEntry(path, "unreadable"))
                continue
            want = _sig(st)
            self._verify(path, want)
            if stat.S_ISLNK(st.st_mode):
                self.skipped.append(SkippedEntry(path, "symlink"))
            elif stat.S_ISDIR(st.st_mode):
                self._dir(dir_fd, name, path, st, want, depth)
            elif stat.S_ISREG(st.st_mode):
                self._file(dir_fd, name, path, st, want)
            else:
                self.skipped.append(SkippedEntry(path, "not-regular-file"))

    def _open(self, name, dir_fd, extra, path, want):
        """Open without following symlinks; the opened object must match `want`. -> (fd, fstat) | None"""
        try:
            fd = os.open(name, _RD | extra, dir_fd=dir_fd)
        except OSError as e:
            if e.errno in _GONE:
                raise _changed(path, "entry was replaced or removed") from None
            self.skipped.append(SkippedEntry(path, "unreadable"))
            return None
        fst = os.fstat(fd)
        if _sig(fst) != want:
            os.close(fd)
            raise _changed(path, "entry was replaced or modified")
        return fd, fst

    def _dir(self, dir_fd, name, path, st, want, depth):
        self.budget.depth(depth + 1)
        if self._private(path, st.st_mode, 0o005):
            return
        opened = self._open(name, dir_fd, os.O_DIRECTORY, path, want)
        if opened is None:
            return
        fd, _ = opened
        try:
            if self.sink:
                self.sink.mkdir(path)
                self.copied_dirs += 1
            self.walk(fd, path, depth + 1)
        finally:
            os.close(fd)

    def _file(self, dir_fd, name, path, st, want):
        if self.sink is None:  # pre-scan
            if st.st_nlink > 1:
                self.links[(st.st_dev, st.st_ino)] += 1
            if not self._private(path, st.st_mode, 0o004):
                self.budget.add_bytes(st.st_size)
            return
        if self._private(path, st.st_mode, 0o004):  # never opened, never read
            return
        opened = self._open(name, dir_fd, os.O_NONBLOCK | os.O_NOCTTY, path, want)
        if opened is None:
            return
        fd, fst = opened
        try:
            # Hard link: only safe if EVERY name of this inode was seen inside the tree.
            if fst.st_nlink > 1 and self.seen_links[(fst.st_dev, fst.st_ino)] != fst.st_nlink:
                self.skipped.append(SkippedEntry(path, "hardlink-external"))
                return
            kind, kept = self.sink.write(path, fd, want, self.budget, self.redactor,
                                         withhold_on_match=path not in self.policy.allow_paths)
            if kind:
                self.withheld.append(WithheldEntry(path, kind))
            else:
                self.copied_files += 1
                self.copied_bytes += kept
        finally:
            os.close(fd)


def _validate_tree(dir_fd: int, rel: str, records: dict, listings: dict, budget: _Budget) -> None:
    """Final pass: `dir_fd` and everything below it must still be exactly what the pre-scan recorded.

    Recurses only into directories the pre-scan descended into (those with a recorded listing);
    other entries (symlinks, withheld or unreadable directories, special files) are checked by lstat.
    """
    expected = listings[rel]
    names: list[str] = []
    with os.scandir(dir_fd) as it:
        for e in it:
            budget.entry()
            if e.name not in expected:
                raise _changed(f"{rel}/{e.name}" if rel else e.name, "entry was added (final check)")
            names.append(e.name)
    if len(names) != len(expected):
        raise _changed(rel, "an entry was removed (final check)")
    for name in sorted(names):
        path = f"{rel}/{name}" if rel else name
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise _changed(path, "entry was removed (final check)") from None
        except OSError:
            if path in records:
                raise _changed(path, "entry became unreadable (final check)") from None
            continue  # was already unreadable at pre-scan time
        if records.get(path) != _sig(st):
            raise _changed(path, "entry was replaced or modified (final check)")
        if stat.S_ISDIR(st.st_mode) and path in listings:
            try:
                fd = os.open(name, _RD | os.O_DIRECTORY, dir_fd=dir_fd)
            except OSError:
                raise _changed(path, "directory was replaced or removed (final check)") from None
            try:
                if _sig(os.fstat(fd)) != records[path]:
                    raise _changed(path, "directory was replaced or modified (final check)")
                _validate_tree(fd, path, records, listings, budget)
            finally:
                os.close(fd)


def copy_tree(src: str, dest: str, lim: WorkspaceLimits,
              policy: SensitivePolicy | None = None) -> CopyResult:
    """Pre-scan (stat only), verified copy, then a final validation pass.

    Raises WorkspaceLimitError before anything is copied if the pre-scan already exceeds a
    limit (limits are enforced again during the copy) and WorkspaceChangedError if the tree
    is found modified between the passes, during a read, or by the final validation.
    """
    policy = policy or SensitivePolicy()
    root_fd = os.open(src, _RD | os.O_DIRECTORY)
    try:
        pre = _Walker(lim, policy, None)
        pre.records[""] = _sig(os.fstat(root_fd))
        pre.walk(root_fd, "", 0)
        w = _Walker(lim, policy, _Sink(dest), pre.links, pre.records, pre.listings)
        if _sig(os.fstat(root_fd)) != pre.records[""]:
            raise _changed("", "the project root was modified")
        w.walk(root_fd, "", 0)
        if _sig(os.fstat(root_fd)) != pre.records[""]:
            raise _changed("", "the project root was modified (final check)")
        _validate_tree(root_fd, "", pre.records, pre.listings, _Budget(lim))
        return CopyResult(w.skipped, w.withheld, w.budget.files, w.copied_files, w.copied_dirs,
                          w.copied_bytes, w.redactor)
    finally:
        os.close(root_fd)
