"""Windows copy engine: the same algorithm and guarantees-by-detection as copy.py, on Win32 handles (see hostos/winfs.py).

Three passes over the tree (pre-scan, verified copy, final validation) compare a signature per entry (type, attributes, 128-bit file id,
size, LastWrite and Change time, link count) and the name set of every directory; any replaced, added, removed or modified entry abandons
the whole copy (WorkspaceChangedError). On top of that, Windows lets us hold directories and files open with a share mode that forbids
rename / delete / write, which prevents what the POSIX engine can only detect (see winfs.py for exactly what is and is not prevented).

Not copied, and reported as skipped: symlinks and every other reparse point (junctions, mount points, cloud placeholders) and entries
with an alternate data stream other than Zone.Identifier. Withheld: files whose access list is narrower than the project root's
(or cannot be read), and files with a credential signature. Hard links with names outside the tree are skipped.

This module has no Windows-only imports: it runs against any `FsOps`, which is how its logic is tested on every platform.
"""
from __future__ import annotations

import os
from collections import Counter

from ..hostos.fsops import EntryReplaced, FsOps, Info
from .config import (
    SandboxError, SensitivePolicy, SkippedEntry, WithheldEntry, WorkspaceChangedError, WorkspaceLimits,
)
from .copy import CHUNK, CopyResult, _Budget
from .secrets import LEARN_MAX, Redactor, SignatureScanner


def _changed(path: str, what: str) -> WorkspaceChangedError:
    return WorkspaceChangedError(
        f"{path or '.'}: {what} while SafeRun was copying; the copy was abandoned (retry on a quiescent tree)")


class _Sink:
    """Writes the copy under `dest` (a directory we own and created)."""

    def __init__(self, dest: str, ops: FsOps):
        self.dest, self.ops = dest, ops

    def _p(self, rel: str) -> str:
        p = os.path.join(self.dest, *rel.split("/"))
        return "\\\\?\\" + os.path.abspath(p) if os.name == "nt" else p

    def mkdir(self, rel: str) -> None:
        os.mkdir(self._p(rel))

    def write(self, rel, node, want: Info, budget: _Budget, redactor: Redactor, withhold_on_match: bool):
        dest, scanner, kind = self._p(rel), SignatureScanner(), None
        head: bytearray | None = bytearray()
        written = read = 0
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        try:
            fd = os.open(dest, flags, 0o644)
        except FileExistsError:
            raise SandboxError(f"{rel}: another entry with the same name (differing only in case) was already copied") from None
        try:
            while chunk := self.ops.read(node, CHUNK):
                read += len(chunk)
                budget.add_bytes(len(chunk))
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
        after = self.ops.refresh(node)
        if read != want.size or after.sig != want.sig:
            raise _changed(rel, "file was modified while being read")
        if head is not None:
            redactor.learn(bytes(head))
        return None, written


class _Walker:
    """One traversal. sink=None is the pre-scan (nothing is read or written)."""

    def __init__(self, ops: FsOps, lim: WorkspaceLimits, policy: SensitivePolicy, sink: _Sink | None,
                 seen_links: Counter | None = None, expected: dict | None = None, expected_listings: dict | None = None):
        self.ops, self.budget, self.policy, self.sink = ops, _Budget(lim), policy, sink
        self.skipped: list[SkippedEntry] = []
        self.withheld: list[WithheldEntry] = []
        self.redactor = Redactor()
        self.copied_files = self.copied_dirs = self.copied_bytes = 0
        self.links: Counter = Counter()
        self.seen_links = seen_links or Counter()
        self.records: dict[str, tuple] = {}
        self.listings: dict[str, frozenset] = {}
        self.expected, self.expected_listings = expected, expected_listings

    def _private(self, path: str, info: Info) -> bool:
        if self.policy.honor_private_modes and path not in self.policy.allow_paths and info.private:
            self.withheld.append(WithheldEntry(path, "private-mode"))
            return True
        return False

    def _verify(self, path: str, want: tuple) -> None:
        if self.expected is None:
            self.records[path] = want
        elif self.expected.get(path) != want:
            raise _changed(path, "entry was replaced, added or modified")

    def _list(self, d, rel: str) -> list[str]:
        exp = None
        if self.expected_listings is not None:
            exp = self.expected_listings.get(rel)
            if exp is None:
                raise _changed(rel, "directory was not part of the pre-scan")
        names = self.ops.listdir(d)
        for name in names:
            self.budget.entry()
            if exp is not None and name not in exp:
                raise _changed(f"{rel}/{name}" if rel else name, "entry was added")
        if exp is not None:
            if len(names) != len(exp):
                raise _changed(rel, "an entry was removed")
        else:
            self.listings[rel] = frozenset(names)
        return sorted(names)

    def walk(self, d, rel: str, depth: int) -> None:
        for name in self._list(d, rel):
            path = f"{rel}/{name}" if rel else name
            try:
                info = self.ops.probe(d, name, True)
            except FileNotFoundError:
                raise _changed(path, "entry was removed") from None
            except OSError:
                self.skipped.append(SkippedEntry(path, "unreadable"))
                continue
            self._verify(path, info.sig)
            if info.kind == "symlink":
                self.skipped.append(SkippedEntry(path, "symlink"))
            elif info.kind == "reparse":
                self.skipped.append(SkippedEntry(path, "reparse-point"))
            elif info.kind == "dir":
                self._dir(d, name, path, info, depth)
            elif info.kind == "file":
                self._file(d, name, path, info)
            else:
                self.skipped.append(SkippedEntry(path, "not-regular-file"))

    def _streams_skip(self, d, name: str, path: str) -> bool:
        try:
            extra = self.ops.streams(d, name)
        except OSError:
            self.skipped.append(SkippedEntry(path, "unreadable"))
            return True
        if extra:
            self.skipped.append(SkippedEntry(path, "alternate-data-stream"))
            return True
        return False

    def _open(self, opener, d, name: str, path: str, want: Info):
        try:
            node = opener(d, name)
        except EntryReplaced:
            raise _changed(path, "entry was replaced or moved") from None
        except (FileNotFoundError, NotADirectoryError):
            raise _changed(path, "entry was replaced or removed") from None
        except OSError:
            self.skipped.append(SkippedEntry(path, "unreadable"))
            return None
        if node.info.sig != want.sig:
            self.ops.close(node)
            raise _changed(path, "entry was replaced or modified")
        return node

    def _dir(self, d, name, path, info: Info, depth):
        self.budget.depth(depth + 1)
        if self._private(path, info) or self._streams_skip(d, name, path):   # same in both passes: such a directory is never entered
            return
        node = self._open(self.ops.open_dir, d, name, path, info)
        if node is None:
            return
        try:
            if self.sink:
                self.sink.mkdir(path)
                self.copied_dirs += 1
            self.walk(node, path, depth + 1)
        finally:
            self.ops.close(node)

    def _file(self, d, name, path, info: Info):
        if self.sink is None:   # pre-scan
            if info.nlink > 1:
                self.links[info.ident] += 1
            if not (self.policy.honor_private_modes and path not in self.policy.allow_paths and info.private):
                self.budget.add_bytes(info.size)
            return
        if self._private(path, info):   # never opened, never read
            return
        if self._streams_skip(d, name, path):
            return
        node = self._open(self.ops.open_file, d, name, path, info)
        if node is None:
            return
        try:
            if node.info.nlink > 1 and self.seen_links[node.info.ident] != node.info.nlink:
                self.skipped.append(SkippedEntry(path, "hardlink-external"))
                return
            kind, kept = self.sink.write(path, node, info, self.budget, self.redactor,
                                         withhold_on_match=path not in self.policy.allow_paths)
            if kind:
                self.withheld.append(WithheldEntry(path, kind))
            else:
                self.copied_files += 1
                self.copied_bytes += kept
        finally:
            self.ops.close(node)


def _validate_tree(ops: FsOps, d, rel: str, records: dict, listings: dict, budget: _Budget) -> None:
    """Final pass: everything below `d` must still be exactly what the pre-scan recorded."""
    expected = listings[rel]
    names = ops.listdir(d)
    for name in names:
        budget.entry()
        if name not in expected:
            raise _changed(f"{rel}/{name}" if rel else name, "entry was added (final check)")
    if len(names) != len(expected):
        raise _changed(rel, "an entry was removed (final check)")
    for name in sorted(names):
        path = f"{rel}/{name}" if rel else name
        try:
            info = ops.probe(d, name, False)
        except FileNotFoundError:
            raise _changed(path, "entry was removed (final check)") from None
        except OSError:
            if path in records:
                raise _changed(path, "entry became unreadable (final check)") from None
            continue
        if records.get(path) != info.sig:
            raise _changed(path, "entry was replaced or modified (final check)")
        if info.kind == "dir" and path in listings:
            try:
                node = ops.open_dir(d, name)
            except OSError:
                raise _changed(path, "directory was replaced or removed (final check)") from None
            try:
                if node.info.sig != records[path]:
                    raise _changed(path, "directory was replaced or modified (final check)")
                _validate_tree(ops, node, path, records, listings, budget)
            finally:
                ops.close(node)


def copy_tree(src: str, dest: str, lim: WorkspaceLimits, policy: SensitivePolicy | None = None, ops: FsOps | None = None) -> CopyResult:
    """Same contract as copy.copy_tree."""
    policy = policy or SensitivePolicy()
    if ops is None:
        from ..hostos.winfs import WinOps
        ops = WinOps()
    try:
        root = ops.open_root(src)
    except EntryReplaced as e:
        raise _changed("", str(e)) from None
    try:
        pre = _Walker(ops, lim, policy, None)
        pre.records[""] = root.info.sig
        pre.walk(root, "", 0)
        w = _Walker(ops, lim, policy, _Sink(dest, ops), pre.links, pre.records, pre.listings)
        if ops.refresh(root).sig != pre.records[""]:
            raise _changed("", "the project root was modified")
        w.walk(root, "", 0)
        if ops.refresh(root).sig != pre.records[""]:
            raise _changed("", "the project root was modified (final check)")
        _validate_tree(ops, root, "", pre.records, pre.listings, _Budget(lim))
        return CopyResult(w.skipped, w.withheld, w.budget.files, w.copied_files, w.copied_dirs, w.copied_bytes, w.redactor)
    finally:
        ops.close(root)
