"""A POSIX `FsOps` (hostos.fsops) so the Windows copy engine's algorithm can be tested on Linux and macOS.

It can pretend that named entries are reparse points, private (ACL-narrow) or carry alternate data streams, and run a callback right
before a file / directory is opened, which is where the race tests change the tree.
"""
import os
import stat
from dataclasses import dataclass

from saferun.hostos.fsops import Info

_RD = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW


@dataclass
class N:
    path: str
    info: Info
    fd: int


def _info(st, kind, private=False):
    sig = (kind, stat.S_IMODE(st.st_mode), st.st_dev, st.st_ino, st.st_size if kind == "file" else 0, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)
    return Info(kind, sig, (st.st_dev, st.st_ino), st.st_size if kind == "file" else 0, st.st_nlink, private)


def _kind(mode):
    return "symlink" if stat.S_ISLNK(mode) else "dir" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else "other"


class PosixOps:
    def __init__(self, reparse=(), private=(), streams=None, before_open=None, unreadable=()):
        self.reparse, self.private, self.streams_of = set(reparse), set(private), dict(streams or {})
        self.before_open, self.unreadable = before_open, set(unreadable)
        self.opened = []   # names opened for reading (private entries must never appear here)

    def open_root(self, path):
        fd = os.open(path, _RD | os.O_DIRECTORY)
        return N(path, _info(os.fstat(fd), "dir"), fd)

    def listdir(self, d):
        with os.scandir(d.fd) as it:
            return [e.name for e in it]

    def probe(self, d, name, with_acl):
        st = os.stat(name, dir_fd=d.fd, follow_symlinks=False)
        kind = "reparse" if name in self.reparse else _kind(st.st_mode)
        return _info(st, kind, with_acl and name in self.private)

    def _open(self, d, name, extra):
        if self.before_open:
            self.before_open(name)
        if name in self.unreadable:
            raise PermissionError(name)
        try:
            fd = os.open(name, _RD | extra, dir_fd=d.fd)
        except OSError as e:
            if e.errno in (40, 20):   # ELOOP, ENOTDIR: replaced by a symlink / non-directory
                raise FileNotFoundError(name) from None
            raise
        st = os.fstat(fd)
        return N(d.path + "/" + name, _info(st, _kind(st.st_mode)), fd)

    def open_dir(self, d, name):
        return self._open(d, name, os.O_DIRECTORY)

    def open_file(self, d, name):
        self.opened.append(name)
        return self._open(d, name, os.O_NONBLOCK)

    def refresh(self, node):
        st = os.fstat(node.fd)
        return _info(st, _kind(st.st_mode))

    def read(self, node, n):
        return os.read(node.fd, n)

    def streams(self, d, name):
        return list(self.streams_of.get(name, []))

    def close(self, node):
        if node.fd is not None:
            os.close(node.fd)
            node.fd = None
