"""`FsOps` for Windows (NTFS / ReFS) on Win32 handles. Imported only on Windows.

Why this is race-resistant (the Windows counterpart of openat + O_NOFOLLOW):
* every entry is opened with FILE_FLAG_OPEN_REPARSE_POINT, so a symlink / junction / mount point is opened as itself and never followed;
* every directory stays open, with a share mode that forbids rename and delete, until its subtree has been walked, so NTFS refuses to
  move or replace it or any ancestor on the way down;
* files are read with a share mode that forbids writers and deleters;
* the final path of each opened handle must equal parent path + name;
* identity is read from the open handle (128-bit file id + volume), never from a path.
Adding or removing entries inside a directory is still possible, so the listing / signature comparison of the three passes stays.
"""
from __future__ import annotations

import msvcrt
import os
from dataclasses import dataclass, field

from . import _win, acl
from .fsops import EntryReplaced, Info

_SIG_ATTRS = 0x1 | 0x2 | 0x4 | 0x10 | 0x400    # READONLY HIDDEN SYSTEM DIRECTORY REPARSE_POINT; ARCHIVE / indexing flags change by themselves
_ALL_SHARE = _win.SHARE_READ | _win.SHARE_WRITE | _win.SHARE_DELETE
_BENIGN_STREAMS = frozenset({"::$DATA", ":Zone.Identifier:$DATA"})   # default data; "downloaded from the internet" mark (never copied)


@dataclass
class WinNode:
    path: str
    info: Info
    handle: int | None = None     # directories
    fd: int | None = None         # files (owns the handle)
    final: str = ""
    extra: dict = field(default_factory=dict)


def _norm(p: str) -> str:
    return os.path.normcase(p).rstrip("\\")


def _mk_info(h: int, acl_state: tuple | None, with_acl: bool) -> Info:
    fi = _win.file_info(h)
    attrs = fi["attrs"]
    if attrs & _win.ATTR_REPARSE_POINT:
        kind = "symlink" if fi["tag"] == _win.TAG_SYMLINK else "reparse"
    else:
        kind = "dir" if attrs & _win.ATTR_DIRECTORY else "file"
    size = fi["size"] if kind == "file" else 0
    sig = (kind, attrs & _SIG_ATTRS, fi["ident"], size, fi["written"], fi["changed"], fi["nlink"])
    private = False
    if with_acl and kind in ("file", "dir"):
        private = not _readable_like_root(h, kind == "dir", acl_state)
    return Info(kind, sig, fi["ident"], size, fi["nlink"], private)


def _readable_like_root(h: int, directory: bool, state) -> bool:
    caller, baseline = state
    try:
        desc = acl.parse_descriptor(_win.security_descriptor(h))
        return acl.at_least_as_readable(desc.dacl, baseline, caller, directory=directory)
    except (OSError, acl.AclUnverifiable):
        return False   # cannot verify -> treated as private (withheld), never as shareable


class WinOps:
    def __init__(self):
        self._caller = _win.current_token()[0]
        self._state: tuple | None = None   # (caller token, root DACL) once the root is open

    def open_root(self, path: str) -> WinNode:
        real = os.path.realpath(path)
        if _win.is_remote_drive(real):
            raise OSError(f"{real} is on a network drive; SafeRun copies local projects only")
        h = _win.open_handle(real, _win.FILE_LIST_DIRECTORY | _win.FILE_READ_ATTRIBUTES | _win.READ_CONTROL, _win.SHARE_READ,
                             flags=_win.FLAG_BACKUP_SEMANTICS | _win.FLAG_OPEN_REPARSE_POINT)
        try:
            final = _win.final_path(h)
            if _norm(final) != _norm(real):
                raise EntryReplaced(f"the project root resolves to {final}, not {real}")
            info = _mk_info(h, None, False)
            if info.kind != "dir":
                raise NotADirectoryError(f"not a plain directory (reparse point?): {real}")
            try:
                self._state = (self._caller, acl.parse_descriptor(_win.security_descriptor(h)).dacl)
            except (OSError, acl.AclUnverifiable) as e:
                raise OSError(f"cannot read the access-control list of the project root, so private files cannot be told apart: {e}") from None
            return WinNode(final, info, handle=h, final=final)
        except BaseException:
            _win.close(h)
            raise

    def listdir(self, d: WinNode) -> list[str]:
        with os.scandir(_win.ext(d.path)) as it:
            return [e.name for e in it]

    def _child(self, d: WinNode, name: str) -> str:
        return d.path.rstrip("\\") + "\\" + name

    def probe(self, d: WinNode, name: str, with_acl: bool) -> Info:
        path = self._child(d, name)
        private_forced = False
        try:
            h = _win.open_handle(path, _win.FILE_READ_ATTRIBUTES | _win.READ_CONTROL, _ALL_SHARE,
                                 flags=_win.FLAG_BACKUP_SEMANTICS | _win.FLAG_OPEN_REPARSE_POINT)
        except PermissionError:   # cannot even read its ACL: describe it, but it counts as private
            h = _win.open_handle(path, _win.FILE_READ_ATTRIBUTES, _ALL_SHARE,
                                 flags=_win.FLAG_BACKUP_SEMANTICS | _win.FLAG_OPEN_REPARSE_POINT)
            private_forced = True
        try:
            info = _mk_info(h, self._state, with_acl and not private_forced)
            if private_forced and with_acl:
                info = Info(info.kind, info.sig, info.ident, info.size, info.nlink, True)
            return info
        finally:
            _win.close(h)

    def _check_path(self, d: WinNode, name: str, h: int) -> str:
        """Final path of the open handle `h`. Raises without closing `h`: the caller owns it and closes it on any failure."""
        final = _win.final_path(h)
        if _norm(final) != _norm(d.final.rstrip("\\") + "\\" + name):
            raise EntryReplaced(f"{name} is not located where its directory says")
        return final

    def open_dir(self, d: WinNode, name: str) -> WinNode:
        h = _win.open_handle(self._child(d, name), _win.FILE_LIST_DIRECTORY | _win.FILE_READ_ATTRIBUTES | _win.READ_CONTROL, _win.SHARE_READ,
                             flags=_win.FLAG_BACKUP_SEMANTICS | _win.FLAG_OPEN_REPARSE_POINT)
        try:
            final = self._check_path(d, name, h)
            return WinNode(self._child(d, name), _mk_info(h, None, False), handle=h, final=final)
        except BaseException:
            _win.close(h)
            raise

    def open_file(self, d: WinNode, name: str) -> WinNode:
        h = _win.open_handle(self._child(d, name), _win.GENERIC_READ | _win.FILE_READ_ATTRIBUTES, _win.SHARE_READ,
                             flags=_win.FLAG_OPEN_REPARSE_POINT)
        try:
            final = self._check_path(d, name, h)
            fd = msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
        except BaseException:
            _win.close(h)
            raise
        try:   # from here the descriptor owns the handle
            return WinNode(self._child(d, name), _mk_info(h, None, False), fd=fd, final=final)
        except BaseException:
            os.close(fd)
            raise

    def refresh(self, node: WinNode) -> Info:
        h = node.handle if node.handle is not None else msvcrt.get_osfhandle(node.fd)
        return _mk_info(h, None, False)

    def read(self, node: WinNode, n: int) -> bytes:
        return os.read(node.fd, n)

    def streams(self, d: WinNode, name: str) -> list[str]:
        return [s for s in _win.stream_names(self._child(d, name)) if s not in _BENIGN_STREAMS]

    def close(self, node: WinNode) -> None:
        if node.fd is not None:
            os.close(node.fd)
            node.fd = None
        elif node.handle is not None:
            _win.close(node.handle)
            node.handle = None
