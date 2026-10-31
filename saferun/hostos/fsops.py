"""The file-system operations the Windows copy engine (sandbox/copy_windows.py) is written against.

`copy_windows` contains the whole algorithm (three passes, signatures, listings, limits, exposure rules); an `FsOps` implementation only
opens, lists, reads and describes things. The real one (`hostos.winfs.WinOps`) uses Win32 handles; the tests also run the algorithm
against a POSIX implementation so its logic is exercised on every platform.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class EntryReplaced(OSError):
    """An opened object is not the one that was named (moved, replaced, or reached through a different path)."""


@dataclass(frozen=True)
class Info:
    kind: str          # file | dir | symlink | reparse | other
    sig: tuple         # identity + state; the two passes and the final check must see the same value
    ident: tuple       # identity shared by all hard links of a file
    size: int
    nlink: int
    private: bool = False   # only meaningful when the probe asked for it: narrower than the project root, or unverifiable


class Node(Protocol):
    info: Info
    path: str


class FsOps(Protocol):
    def open_root(self, path: str) -> Any: ...                              # directory node; reparse point or remote path -> OSError
    def listdir(self, d: Any) -> list[str]: ...
    def probe(self, d: Any, name: str, with_acl: bool) -> Info: ...               # describe WITHOUT following; FileNotFoundError if gone
    def open_dir(self, d: Any, name: str) -> Any: ...                        # locks it against rename / delete while open
    def open_file(self, d: Any, name: str) -> Any: ...                       # read-only; denies others write / delete while open
    def refresh(self, node: Any) -> Info: ...                                # state of the OPEN object (fstat)
    def read(self, node: Any, n: int) -> bytes: ...
    def streams(self, d: Any, name: str) -> list[str]: ...                   # data stream names other than the default one
    def close(self, node: Any) -> None: ...
