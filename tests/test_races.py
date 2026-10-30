"""Copy-pass races: content introduced or altered after the pre-scan is detected and the copy abandoned.

Most attacks run at the instant the copy pass starts listing the project root (i.e. after the
pre-scan recorded everything); the final-validation tests run right after a chosen directory's copy-pass
listing. Each asserts WorkspaceChangedError and that *nothing* is left in the workspace root.
This tests detection on a live filesystem, not an atomic-snapshot guarantee. Host-only (no Docker).
"""
import os
import shutil
import stat

import pytest

from saferun.sandbox import SensitivePolicy, WorkspaceChangedError, WorkspaceLimitError, WorkspaceLimits
from saferun.sandbox import copy as cp
from saferun.sandbox.workspace import create_workspace

EXTERNAL = "EXTERNAL-CONTENT-MUST-NEVER-BE-COPIED"


@pytest.fixture
def world(tmp_path):
    out = tmp_path / "outside"; out.mkdir()
    src = tmp_path / "p"; (src / "sub").mkdir(parents=True)
    (src / "a.py").write_text("original-a")
    (src / "sub" / "b.py").write_text("original-b")
    return out, src


@pytest.fixture
def after_prescan(monkeypatch):
    """Run `action` once, right before the copy pass lists the project root."""
    def install(src, action):
        real, root_ino, n = os.scandir, os.stat(src).st_ino, []

        def hooked(fd):
            if isinstance(fd, int) and os.fstat(fd).st_ino == root_ino:
                n.append(1)
                if len(n) == 2:  # 1st listing = pre-scan, 2nd = copy pass
                    action()
            return real(fd)
        monkeypatch.setattr(os, "scandir", hooked)
        return n
    return install


def _assert_abandoned(src, ws_root, fired):
    with pytest.raises(WorkspaceChangedError):
        create_workspace(src)
    assert len(fired) >= 2, "attack hook never ran; test would be vacuous"
    assert list(ws_root.iterdir()) == []


def _external_file(out, how):
    secret = out / "secret.txt"; secret.write_text(EXTERNAL)
    if how == "fresh-copy":                       # new inode, same filesystem
        fresh = out / "fresh.txt"; shutil.copyfile(secret, fresh)
        return fresh
    return secret                                 # an existing file, moved in (keeps its inode)


@pytest.mark.parametrize("how", ["moved", "fresh-copy"])
def test_regular_file_replaced_by_external_file(world, ws_root, after_prescan, how):
    """The reported attack: nlink == 1, regular file, so the hard-link check cannot see it."""
    out, src = world
    fired = after_prescan(src, lambda: os.replace(_external_file(out, how), src / "a.py"))
    _assert_abandoned(src, ws_root, fired)


@pytest.mark.parametrize("how", ["moved", "fresh-copy"])
def test_nested_file_replaced_by_external_file(world, ws_root, after_prescan, how):
    out, src = world
    fired = after_prescan(src, lambda: os.replace(_external_file(out, how), src / "sub" / "b.py"))
    _assert_abandoned(src, ws_root, fired)


def test_directory_replaced_by_external_directory(world, ws_root, after_prescan):
    out, src = world
    ext = out / "extdir"; ext.mkdir(); (ext / "b.py").write_text(EXTERNAL); (ext / "loot.txt").write_text(EXTERNAL)

    def swap():
        shutil.rmtree(src / "sub")
        os.rename(ext, src / "sub")               # same name, different inode, external content
    fired = after_prescan(src, swap)
    _assert_abandoned(src, ws_root, fired)


def test_directory_replaced_by_symlink_to_external_directory(world, ws_root, after_prescan):
    out, src = world
    (out / "loot.txt").write_text(EXTERNAL)

    def swap():
        shutil.rmtree(src / "sub"); (src / "sub").symlink_to(out)
    fired = after_prescan(src, swap)
    _assert_abandoned(src, ws_root, fired)


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_new_external_entry_added_after_prescan(world, ws_root, after_prescan, kind):
    out, src = world
    if kind == "file":
        (out / "n.txt").write_text(EXTERNAL); action = lambda: os.rename(out / "n.txt", src / "new.py")
    else:
        (out / "nd").mkdir(); (out / "nd" / "x").write_text(EXTERNAL)
        action = lambda: os.rename(out / "nd", src / "newdir")
    fired = after_prescan(src, action)
    _assert_abandoned(src, ws_root, fired)


def test_entry_added_inside_subdirectory(world, ws_root, after_prescan):
    out, src = world
    (out / "n.txt").write_text(EXTERNAL)
    fired = after_prescan(src, lambda: os.rename(out / "n.txt", src / "sub" / "new.py"))
    _assert_abandoned(src, ws_root, fired)


def test_entry_removed_after_prescan(world, ws_root, after_prescan):
    out, src = world
    fired = after_prescan(src, lambda: (src / "a.py").unlink())
    _assert_abandoned(src, ws_root, fired)


def test_symlink_replaced_by_external_regular_file(world, ws_root, after_prescan):
    """Recorded as a symlink (skipped, never opened); swapping in a real external file is still detected."""
    out, src = world
    (src / "link").symlink_to("/etc/passwd")
    (out / "s.txt").write_text(EXTERNAL)

    def swap():
        (src / "link").unlink(); os.rename(out / "s.txt", src / "link")
    fired = after_prescan(src, swap)
    _assert_abandoned(src, ws_root, fired)


def test_in_place_rewrite_with_same_size_and_restored_mtime(world, ws_root, after_prescan):
    """Same inode, same size, mtime put back: ctime (not settable) still gives it away."""
    out, src = world
    f = src / "a.py"; st = f.stat()

    def rewrite():
        f.write_text("X" * st.st_size)
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
    fired = after_prescan(src, rewrite)
    _assert_abandoned(src, ws_root, fired)


def test_chmod_after_prescan_is_detected(world, ws_root, after_prescan):
    out, src = world
    fired = after_prescan(src, lambda: (src / "a.py").chmod(0o600))
    _assert_abandoned(src, ws_root, fired)


def test_file_modified_while_being_read(world, ws_root, monkeypatch):
    """Changed after it was verified and opened, mid-read: caught by the post-read check."""
    out, src = world
    (src / "sub" / "b.py").unlink(); (src / "sub").rmdir(); (src / "a.py").unlink()  # only the target remains
    monkeypatch.setattr(cp, "CHUNK", 64)
    big = src / "big.bin"; big.write_bytes(b"A" * 200)
    real, calls = os.read, []

    def hooked(fd, n):
        if n == 64:
            calls.append(1)
            if len(calls) == 2:
                with open(big, "r+b") as g:  # same size, different bytes
                    g.write(b"Z" * 10)
        return real(fd, n)
    monkeypatch.setattr(os, "read", hooked)
    with pytest.raises(WorkspaceChangedError, match="modified while being read"):
        create_workspace(src)
    monkeypatch.undo()
    assert list(ws_root.iterdir()) == []


def test_file_growing_while_being_read_hits_the_byte_budget(world, ws_root, monkeypatch):
    out, src = world
    (src / "sub" / "b.py").unlink(); (src / "sub").rmdir(); (src / "a.py").unlink()
    f = src / "grow.bin"; f.write_bytes(b"x" * 10)
    real, calls = os.read, []

    def hooked(fd, n):
        if n == cp.CHUNK:
            calls.append(1)
            if len(calls) == 1:
                with open(f, "ab") as g:
                    g.write(b"y" * 5000)
        return real(fd, n)
    monkeypatch.setattr(os, "read", hooked)
    with pytest.raises(WorkspaceLimitError, match="larger than"):
        create_workspace(src, WorkspaceLimits(max_bytes=1000))
    monkeypatch.undo()
    assert list(ws_root.iterdir()) == []


# ---- recorded identity, listing limits, and non-attack behaviour --------------

def test_prescan_records_identity_and_type_of_every_visited_entry(world):
    out, src = world
    os.symlink("/etc/passwd", src / "ln"); os.mkfifo(src / "pipe")
    pre = cp._Walker(WorkspaceLimits(), SensitivePolicy(), None)
    fd = os.open(src, os.O_RDONLY | os.O_DIRECTORY)
    try:
        pre.walk(fd, "", 0)
    finally:
        os.close(fd)
    assert set(pre.records) == {"a.py", "sub", "sub/b.py", "ln", "pipe"}
    kinds = {p: stat.S_IFMT(r[0]) for p, r in pre.records.items()}
    assert kinds == {"a.py": stat.S_IFREG, "sub": stat.S_IFDIR, "sub/b.py": stat.S_IFREG,
                     "ln": stat.S_IFLNK, "pipe": stat.S_IFIFO}
    for path, rec in pre.records.items():
        st = os.lstat(src / path)
        assert rec[1:3] == (st.st_dev, st.st_ino)
    assert pre.listings == {"": frozenset({"a.py", "sub", "ln", "pipe"}), "sub": frozenset({"b.py"})}


def test_quiescent_tree_is_copied_exactly(world, ws_root):
    out, src = world
    ws = create_workspace(src)
    try:
        assert (ws.project / "a.py").read_text() == "original-a"
        assert (ws.project / "sub" / "b.py").read_text() == "original-b"
        assert (ws.copied_files, ws.copied_dirs) == (2, 1)
    finally:
        ws.cleanup()


def test_unreadable_file_is_skipped_not_treated_as_tampering(world, ws_root):
    out, src = world
    (src / "noread.txt").write_text("x"); (src / "noread.txt").chmod(0o044)  # world-readable, owner cannot read
    ws = create_workspace(src)
    try:
        assert [(s.path, s.reason) for s in ws.skipped] == [("noread.txt", "unreadable")]
    finally:
        ws.cleanup()


def test_directory_listing_is_bounded_by_the_entry_limit(world, ws_root, monkeypatch):
    """A directory with a million entries must be rejected after ~max_files reads, not read in full."""
    out, src = world
    consumed = []

    class Entry:
        def __init__(self, name): self.name = name

    class FakeScan:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def __iter__(self):
            for i in range(1_000_000):
                consumed.append(i)
                yield Entry(f"f{i}")
    real, root_ino = os.scandir, os.stat(src).st_ino
    monkeypatch.setattr(os, "scandir", lambda fd: FakeScan()
                        if isinstance(fd, int) and os.fstat(fd).st_ino == root_ino else real(fd))
    with pytest.raises(WorkspaceLimitError, match="more than 50 entries"):
        create_workspace(src, WorkspaceLimits(max_files=50))
    monkeypatch.undo()
    assert len(consumed) <= 51
    assert list(ws_root.iterdir()) == []


# ---- final validation pass: changes after a directory's copy-pass listing -----

@pytest.fixture
def tree(tmp_path):
    out = tmp_path / "outside"; out.mkdir()
    src = tmp_path / "p"
    for rel in ("a.py", "adir/x.py", "zsub/b.py", "zsub/deep/c.py"):  # copy order: a.py, adir, zsub, zsub/deep
        f = src / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(f"orig-{rel}")
    return out, src


@pytest.fixture
def after_listing(monkeypatch):
    """Run `action` the instant the copy-pass (2nd) os.scandir of `target` has finished listing it."""
    def install(target, action):
        real, ino, n = os.scandir, os.stat(target).st_ino, []

        class Wrapped:
            def __init__(self, it): self.it = it
            def __enter__(self): return self.it.__enter__()
            def __exit__(self, *a):
                r = self.it.__exit__(*a)
                if len(n) == 2:
                    action()
                return r

        def hooked(fd):
            if isinstance(fd, int) and os.fstat(fd).st_ino == ino:
                n.append(1)
                if len(n) == 2:
                    return Wrapped(real(fd))
            return real(fd)
        monkeypatch.setattr(os, "scandir", hooked)
        return n
    return install


def _rejected_by_final_check(src, ws_root, fired):
    with pytest.raises(WorkspaceChangedError, match="final check"):
        create_workspace(src)
    assert len(fired) >= 2, "hook never ran; test would be vacuous"
    assert list(ws_root.iterdir()) == []


@pytest.mark.parametrize("content", ["harmless", EXTERNAL], ids=["new-file", "external-content"])
@pytest.mark.parametrize("where", ["", "zsub", "zsub/deep"], ids=["root", "nested", "deeply-nested"])
def test_file_added_right_after_its_directory_was_listed(tree, ws_root, after_listing, where, content):
    """The owner-reported case, at every depth: the new name was not in the listing the copy used."""
    out, src = tree
    d = src / where
    fired = after_listing(d, lambda: (d / "added_late.py").write_text(content))
    _rejected_by_final_check(src, ws_root, fired)


@pytest.mark.parametrize("where", ["", "zsub", "zsub/deep"], ids=["root", "nested", "deeply-nested"])
def test_directory_added_right_after_its_parent_was_listed(tree, ws_root, after_listing, where):
    out, src = tree
    d = src / where

    def add():
        (d / "late_dir" / "inner").mkdir(parents=True); (d / "late_dir" / "inner" / "f.txt").write_text(EXTERNAL)
    fired = after_listing(d, add)
    _rejected_by_final_check(src, ws_root, fired)


def test_external_directory_moved_in_after_listing(tree, ws_root, after_listing):
    out, src = tree
    (out / "ext").mkdir(); (out / "ext" / "loot.txt").write_text(EXTERNAL)
    fired = after_listing(src / "zsub", lambda: os.rename(out / "ext", src / "zsub" / "late_ext"))
    _rejected_by_final_check(src, ws_root, fired)


def test_entry_added_to_an_already_copied_directory(tree, ws_root, after_listing):
    """adir was listed *and fully copied* before zsub is processed; adding to it afterwards is still caught."""
    out, src = tree
    fired = after_listing(src / "zsub", lambda: (src / "adir" / "late.py").write_text(EXTERNAL))
    _rejected_by_final_check(src, ws_root, fired)


def test_entry_added_to_root_while_a_later_directory_is_being_copied(tree, ws_root, after_listing):
    out, src = tree
    fired = after_listing(src / "zsub" / "deep", lambda: (src / "late_root.py").write_text("x"))
    _rejected_by_final_check(src, ws_root, fired)


@pytest.mark.parametrize("change", ["removed", "rewritten-in-place", "replaced-by-external", "chmod"])
def test_already_copied_file_changed_afterwards(tree, ws_root, after_listing, change):
    out, src = tree
    f = src / "a.py"; st = f.stat()

    def act():
        if change == "removed":
            f.unlink()
        elif change == "rewritten-in-place":
            f.write_text("X" * st.st_size); os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        elif change == "replaced-by-external":
            (out / "s.txt").write_text(EXTERNAL); os.replace(out / "s.txt", f)
        else:
            f.chmod(0o600)
    fired = after_listing(src / "zsub", act)
    _rejected_by_final_check(src, ws_root, fired)


@pytest.mark.parametrize("change", ["chmod", "replaced-by-external-dir", "entry-removed-inside", "entry-renamed-inside"])
def test_already_copied_directory_changed_afterwards(tree, ws_root, after_listing, change):
    """Directory identity and metadata, not just its files, are validated at the end."""
    out, src = tree
    adir = src / "adir"

    def act():
        if change == "chmod":
            adir.chmod(0o750 | 0o005)                    # still world-accessible, but metadata changed
        elif change == "replaced-by-external-dir":
            shutil.rmtree(adir); (out / "ed").mkdir(); (out / "ed" / "x.py").write_text(EXTERNAL)
            os.rename(out / "ed", adir)
        elif change == "entry-removed-inside":
            (adir / "x.py").unlink()
        else:
            os.rename(adir / "x.py", adir / "y.py")
    fired = after_listing(src / "zsub", act)
    _rejected_by_final_check(src, ws_root, fired)


def test_final_validation_accepts_an_untouched_tree_with_private_and_special_entries(tree, ws_root):
    """The final pass must not reject entries it cannot descend into."""
    out, src = tree
    os.symlink("/etc/passwd", src / "ln"); os.mkfifo(src / "pipe")
    (src / "priv").mkdir(); (src / "priv" / "k").write_text("p"); (src / "priv").chmod(0o700)
    (src / "secret.txt").write_text("s"); (src / "secret.txt").chmod(0o600)
    ws = create_workspace(src)
    try:
        assert (ws.copied_files, ws.copied_dirs) == (4, 3)
        assert {w.path for w in ws.withheld} == {"priv", "secret.txt"}
    finally:
        ws.cleanup()


# ---- removal and truncation inside the stat -> open -> read windows --------------

@pytest.mark.parametrize("kind", ["file", "directory"])
def test_entry_removed_between_stat_and_open(tree, ws_root, monkeypatch, kind):
    out, src = tree
    victim = src / ("a.py" if kind == "file" else "adir")
    real, seen = os.stat, []

    def hooked(path, *a, **k):
        st = real(path, *a, **k)
        if path == victim.name:
            seen.append(1)
            if len(seen) == 2:  # copy pass: gone right after it was checked
                shutil.rmtree(victim) if kind == "directory" else victim.unlink()
        return st
    monkeypatch.setattr(os, "stat", hooked)
    with pytest.raises(WorkspaceChangedError):
        create_workspace(src)
    monkeypatch.undo()
    assert len(seen) == 2 and list(ws_root.iterdir()) == []


def test_file_truncated_while_being_read(tree, ws_root, monkeypatch):
    out, src = tree
    for rel in ("adir/x.py", "zsub/b.py", "zsub/deep/c.py"):
        (src / rel).unlink()
    for d in ("adir", "zsub/deep", "zsub"):
        (src / d).rmdir()
    (src / "a.py").write_bytes(b"A" * 200)
    monkeypatch.setattr(cp, "CHUNK", 64)
    real, calls = os.read, []

    def hooked(fd, n):
        if n == 64:
            calls.append(1)
            if len(calls) == 2:
                os.truncate(src / "a.py", 10)
        return real(fd, n)
    monkeypatch.setattr(os, "read", hooked)
    with pytest.raises(WorkspaceChangedError, match="modified while being read"):
        create_workspace(src)
    monkeypatch.undo()
    assert list(ws_root.iterdir()) == []
