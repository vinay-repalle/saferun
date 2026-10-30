"""Workspace copy: limits, skipped-entry audit, symlink races. Host-only (no Docker)."""
import os
import stat

import pytest

from saferun.sandbox import SandboxError, WorkspaceChangedError, WorkspaceLimitError, WorkspaceLimits
from saferun.sandbox import copy as cp
from saferun.sandbox.workspace import create_workspace


def _leftovers(ws_root):
    return list(ws_root.iterdir())


def test_copies_files_and_records_skipped_entries(tmp_path, ws_root):
    src = tmp_path / "p"; (src / "sub").mkdir(parents=True)
    (src / "a.py").write_text("x=1"); (src / "sub" / "b.py").write_text("y=2")
    (src / "pw").symlink_to("/etc/passwd"); (src / "dl").symlink_to("/etc")
    os.mkfifo(src / "pipe")
    ws = create_workspace(src)
    try:
        assert sorted(p.relative_to(ws.project).as_posix() for p in ws.project.rglob("*")) == [
            "a.py", "sub", "sub/b.py"]
        assert {(s.path, s.reason) for s in ws.skipped} == {
            ("pw", "symlink"), ("dl", "symlink"), ("pipe", "not-regular-file")}
        assert (ws.copied_files, ws.copied_dirs, ws.copied_bytes) == (2, 1, 6)
        assert ws.entries_scanned == 6  # 2 files + 1 dir + 3 skipped
    finally:
        ws.cleanup()
    assert _leftovers(ws_root) == []


def test_permissions_are_normalized_and_private_files_are_not_widened(tmp_path, ws_root):
    src = tmp_path / "p"; src.mkdir()
    f = src / "run.sh"; f.write_text("#!/bin/sh"); f.chmod(0o777)
    (src / "secret.env").write_text("K=V"); (src / "secret.env").chmod(0o600)
    ws = create_workspace(src)
    try:
        assert stat.S_IMODE((ws.project / "run.sh").stat().st_mode) == 0o644
        assert not (ws.project / "secret.env").exists()  # was copied as 0644 before the fix
        assert [(w.path, w.reason) for w in ws.withheld] == [("secret.env", "private-mode")]
        assert stat.S_IMODE(ws.project.stat().st_mode) == 0o755
        assert stat.S_IMODE(ws.root.stat().st_mode) == 0o711
    finally:
        ws.cleanup()


def _tree(tmp_path, files=0, depth=0, size=0):
    src = tmp_path / "p"; src.mkdir()
    for i in range(files):
        (src / f"f{i}").write_bytes(b"x" * size)
    d = src
    for i in range(depth):
        d = d / "d"; d.mkdir()
    return src


@pytest.mark.parametrize("make,lim", [
    (dict(files=1, size=200), WorkspaceLimits(max_bytes=199)),
    (dict(files=6), WorkspaceLimits(max_files=5)),
    (dict(depth=4), WorkspaceLimits(max_depth=3)),
])
def test_limits_rejected_before_anything_is_copied(tmp_path, ws_root, monkeypatch, make, lim):
    def boom(*a, **k):
        raise AssertionError("copy started although the pre-scan exceeds a limit")
    monkeypatch.setattr(cp._Sink, "write", boom)
    monkeypatch.setattr(cp._Sink, "mkdir", boom)
    with pytest.raises(WorkspaceLimitError):
        create_workspace(_tree(tmp_path, **make), lim)
    assert _leftovers(ws_root) == []


def test_limits_are_inclusive_at_the_boundary(tmp_path, ws_root):
    (tmp_path / "ok").mkdir(); (tmp_path / "bad").mkdir()
    ws = create_workspace(_tree(tmp_path / "ok", files=5, size=10), WorkspaceLimits(max_bytes=50, max_files=5))
    ws.cleanup()
    with pytest.raises(WorkspaceLimitError):
        create_workspace(_tree(tmp_path / "bad", files=5, size=10), WorkspaceLimits(max_bytes=49, max_files=5))


def test_skipped_entries_count_toward_file_limit(tmp_path, ws_root):
    src = tmp_path / "p"; src.mkdir()
    for i in range(10):
        (src / f"l{i}").symlink_to("/etc")
    with pytest.raises(WorkspaceLimitError):
        create_workspace(src, WorkspaceLimits(max_files=9))


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_symlink_swapped_in_after_stat_is_not_followed(tmp_path, ws_root, monkeypatch, kind):
    """Time-of-check/time-of-use: entry is a regular file/dir at stat time, a symlink at open time.
    The swap is detected (abort) and the symlink target is never read."""
    secret_dir = tmp_path / "secret"; secret_dir.mkdir()
    (secret_dir / "loot.txt").write_text("TOP-SECRET")
    src = tmp_path / "p"; src.mkdir()
    target = src / "victim"
    if kind == "file":
        target.write_text("harmless")
    else:
        target.mkdir(); (target / "x").write_text("harmless")

    def swap():
        if kind == "file":
            target.unlink(); target.symlink_to(secret_dir / "loot.txt")
        else:
            import shutil
            shutil.rmtree(target); target.symlink_to(secret_dir)
    real_stat, seen = os.stat, []

    def hooked(path, *a, **k):
        st = real_stat(path, *a, **k)
        if path == "victim":
            seen.append(1)
            if len(seen) == 2:  # 2nd stat of this name == copy pass; swap right after the check
                swap()
        return st
    monkeypatch.setattr(os, "stat", hooked)
    with pytest.raises(WorkspaceChangedError):
        create_workspace(src)
    monkeypatch.undo()
    assert len(seen) == 2, "hook did not fire; test would be vacuous"
    assert list(ws_root.iterdir()) == []  # nothing, in particular no copy of the target, remains


def test_not_a_directory(tmp_path, ws_root):
    f = tmp_path / "f"; f.write_text("")
    with pytest.raises(SandboxError, match="not a directory"):
        create_workspace(f)
    assert _leftovers(ws_root) == []


def test_metrics_count_only_what_was_actually_kept(tmp_path, ws_root):
    """copied_* describe the workspace on disk; skipped/withheld entries and their bytes are excluded."""
    out = tmp_path / "outside"; out.mkdir(); (out / "t").write_text("E" * 70)
    src = tmp_path / "p"; (src / "sub").mkdir(parents=True); (src / "priv").mkdir()
    (src / "a.py").write_text("a" * 10); (src / "sub" / "b.py").write_text("b" * 5)
    (src / "link").symlink_to("/etc/passwd")                       # skipped: symlink
    os.link(out / "t", src / "hl.py")                              # skipped: hardlink-external
    (src / "private.txt").write_text("p" * 100); (src / "private.txt").chmod(0o600)  # withheld: mode
    (src / "key.txt").write_text("-----BEGIN " + "PRIVATE KEY-----\n" + "A" * 64 + "\n" * 1 + "x" * 5000)  # withheld: signature
    (src / "priv" / "in.txt").write_text("i" * 30); (src / "priv").chmod(0o700)      # withheld dir (1 entry)
    ws = create_workspace(src)
    try:
        on_disk = [p for p in ws.project.rglob("*") if p.is_file()]
        assert ws.copied_files == len(on_disk) == 2
        assert ws.copied_bytes == sum(p.stat().st_size for p in on_disk) == 15
        assert ws.copied_dirs == len([p for p in ws.project.rglob("*") if p.is_dir()]) == 1
        assert {(s.path, s.reason) for s in ws.skipped} == {("link", "symlink"), ("hl.py", "hardlink-external")}
        assert {(w.path, w.reason) for w in ws.withheld} == {
            ("private.txt", "private-mode"), ("key.txt", "private-key"), ("priv", "private-mode")}
        assert ws.entries_scanned == 8 == (ws.copied_files + ws.copied_dirs
                                           + len(ws.skipped) + len(ws.withheld))
    finally:
        ws.cleanup()
