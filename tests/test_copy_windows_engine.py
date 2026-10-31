"""The Windows copy engine's algorithm (sandbox/copy_windows.py), run against a POSIX FsOps on every platform.

This proves the logic (three passes, race detection, limits, withholding, skipping); it does NOT prove the Win32 behaviour of
hostos/winfs.py, which tests/test_windows_native.py exercises on a real Windows runner.
"""
import os

import pytest

from posix_fsops import PosixOps
from saferun.sandbox.config import (
    SensitivePolicy, WorkspaceChangedError, WorkspaceLimitError, WorkspaceLimits,
)
from saferun.sandbox.copy_windows import copy_tree

pytestmark = pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs the POSIX test adapter (O_NOFOLLOW, dir_fd)")

LIM = WorkspaceLimits()


@pytest.fixture
def tree(tmp_path):
    src, dest = tmp_path / "src", tmp_path / "dest"
    (src / "pkg").mkdir(parents=True)
    (src / "a.py").write_text("print('a')\n")
    (src / "pkg" / "b.py").write_text("x = 1\n")
    dest.mkdir()
    return src, dest


def run(src, dest, ops=None, policy=None, lim=LIM):
    return copy_tree(str(src), str(dest), lim, policy, ops=ops or PosixOps())


def test_copies_files_and_directories_and_accounts_for_every_entry(tree):
    src, dest = tree
    r = run(src, dest)
    assert (dest / "a.py").read_text() == "print('a')\n" and (dest / "pkg" / "b.py").read_text() == "x = 1\n"
    assert (r.copied_files, r.copied_dirs, r.skipped, r.withheld) == (2, 1, [], [])
    assert r.entries_scanned == r.copied_files + r.copied_dirs + len(r.skipped) + len(r.withheld)


def test_symlink_is_skipped_as_symlink_and_never_followed(tree):
    src, dest = tree
    (src / "ln").symlink_to("/etc")
    r = run(src, dest)
    assert [(s.path, s.reason) for s in r.skipped] == [("ln", "symlink")] and not (dest / "ln").exists()


def test_other_reparse_points_are_skipped_and_reported_distinctly(tree):
    src, dest = tree
    (src / "junction").mkdir()
    (src / "junction" / "secret.txt").write_text("inside")
    r = run(src, dest, PosixOps(reparse={"junction"}))
    assert [(s.path, s.reason) for s in r.skipped] == [("junction", "reparse-point")]
    assert not (dest / "junction").exists() and r.copied_files == 2


def test_alternate_data_streams_skip_the_entry_and_say_so(tree):
    src, dest = tree
    r = run(src, dest, PosixOps(streams={"a.py": [":payload:$DATA"]}))
    assert [(s.path, s.reason) for s in r.skipped] == [("a.py", "alternate-data-stream")] and not (dest / "a.py").exists()
    assert r.entries_scanned == r.copied_files + r.copied_dirs + len(r.skipped) + len(r.withheld)


def test_private_entries_are_withheld_and_never_opened(tree):
    src, dest = tree
    (src / "id_key").write_text("harmless text")
    ops = PosixOps(private={"id_key", "pkg"})
    r = run(src, dest, ops)
    assert sorted((w.path, w.reason) for w in r.withheld) == [("id_key", "private-mode"), ("pkg", "private-mode")]
    assert "id_key" not in ops.opened and "b.py" not in ops.opened and not (dest / "pkg").exists()


def test_allow_paths_and_honor_private_modes_still_work(tree):
    src, dest = tree
    (src / "id_key").write_text("harmless text")
    r = run(src, dest, PosixOps(private={"id_key"}), SensitivePolicy(allow_paths=frozenset({"id_key"})))
    assert (dest / "id_key").exists() and r.withheld == []


def test_credential_content_is_withheld_whatever_the_acl(tree):
    src, dest = tree
    (src / "creds").write_text("AKIA" + "ABCDEFGHIJKLMNOP" + "\n")
    r = run(src, dest)
    assert [(w.path, w.reason) for w in r.withheld] == [("creds", "token:aws-access-key")] and not (dest / "creds").exists()


def test_hardlink_with_a_name_outside_the_tree_is_skipped(tree, tmp_path):
    src, dest = tree
    outside = tmp_path / "outside.txt"
    outside.write_text("shared")
    os.link(outside, src / "linked")
    r = run(src, dest)
    assert [(s.path, s.reason) for s in r.skipped] == [("linked", "hardlink-external")]


def test_hardlink_with_all_names_inside_the_tree_is_copied(tree):
    src, dest = tree
    os.link(src / "a.py", src / "pkg" / "a2.py")
    r = run(src, dest)
    assert r.skipped == [] and (dest / "pkg" / "a2.py").exists()


@pytest.mark.parametrize("mutate", ["modify", "replace", "add", "remove"])
def test_a_change_between_the_passes_abandons_the_copy(tree, mutate):
    src, dest = tree
    state = {"done": False}

    def before(name):
        if state["done"] or name != "a.py":
            return
        state["done"] = True
        p = src / "a.py"
        if mutate == "modify":
            p.write_text("print('changed, and longer')\n")
        elif mutate == "replace":
            p.unlink(); (src / "evil").write_text("x"); (src / "evil").rename(p)
        elif mutate == "add":
            (src / "new.py").write_text("x")
        else:
            (src / "pkg" / "b.py").unlink()

    with pytest.raises(WorkspaceChangedError):
        run(src, dest, PosixOps(before_open=before))


def test_a_symlink_swapped_in_after_the_prescan_is_detected(tree, tmp_path):
    src, dest = tree
    target = tmp_path / "secret"
    target.write_text("top secret")

    def before(name):
        if name == "a.py" and not (src / "a.py").is_symlink():
            (src / "a.py").unlink()
            (src / "a.py").symlink_to(target)

    with pytest.raises(WorkspaceChangedError):
        run(src, dest, PosixOps(before_open=before))
    assert not any("top secret" in p.read_text() for p in dest.rglob("*") if p.is_file())


def test_limits_are_enforced(tree):
    src, dest = tree
    with pytest.raises(WorkspaceLimitError):
        run(src, dest, lim=WorkspaceLimits(max_files=2))
    with pytest.raises(WorkspaceLimitError):
        run(src, dest, lim=WorkspaceLimits(max_bytes=5))


def test_depth_limit(tree):
    src, dest = tree
    d = src
    for i in range(3):
        d = d / f"d{i}"
        d.mkdir()
    with pytest.raises(WorkspaceLimitError):
        run(src, dest, lim=WorkspaceLimits(max_depth=2))


def test_unreadable_entry_is_skipped_not_fatal(tree):
    src, dest = tree
    r = run(src, dest, PosixOps(unreadable={"a.py"}))
    assert [(s.path, s.reason) for s in r.skipped] == [("a.py", "unreadable")] and (dest / "pkg" / "b.py").exists()
