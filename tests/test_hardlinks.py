"""Hard links: a file is copied only if every name of its inode lies inside the scanned tree."""
import os

import pytest

from saferun.sandbox import SensitivePolicy, WorkspaceChangedError
from saferun.sandbox.workspace import create_workspace


@pytest.fixture
def layout(tmp_path):
    out = tmp_path / "outside"; out.mkdir()
    src = tmp_path / "p"; src.mkdir()
    return out, src


def _copy(src, **kw):
    return create_workspace(src, **kw)


def _skipped(ws):
    return {(s.path, s.reason) for s in ws.skipped}


def _all_text(ws):
    return "".join(p.read_text() for p in ws.project.rglob("*") if p.is_file())


def test_hardlink_to_file_outside_project_is_not_copied(layout, ws_root):
    out, src = layout
    (out / "target.txt").write_text("EXTERNAL-CONTENT")
    os.link(out / "target.txt", src / "innocent.py")
    (src / "ok.py").write_text("x = 1")
    ws = _copy(src)
    try:
        assert _skipped(ws) == {("innocent.py", "hardlink-external")}
        assert [p.name for p in ws.project.iterdir()] == ["ok.py"]
        assert "EXTERNAL-CONTENT" not in _all_text(ws)
    finally:
        ws.cleanup()


def test_hardlinks_wholly_inside_project_are_copied_as_independent_files(layout, ws_root):
    out, src = layout
    (src / "sub").mkdir()
    (src / "a.txt").write_text("shared")
    os.link(src / "a.txt", src / "b.txt"); os.link(src / "a.txt", src / "sub" / "c.txt")
    ws = _copy(src)
    try:
        copies = [ws.project / "a.txt", ws.project / "b.txt", ws.project / "sub" / "c.txt"]
        assert ws.skipped == [] and all(p.read_text() == "shared" for p in copies)
        inodes = {p.stat().st_ino for p in copies} | {(src / "a.txt").stat().st_ino}
        assert len(inodes) == 4                                   # nothing shares an inode with the source
        assert all(p.stat().st_nlink == 1 for p in copies)
        assert (src / "a.txt").stat().st_nlink == 3               # source untouched
    finally:
        ws.cleanup()


def test_internal_pair_that_also_has_an_external_name_is_skipped(layout, ws_root):
    out, src = layout
    (src / "a.txt").write_text("data"); os.link(src / "a.txt", src / "b.txt")
    os.link(src / "a.txt", out / "elsewhere.txt")                 # third name outside
    ws = _copy(src)
    try:
        assert _skipped(ws) == {("a.txt", "hardlink-external"), ("b.txt", "hardlink-external")}
        assert list(ws.project.iterdir()) == []
    finally:
        ws.cleanup()


def test_external_link_added_after_prescan_fails_closed(layout, ws_root, monkeypatch):
    """Adding a link changes the inode's ctime, so the identity check aborts the copy."""
    out, src = layout
    (src / "a.txt").write_text("data")
    real, calls = os.scandir, []

    def hooked(fd):
        calls.append(1)
        if len(calls) == 2:  # copy pass starts: attacker links an outside name to a project file
            os.link(src / "a.txt", out / "x.txt")
        return real(fd)
    monkeypatch.setattr(os, "scandir", hooked)
    with pytest.raises(WorkspaceChangedError):
        _copy(src)
    monkeypatch.undo()
    assert list(ws_root.iterdir()) == []


def test_secret_linked_into_project_after_prescan_is_not_copied(layout, ws_root, monkeypatch):
    out, src = layout
    (out / "id_rsa").write_text("EXTERNAL-PRIVATE-DATA")
    (src / "ok.py").write_text("x = 1")
    real, calls = os.scandir, []

    def hooked(fd):
        calls.append(1)
        if len(calls) == 2:
            os.link(out / "id_rsa", src / "zz_late.py")  # appears in the copy-pass listing only
        return real(fd)
    monkeypatch.setattr(os, "scandir", hooked)
    with pytest.raises(WorkspaceChangedError):
        _copy(src)
    monkeypatch.undo()
    assert list(ws_root.iterdir()) == []


def test_hardlink_to_private_external_file_is_not_copied(layout, ws_root):
    out, src = layout
    (out / "key").write_text("EXTERNAL-PRIVATE-DATA"); (out / "key").chmod(0o600)
    os.link(out / "key", src / "key_link")
    ws = _copy(src)
    try:
        assert list(ws.project.iterdir()) == [] and "EXTERNAL-PRIVATE-DATA" not in _all_text(ws)
        assert [w.reason for w in ws.withheld] == ["private-mode"]
    finally:
        ws.cleanup()


def test_allow_paths_does_not_override_the_hardlink_check(layout, ws_root):
    out, src = layout
    (out / "t").write_text("EXTERNAL-CONTENT"); os.link(out / "t", src / "l.py")
    ws = _copy(src, policy=SensitivePolicy(allow_paths={"l.py"}))
    try:
        assert _skipped(ws) == {("l.py", "hardlink-external")}
    finally:
        ws.cleanup()


def test_partner_inside_a_withheld_directory_is_treated_conservatively(layout, ws_root):
    out, src = layout
    (src / "priv").mkdir(); (src / "priv").chmod(0o700)
    (src / "priv" / "b.txt").write_text("data")
    os.link(src / "priv" / "b.txt", src / "a.txt")  # other name is in a directory we do not traverse
    ws = _copy(src)
    try:
        assert _skipped(ws) == {("a.txt", "hardlink-external")}
    finally:
        ws.cleanup()
