"""Per-platform rules in hostos: data directories, Docker endpoints, mount sources, process start flags."""
import sys
from pathlib import Path

import pytest

from saferun import hostos
from saferun.hostos import process as hp


@pytest.mark.skipif(sys.platform == "win32", reason="simulates a POSIX HOME; Windows uses LOCALAPPDATA (next tests)")
def test_data_base_prefers_xdg_on_posix_and_is_unchanged_on_linux(monkeypatch):
    monkeypatch.setattr(hostos, "IS_WINDOWS", False)
    monkeypatch.setattr(hostos, "IS_MACOS", False)
    monkeypatch.setenv("XDG_DATA_HOME", "/x/data")
    assert hostos.user_data_base() == Path("/x/data")
    monkeypatch.delenv("XDG_DATA_HOME")
    monkeypatch.setenv("HOME", "/home/u")
    assert hostos.user_data_base() == Path("/home/u/.local/share")


@pytest.mark.skipif(sys.platform == "win32", reason="simulates a POSIX HOME; Windows uses LOCALAPPDATA (next tests)")
def test_data_base_on_macos(monkeypatch):
    monkeypatch.setattr(hostos, "IS_WINDOWS", False)
    monkeypatch.setattr(hostos, "IS_MACOS", True)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", "/Users/u")
    assert hostos.user_data_base() == Path("/Users/u/Library/Application Support")


def test_data_base_on_windows(monkeypatch):
    monkeypatch.setattr(hostos, "IS_WINDOWS", True)
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\u\AppData\Local")
    assert str(hostos.user_data_base()).endswith("Local")


@pytest.mark.parametrize("host,ok", [
    ("npipe:////./pipe/docker_engine", True), ("npipe:////./pipe/dockerDesktopLinuxEngine", True), ("npipe:///./pipe/docker_engine", True),
    ("npipe:////server/pipe/docker_engine", False), ("npipe:////./pipe/", False), ("npipe:////./pipe/a/b", False),
    ("npipe:////./pipe/x;rm", False), ("unix:///var/run/docker.sock", False), ("tcp://127.0.0.1:2375", False),
    ("ssh://u@h", False), ("", False),
])
def test_windows_accepts_only_local_named_pipes(monkeypatch, host, ok):
    monkeypatch.setattr(hostos, "IS_WINDOWS", True)
    assert hostos.docker_endpoint_is_local(host) is ok


@pytest.mark.parametrize("host,ok", [("unix:///var/run/docker.sock", True), ("unix:///Users/u/.docker/run/docker.sock", True),
                                     ("npipe:////./pipe/docker_engine", False), ("tcp://127.0.0.1:2375", False), ("", False)])
def test_posix_accepts_only_unix_sockets(monkeypatch, host, ok):
    monkeypatch.setattr(hostos, "IS_WINDOWS", False)
    assert hostos.docker_endpoint_is_local(host) is ok


def test_mount_source_rules_apply_on_windows_only(monkeypatch):
    monkeypatch.setattr(hostos, "IS_WINDOWS", False)
    assert hostos.mount_source_problem("/tmp/x") is None
    monkeypatch.setattr(hostos, "IS_WINDOWS", True)
    monkeypatch.setattr(hostos, "_win", type("W", (), {"is_remote_drive": staticmethod(lambda p: p.startswith("Z:"))}), raising=False)
    assert hostos.mount_source_problem("C:\\Users\\u\\AppData\\Local\\Temp\\saferun-ws-1\\project") is None
    for bad in ("\\\\server\\share\\x", "\\\\?\\C:\\x", "\\\\.\\pipe\\x", "/tmp/x", "relative\\path", "C:/forward"):
        assert hostos.mount_source_problem(bad), bad
    assert "network" in hostos.mount_source_problem("Z:\\proj")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX start flags")
def test_posix_children_get_their_own_session_as_before():
    assert hp.popen_kwargs() == {"start_new_session": True, "close_fds": True}
