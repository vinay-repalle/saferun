"""macOS-specific checks (skipped elsewhere). The POSIX engines are exercised by the whole suite, which also runs on the macOS runners."""
import os
import sys
from pathlib import Path

import pytest

from saferun import hostos
from saferun.sandbox.workspace import create_workspace

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")


def test_data_directory_default_is_application_support(monkeypatch):
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert hostos.user_data_base() == Path.home() / "Library" / "Application Support"


def test_default_temp_directory_is_a_symlinked_path_and_workspaces_still_work(tmp_path):
    import tempfile
    real = os.path.realpath(tempfile.gettempdir())
    # /var/folders/... is a symlink into /private/var/...: the copy engine opens the real directory without following links
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "a.py").write_text("pass\n")
    ws = create_workspace(tmp_path / "p")
    try:
        assert (ws.project / "a.py").exists() and real
    finally:
        ws.cleanup()


def test_docker_desktop_socket_style_endpoints_are_local(monkeypatch):
    assert hostos.docker_endpoint_is_local("unix:///Users/someone/.docker/run/docker.sock")
    assert not hostos.docker_endpoint_is_local("npipe:////./pipe/docker_engine")
