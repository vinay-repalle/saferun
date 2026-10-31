import os
import sys
import tempfile
import textwrap

import pytest

from saferun.sandbox import DEFAULT_IMAGE, SandboxError, SandboxLimits, run_sandboxed
from saferun.sandbox import docker as dk

# Modules that test the POSIX implementation itself (fcntl locks, O_NOFOLLOW / dir_fd copy, permission bits, symlink races, uid ownership).
# On Windows they are skipped, visibly; the Windows equivalents are in test_windows_native.py and test_copy_windows_engine.py.
POSIX_ONLY_MODULES = frozenset({
    "test_workspace", "test_races", "test_hardlinks", "test_analyzer_lock", "test_osv_db_integrity", "test_sensitive", "test_adversarial",
    "test_cleanup", "test_cleanup_hardening", "test_node_profile", "test_analyzer_isolation", "test_sandbox",
})

REQUIRE_DOCKER = os.environ.get("SAFERUN_REQUIRE_DOCKER", "").lower() in ("1", "true", "yes")


def _docker_status() -> str | None:
    """None if usable, else the reason it is not."""
    try:
        dk.check_available(DEFAULT_IMAGE)
        return None
    except SandboxError as e:
        return str(e)


_STATUS = _docker_status()


def pytest_report_header(config):
    if _STATUS is None:
        return f"saferun: docker OK, image {DEFAULT_IMAGE} present"
    mode = "tests will FAIL the run" if REQUIRE_DOCKER else "docker tests will be SKIPPED"
    return f"saferun: docker UNAVAILABLE ({_STATUS}); {mode} (SAFERUN_REQUIRE_DOCKER={int(REQUIRE_DOCKER)})"


def pytest_collection_modifyitems(config, items):
    if sys.platform == "win32":
        skip_posix = pytest.mark.skip(reason="tests the POSIX implementation; see tests/test_windows_native.py for the Windows equivalents")
        for item in items:
            if item.module.__name__.rpartition(".")[2] in POSIX_ONLY_MODULES:
                item.add_marker(skip_posix)
    docker_items = [i for i in items if "docker" in i.keywords]
    if _STATUS is None or not docker_items:
        return
    if REQUIRE_DOCKER:
        pytest.exit(f"SAFERUN_REQUIRE_DOCKER is set but Docker is unusable: {_STATUS}", returncode=2)
    skip = pytest.mark.skip(reason=f"Docker unavailable: {_STATUS}")
    for item in docker_items:
        item.add_marker(skip)


@pytest.fixture
def ws_root(tmp_path, monkeypatch):
    """Redirect SafeRun workspaces into an empty per-test directory."""
    root = tmp_path / "wsroot"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


@pytest.fixture
def probe(tmp_path, ws_root):
    """Run a Python snippet as the untrusted project's main.py in the sandbox."""
    def _run(code: str, **limit_kw):
        proj = tmp_path / "proj"
        proj.mkdir(exist_ok=True)
        (proj / "main.py").write_text(textwrap.dedent(code))
        return run_sandboxed(proj, ["python", "-I", "main.py"], SandboxLimits(**limit_kw))
    return _run


def require_image(image: str) -> None:
    """Skip (visibly) if `image` is not present locally; under SAFERUN_REQUIRE_DOCKER=1 fail instead."""
    try:
        dk.resolve_image(image)
    except SandboxError as e:
        msg = f"{e}. Pull it explicitly (SafeRun never pulls): docker pull {image}"
        if REQUIRE_DOCKER:
            pytest.fail(msg, pytrace=False)
        pytest.skip(msg)


@pytest.fixture
def low_osv_floor(monkeypatch):
    """Small test databases: lower the 'too few advisories' floors (the real floors are exercised in test_osv_db_integrity)."""
    from saferun.engine import osvdb
    monkeypatch.setattr(osvdb, "MIN_ENTRIES", {"PyPI": 1, "npm": 1})


@pytest.fixture(autouse=True)
def _no_real_downloads(monkeypatch):
    """No test may download anything (OSV data, cosign) by accident: an http(s) urlopen fails loudly unless a test replaces it or passes its own
    opener. file:// URLs (used by the fetch_verified tests) still work."""
    import urllib.request
    real = urllib.request.urlopen

    def guarded(url, *a, **k):
        target = getattr(url, "full_url", url)
        if str(target).lower().startswith(("http://", "https://")):
            raise AssertionError(f"a test tried a real network download: {target}")
        return real(url, *a, **k)
    monkeypatch.setattr(urllib.request, "urlopen", guarded)
