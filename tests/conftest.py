import os
import tempfile
import textwrap

import pytest

from saferun.sandbox import DEFAULT_IMAGE, SandboxError, SandboxLimits, run_sandboxed
from saferun.sandbox import docker as dk

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
