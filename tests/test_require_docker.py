"""SAFERUN_REQUIRE_DOCKER must turn 'Docker missing' into a hard failure, not a skip."""
import os
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).parent
ONE = str(TESTS / "test_sandbox.py::test_runs_code_and_captures_output")


def _pytest(require: bool):
    # Empty PATH => the `docker` binary cannot be found => Docker is unavailable.
    env = {"PATH": "/nonexistent", "HOME": os.environ.get("HOME", "/")}
    if require:
        env["SAFERUN_REQUIRE_DOCKER"] = "1"
    return subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", ONE],
                          env=env, capture_output=True, text=True, timeout=120)


def test_required_docker_missing_fails_the_run():
    r = _pytest(require=True)
    assert r.returncode == 2 and "SAFERUN_REQUIRE_DOCKER is set" in r.stdout + r.stderr
    assert "skipped" not in r.stdout


def test_optional_docker_missing_skips_loudly():
    r = _pytest(require=False)
    assert r.returncode == 0 and "1 skipped" in r.stdout and "docker UNAVAILABLE" in r.stdout
