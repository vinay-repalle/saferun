"""The CI workflow (.github/workflows/ci.yml) tests and checks only: it must never publish, log in to a registry or use a secret."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"


@pytest.fixture(scope="module")
def ci() -> str:
    return CI.read_text()


def test_every_action_is_pinned_to_a_full_commit(ci):
    uses = re.findall(r"^\s*(?:- )?uses: (\S+)", ci, re.M)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses


def test_ci_has_read_only_permissions_and_no_secrets(ci):
    top = ci.split("\npermissions:\n", 1)[1].split("\n\n", 1)[0]
    assert top.strip() == "contents: read"
    assert "secrets." not in ci and "packages:" not in ci and "id-token" not in ci
    assert "pull_request_target" not in ci


def test_ci_never_publishes(ci):
    for forbidden in ("docker push", "docker login", "docker/login-action", "build-push-action", "cosign", "twine upload", "npm publish",
                      "gh release", "git push", "git tag"):
        assert forbidden not in ci, forbidden


def test_ci_runs_on_pull_requests_and_pushes_to_main_only(ci):
    on = ci.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert re.fullmatch(r"\s*pull_request:\n\s*push:\n\s*branches: \[main\]\s*", on), on


def test_ci_is_valid_yaml_with_the_expected_jobs():
    ruamel = pytest.importorskip("ruamel.yaml")
    doc = ruamel.YAML(typ="safe").load(CI.read_text())
    assert set(doc["jobs"]) == {"python", "platforms", "web", "package", "audit", "docker"}
    blocking = {k for k, v in doc["jobs"].items() if not v.get("continue-on-error")}
    assert blocking == {"python", "web", "package"}   # "platforms" sets continue-on-error per matrix leg (only Intel macOS is advisory)
    for job in doc["jobs"].values():
        assert all(isinstance(s, dict) and ("uses" in s or "run" in s) for s in job["steps"])


def test_platform_matrix_covers_windows_and_both_macos_architectures_and_marks_only_intel_advisory():
    ruamel = pytest.importorskip("ruamel.yaml")
    job = ruamel.YAML(typ="safe").load(CI.read_text())["jobs"]["platforms"]
    legs = {m["os"]: m["experimental"] for m in job["strategy"]["matrix"]["include"]}
    assert legs == {"windows-2022": False, "macos-14": False, "macos-15-intel": True}
    assert job["strategy"]["fail-fast"] is False
    assert any("-m \"not docker\"" in s.get("run", "") for s in job["steps"])
