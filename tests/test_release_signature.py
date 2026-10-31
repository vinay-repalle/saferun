"""Phase 5E: cosign signature verification of the published analyzer image, and the release workflow that produces it.

cosign itself is NOT run for real here (it is not a dependency of the test suite and needs the network and a published image):
the verifier is exercised against fake `cosign` executables and injected runners. A real end-to-end check is
`saferun verify-images --signature` after the first release (docs/release-images.md).
"""
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from saferun import cli, hostos
from saferun.sandbox import images as im
from saferun.sandbox import signature as sig
from saferun.sandbox.signature import CosignMissing, SignatureError

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release-analyzer.yml"
DIGEST = "sha256:" + "a" * 64
REL = im.AnalyzerRelease(im.ANALYZER_REGISTRY_REPOSITORY, DIGEST, "2026-11-01")


def payload(digest=DIGEST, repo=im.ANALYZER_REGISTRY_REPOSITORY):
    return json.dumps([{"critical": {"identity": {"docker-reference": repo}, "image": {"docker-manifest-digest": digest},
                                     "type": "cosign container image signature"}, "optional": {"Issuer": im.GITHUB_OIDC_ISSUER}}])


def runner(stdout="", stderr="", rc=0, calls=None):
    def run(argv, **kw):
        if calls is not None:
            calls.append((argv, kw))
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)
    return run


def verify(rel=REL, **kw):
    kw.setdefault("which", lambda: "/usr/bin/cosign")
    return sig.verify_release_signature(rel, **kw)


# ------------------------------------------------------------------------------------------ the command
def test_command_is_exactly_the_documented_cosign_verify():
    calls = []
    assert verify(run=runner(payload(), calls=calls)) == 1
    argv, kw = calls[0]
    assert argv == ["/usr/bin/cosign", "verify", "--certificate-identity-regexp", im.ANALYZER_SIGNER_IDENTITY_REGEXP,
                    "--certificate-oidc-issuer", im.GITHUB_OIDC_ISSUER, "--output", "json", f"{im.ANALYZER_REGISTRY_REPOSITORY}@{DIGEST}"]
    assert kw.get("shell") is not True and kw["stdin"] == subprocess.DEVNULL and kw["timeout"] == sig.COSIGN_TIMEOUT_S


def test_cosign_gets_a_minimal_environment_and_a_private_home(monkeypatch):
    for k, v in {"GITHUB_TOKEN": "t", "AWS_SECRET_ACCESS_KEY": "s", "OPENAI_API_KEY": "k", "SSH_AUTH_SOCK": "/x", "HTTPS_PROXY": "http://p"}.items():
        monkeypatch.setenv(k, v)
    calls = []
    verify(run=runner(payload(), calls=calls))
    env = calls[0][1]["env"]
    allowed = set(sig._ENV_KEEP) | {"HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"} | set(hostos.base_env_names()) | set(hostos.private_home_env("x"))
    assert set(env) <= allowed
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env and "SSH_AUTH_SOCK" not in env
    assert env["HTTPS_PROXY"] == "http://p"                           # network settings are needed and harmless
    assert env["HOME"] != os.path.expanduser("~") and not os.path.exists(env["HOME"])   # private, and removed afterwards
    assert calls[0][1]["cwd"] == env["HOME"]


@pytest.mark.parametrize("rel", [
    im.AnalyzerRelease(im.ANALYZER_REGISTRY_REPOSITORY, "sha256:123", "x"),
    im.AnalyzerRelease(im.ANALYZER_REGISTRY_REPOSITORY, DIGEST, "x", signer_identity_regexp=""),
    im.AnalyzerRelease(im.ANALYZER_REGISTRY_REPOSITORY, DIGEST, "x", oidc_issuer=""),
    im.AnalyzerRelease("-oops", DIGEST, "x"),
    im.AnalyzerRelease("repo with space", DIGEST, "x"),
])
def test_a_malformed_release_is_refused_before_cosign_runs(rel):
    calls = []
    with pytest.raises(SignatureError):
        verify(rel, run=runner(payload(), calls=calls))
    assert calls == []


# ------------------------------------------------------------------------------------------- failures
def test_missing_cosign_is_its_own_error_and_runs_nothing():
    calls = []
    with pytest.raises(CosignMissing, match="not installed"):
        verify(which=lambda: None, run=runner(payload(), calls=calls))
    assert calls == []
    assert issubclass(CosignMissing, SignatureError)


def test_a_failing_verification_is_an_error_with_a_bounded_message():
    with pytest.raises(SignatureError, match=r"exit 1.*none of the expected identities matched") as e:
        verify(run=runner(stderr="Error: " + "x" * 5000 + " none of the expected identities matched", rc=1))
    assert len(str(e.value)) < 700


def test_timeout_and_start_failures_are_errors():
    def hung(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw["timeout"])

    def broken(argv, **kw):
        raise PermissionError("denied")
    with pytest.raises(SignatureError, match="did not finish"):
        verify(run=hung)
    with pytest.raises(SignatureError, match="could not be started"):
        verify(run=broken)


@pytest.mark.parametrize("out", [
    "", "not json", "{}", "null", "[]", "[1, 2]", "[{}]", '[{"critical": {}}]',
    payload(digest="sha256:" + "b" * 64),                                  # a signature for a different image
    payload(repo="ghcr.io/someone-else/saferun-analyzer"),                 # same digest, different repository
    "[" * 5000,
])
def test_cosign_success_is_not_enough_the_payload_must_name_this_image(out):
    with pytest.raises(SignatureError):
        verify(run=runner(out))


def test_oversized_output_is_refused():
    with pytest.raises(SignatureError, match="large"):
        verify(run=runner(payload() + " " * sig.MAX_OUTPUT))


def test_extra_signatures_for_other_images_do_not_count():
    data = json.loads(payload()) + json.loads(payload(digest="sha256:" + "c" * 64))
    assert verify(run=runner(json.dumps(data))) == 1


def test_a_real_process_is_run_without_a_shell(tmp_path, monkeypatch):
    if sys.platform == "win32":   # no sh: a .bat that runs a Python body (cosign.bat is found through PATHEXT)
        body = tmp_path / "fake_cosign.py"
        fake = tmp_path / "cosign.bat"
        fake.write_text(f'@"{sys.executable}" "{body}" %*\r\n')

        def write(py):
            body.write_text(py)
        ok = f"import sys\nif sys.argv[1] != 'verify':\n    sys.exit(9)\nsys.stdout.write({payload()!r})\n"
        bad = "import sys\nsys.stderr.write('no matching signatures')\nsys.exit(1)\n"
    else:
        fake = tmp_path / "cosign"

        def write(sh):
            fake.write_text(sh)
            fake.chmod(0o755)
        ok = "#!/bin/sh\n[ \"$1\" = verify ] || exit 9\ncat <<'EOF'\n" + payload() + "\nEOF\n"
        bad = "#!/bin/sh\necho 'no matching signatures' >&2\nexit 1\n"
    write(ok)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    assert os.path.normcase(sig.find_cosign()) == os.path.normcase(str(fake))
    assert sig.verify_release_signature(REL) == 1
    write(bad)
    with pytest.raises(SignatureError, match="no matching signatures"):
        sig.verify_release_signature(REL)


def test_find_cosign_reports_none_when_absent(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    assert sig.find_cosign() is None


# ------------------------------------------------------------------------------- the identity expression
GOOD = "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v{}"


@pytest.mark.parametrize("version", ["1", "1.0", "1.2.3", "20.10"])
def test_identity_accepts_release_tags(version):
    assert re.search(im.ANALYZER_SIGNER_IDENTITY_REGEXP, GOOD.format(version))


@pytest.mark.parametrize("identity", [
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/heads/main",                  # a branch
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/pull/7/merge",                # a pull request
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/v1.0",                   # other tag
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v",
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1.",
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1-rc1",
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1/../x",
    "https://github.com/vinay-repalle/saferun/.github/workflows/other.yml@refs/tags/analyzer-v1",                       # other workflow
    "https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml.evil@refs/tags/analyzer-v1",
    "https://github.com/vinay-repalle/other/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1",              # other repository
    "https://github.com/Evil/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1",
    # signatures made under the repository this project was copied from must never be accepted here (both spellings of the owner name)
    "https://github.com/Vinay-Ampera/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1.0.0",
    "https://github.com/vinay-ampera/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1.0.0",
    "https://github.com/vinay-repallee/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1",
    "http://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1",
    "xhttps://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v1",
    GOOD.format("1") + "\n", GOOD.format("1") + " extra", "",
])
def test_identity_rejects_everything_else(identity):
    assert not re.fullmatch(im.ANALYZER_SIGNER_IDENTITY_REGEXP, identity)


def test_repository_constant_and_issuer():
    assert im.ANALYZER_REGISTRY_REPOSITORY == im.ANALYZER_REGISTRY_REPOSITORY.lower()           # ghcr.io requires lowercase
    assert im.ANALYZER_REGISTRY_REPOSITORY.startswith("ghcr.io/") and im.GITHUB_OIDC_ISSUER == "https://token.actions.githubusercontent.com"
    assert REL.reference == f"{im.ANALYZER_REGISTRY_REPOSITORY}@{DIGEST}"


# --------------------------------------------------------------------------------- the release workflow
@pytest.fixture(scope="module")
def wf() -> str:
    return WORKFLOW.read_text()


def test_workflow_file_name_matches_the_signer_identity(wf):
    assert WORKFLOW.name == "release-analyzer.yml" and "release-analyzer\\.yml" in im.ANALYZER_SIGNER_IDENTITY_REGEXP
    assert "vinay-repalle/saferun" in im.ANALYZER_SIGNER_IDENTITY_REGEXP.replace("\\", "")


def test_workflow_runs_only_on_analyzer_tags(wf):
    on = wf.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
    assert re.fullmatch(r'\s*push:\n\s*tags: \["analyzer-v\*"\]\s*', on)
    for forbidden in ("pull_request", "workflow_dispatch", "branches", "schedule", "workflow_run", "issue_comment"):
        assert forbidden not in on


def test_workflow_permissions_are_minimal(wf):
    top = wf.split("\npermissions:\n", 1)[1].split("\n\n", 1)[0]
    assert top.strip() == "contents: read"
    job = wf.split("    permissions:\n", 1)[1].split("    steps:", 1)[0]
    granted = dict(re.findall(r"^\s+([a-z-]+): (\w+)", job, re.M))
    assert granted == {"contents": "read", "packages": "write", "id-token": "write"}


def test_every_action_is_pinned_to_a_commit(wf):
    uses = re.findall(r"^\s*(?:- )?uses: (\S+)", wf, re.M)
    assert len(uses) == 5
    assert all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses


def test_workflow_publishes_the_repository_the_client_expects(wf):
    assert f"IMAGE: {im.ANALYZER_REGISTRY_REPOSITORY}" in wf
    assert "platforms: linux/amd64" in wf and "provenance: false" in wf and "sbom: false" in wf


def test_workflow_signs_the_digest_not_a_tag_and_verifies_with_the_clients_expression(wf):
    assert 'cosign sign --yes "$IMAGE@$DIGEST"' in wf
    assert not re.search(r"cosign sign[^\n]*:\$|cosign sign[^\n]*ref_name", wf)
    assert "ANALYZER_SIGNER_IDENTITY_REGEXP" in wf and "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in wf
    assert re.search(r"cosign-release: v\d+\.\d+\.\d+", wf)


def test_workflow_checks_tag_name_and_main_ancestry_before_building(wf):
    assert wf.index("is-ancestor") < wf.index("uses: docker/build-push-action") < wf.index("cosign sign --yes")
    assert "analyzer-v[0-9]+" in wf


def test_workflow_tests_the_image_before_logging_in_or_pushing(wf):
    """The image is built locally, smoke-tested, and only then pushed (the very same image); signing comes last, and a wrong identity is refused."""
    assert "push: false" in wf and "load: true" in wf and "push: true" not in wf
    order = [wf.index(s) for s in ("uses: docker/build-push-action", "Smoke-test the exact image", "uses: docker/login-action",
                                   'docker push "$IMAGE:$TAG"', "cosign sign --yes", "Check that a wrong signer identity is refused")]
    assert order == sorted(order)
    smoke = wf.split("Smoke-test the exact image", 1)[1].split("uses: docker/login-action", 1)[0]
    for needle in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--user 65534:65534",
                   "saferun.rules.sha256", "semgrep scan --json", "could reach the network"):
        assert needle in smoke, needle
    assert "cosign accepted an identity it must refuse" in wf
    assert "65534:65534" in smoke and "pushed but NOT signed and verified" in wf      # default user checked; a failure after the push is reported


def test_workflow_signs_the_digest_read_back_from_the_pushed_image(wf):
    assert "steps.push.outputs.digest" in wf and "steps.build.outputs.digest" not in wf
    assert "RepoDigests" in wf


def test_workflow_uses_no_secret_but_the_github_token(wf):
    assert set(re.findall(r"secrets\.(\w+)", wf)) == {"GITHUB_TOKEN"}
    assert "persist-credentials: false" in wf


def test_workflow_stages_the_same_files_as_build_script(wf):
    sh = (ROOT / "docker" / "analyzer" / "build.py").read_text(encoding="utf-8")
    for name in ("Dockerfile", "fetch_verified.py", "semgrep-requirements.txt", "python.yml"):
        assert name in wf and name in sh
    assert "RULES_SHA256=" in wf and "RULES_SHA256=" in sh
    # third-party notices and license texts are staged by both, and copied into the image by the Dockerfile
    for name in ("THIRD_PARTY_NOTICES.md", "licenses", "LICENSE"):
        assert name in wf and name in sh
    df = (ROOT / "docker" / "analyzer" / "Dockerfile").read_text(encoding="utf-8")
    assert "/usr/share/doc/saferun-analyzer/LICENSE" in df and "/usr/share/doc/saferun-analyzer/THIRD_PARTY_NOTICES.md" in df and "/usr/share/doc/saferun-analyzer/licenses/" in df
    lic = ROOT / "docker" / "analyzer" / "licenses"
    assert (ROOT / "docker" / "analyzer" / "THIRD_PARTY_NOTICES.md").stat().st_size > 1000
    assert "Apache License" in (lic / "osv-scanner-v2.7.0-LICENSE").read_text(encoding="utf-8") and "GNU LESSER GENERAL PUBLIC LICENSE" in (lic / "semgrep-LICENSE").read_text(encoding="utf-8")
    # the Go dependency inventory of the pinned OSV-Scanner binary: one table row per module, and a license text section for every module
    inv = (lic / "osv-scanner-v2.7.0-go-modules.md").read_text(encoding="utf-8")
    texts = (lic / "osv-scanner-v2.7.0-go-module-licenses.txt").read_text(encoding="utf-8")
    rows = [l for l in inv.splitlines() if l.startswith("| ") and not l.startswith(("| Module", "|---"))]
    assert len(rows) == 191 and all(len(r.split("|")) == 6 for r in rows)
    for r in rows:
        module, version = (c.strip() for c in r.split("|")[1:3])
        assert f"\n{module} {version} -- " in texts, module
    assert "Go standard library and runtime" in texts and "MPL-2.0" in inv
    assert "licenses/osv-scanner-v2.7.0-go-modules.md" in (ROOT / "docker" / "analyzer" / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert "osv-scanner-v2.7.0-go-module-licenses.txt" in wf


# ------------------------------------------------------------------------------------------ command line
def test_verify_images_signature_without_a_release_fails_closed(monkeypatch, capsys):
    monkeypatch.setattr(cli, "verify_images", lambda *a, **k: [])
    monkeypatch.setattr(im, "ANALYZER_RELEASE", None)
    assert cli.main(["verify-images", "--signature", "--format", "json"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is False and doc["signature"]["ok"] is False and "no analyzer release" in doc["signature"]["detail"]


def test_verify_images_signature_reports_success_and_failure(monkeypatch, capsys):
    monkeypatch.setattr(cli, "verify_images", lambda *a, **k: [])
    monkeypatch.setattr(im, "ANALYZER_RELEASE", REL)
    monkeypatch.setattr(sig, "verify_release_signature", lambda rel: 1)
    assert cli.main(["verify-images", "--signature"]) == 0
    assert "VERIFIED  cosign signature" in capsys.readouterr().out

    def bad(rel):
        raise SignatureError("cosign could not verify\nFORGED LINE")
    monkeypatch.setattr(sig, "verify_release_signature", bad)
    assert cli.main(["verify-images", "--signature"]) == 1
    out = capsys.readouterr().out
    assert "FAILED    cosign signature" in out and "\nFORGED LINE" not in out and "NOT VERIFIED" in out


def test_verify_images_without_the_flag_does_not_touch_cosign(monkeypatch, capsys):
    monkeypatch.setattr(cli, "verify_images", lambda *a, **k: [])
    monkeypatch.setattr(sig, "verify_release_signature", lambda rel: (_ for _ in ()).throw(AssertionError("must not be called")))
    assert cli.main(["verify-images", "--format", "json"]) == 0
    assert "signature" not in json.loads(capsys.readouterr().out)


def test_init_build_local_flag_is_passed_to_setup(monkeypatch):
    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

        def say(self, *a): pass

        def run(self, chosen, **kw):
            seen["chosen"] = chosen
            return 0
    monkeypatch.setattr(cli.setup_mod, "Setup", Fake)
    assert cli.main(["init", "--only", "analyzer", "--build-local"]) == 0
    assert seen["build_local"] is True and seen["chosen"] == ["analyzer"]
    assert cli.main(["init", "--only", "analyzer"]) == 0 and seen["build_local"] is False


def test_no_unsigned_release_can_be_recorded():
    rel = im.ANALYZER_RELEASE
    assert rel is None or (rel.signer_identity_regexp and rel.oidc_issuer)


def test_workflow_is_valid_yaml_with_the_expected_shape():
    """GitHub rejects the whole file on a YAML error (e.g. an unquoted `: ` in a step name), so parse it for real."""
    ruamel = pytest.importorskip("ruamel.yaml")      # installed with Semgrep in the dev venv; not a declared dependency
    doc = ruamel.YAML(typ="safe").load(WORKFLOW.read_text())
    assert doc["on"]["push"]["tags"] == ["analyzer-v*"] and set(doc["on"]) == {"push"}
    steps = doc["jobs"]["release"]["steps"]
    assert len(steps) == 14 and all(isinstance(s, dict) and ("uses" in s or "run" in s) for s in steps)
    assert all(isinstance(s.get("name", ""), str) for s in steps)
