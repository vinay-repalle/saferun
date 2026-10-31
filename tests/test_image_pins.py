"""Phase 5A: digest-pinned images, `saferun verify-images`, fail-closed digest checks, build-recipe pins/checksums."""
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from saferun import cli
from saferun.sandbox import DEFAULT_IMAGE, SandboxError, run_sandboxed
from saferun.sandbox import docker as dk
from saferun.sandbox import images, verify
from saferun.sandbox.profiles import NODE, PROFILES, PYTHON

ROOT = Path(__file__).resolve().parent.parent
ANALYZER = ROOT / "docker" / "analyzer"
OTHER = "sha256:" + "a" * 64
PY = images.PYTHON_IMAGE


def proc(rc=0, out="", err=""):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def fake_docker(monkeypatch, *, digests, image_id=PY.digest, rc=0, err=""):
    """Fake `docker image inspect`: --format {{.Id}} -> image_id; --format {{json .RepoDigests}} -> `digests` (raw JSON text)."""
    calls = []

    def fake(*args, timeout=None):
        calls.append(args)
        if rc:
            return proc(rc, "", err)
        return proc(0, (digests if "RepoDigests" in " ".join(args) else image_id) + "\n")
    monkeypatch.setattr(dk, "docker", fake)
    monkeypatch.setattr(dk, "check_local_daemon", lambda: None)
    return calls


# --- the pins themselves ---

def test_pins_are_wellformed_and_profiles_use_them():
    for img in images.PINNED_IMAGES:
        assert images.DIGEST_RE.match(img.digest)
        assert img.reference == f"{img.repository}:{img.tag}@{img.digest}"
        assert img.pull_reference == f"{img.repository}@{img.digest}"
        assert images.digest_of(img.reference) == img.digest
        dk.validate_image(img.reference)
    assert PYTHON.image == images.PYTHON_IMAGE.reference and NODE.image == images.NODE_IMAGE.reference
    assert DEFAULT_IMAGE == PYTHON.image
    assert all(images.digest_of(p.image) for p in PROFILES.values())  # no profile may fall back to a bare tag


def test_digest_of_and_repo_digests_parsing():
    assert images.digest_of("python:3.12-slim") is None
    assert images.digest_of("python@" + OTHER) == OTHER
    assert images.digest_of("python:3.12@sha256:short") is None
    assert images.repo_digests("null") == [] and images.repo_digests("[]") == []
    assert images.repo_digests(json.dumps(["python@" + OTHER])) == [OTHER]
    for bad in ('{"a":1}', '["not-a-digest"]', "[1]", '["python@sha256:zz"]', "not json"):
        with pytest.raises(ValueError):
            images.repo_digests(bad)


# --- fail closed in the sandbox ---

def test_resolve_image_accepts_matching_digest(monkeypatch):
    fake_docker(monkeypatch, digests=json.dumps([f"python@{PY.digest}"]))
    assert dk.resolve_image(PY.reference) == PY.digest


@pytest.mark.parametrize("digests", [json.dumps(["python@" + OTHER]), "[]", "null", "garbage", '{"x": 1}',
                                     json.dumps([f"python@{PY.digest}x"])])
def test_resolve_image_refuses_digest_mismatch_or_unverifiable(monkeypatch, digests):
    fake_docker(monkeypatch, digests=digests)
    with pytest.raises(SandboxError, match="digest"):
        dk.resolve_image(PY.reference)


def test_resolve_image_refuses_when_second_inspect_fails(monkeypatch):
    seq = iter([proc(0, PY.digest + "\n"), proc(1, "", "boom")])
    monkeypatch.setattr(dk, "docker", lambda *a, timeout=None: next(seq))
    with pytest.raises(SandboxError):
        dk.resolve_image(PY.reference)


def test_tag_only_reference_is_unchanged_single_inspect(monkeypatch):
    calls = fake_docker(monkeypatch, digests="[]")
    assert dk.resolve_image("python:3.12-slim") == PY.digest
    assert len(calls) == 1


def test_preflight_mismatch_raises_before_anything_is_created(monkeypatch):
    calls = fake_docker(monkeypatch, digests=json.dumps(["python@" + OTHER]))
    monkeypatch.setattr(dk, "daemon_info", lambda: {"OSType": "linux"})
    monkeypatch.setattr(dk, "daemon_controls", lambda info: [])
    with pytest.raises(SandboxError, match="digest mismatch"):
        dk.preflight(PY.reference)
    assert all(a[0] == "image" for a in calls)  # only inspections; no create/run


@pytest.mark.docker
def test_real_docker_refuses_a_wrong_digest_and_creates_nothing(tmp_path):
    def labelled():
        return dk.docker("ps", "-a", "-q", "--filter", "label=saferun.sandbox=1").stdout.split()
    before = labelled()
    (tmp_path / "main.py").write_text("print(1)\n")
    bad = f"{PY.repository}:{PY.tag}@{OTHER}"
    with pytest.raises(SandboxError):
        run_sandboxed(tmp_path, ["python", "main.py"], image=bad)
    assert labelled() == before


@pytest.mark.docker
def test_real_docker_runs_the_pinned_image(tmp_path):
    (tmp_path / "main.py").write_text("print('pinned')\n")
    r = run_sandboxed(tmp_path, ["python", "-I", "main.py"], image=PYTHON.image)
    assert r.exit_code == 0 and "pinned" in r.stdout
    # What `docker image inspect .Id` returns depends on the daemon's image store: the manifest digest with the containerd store, the config digest with
    # the classic overlay2 store (GitHub-hosted runners). So the run must use the image Docker reports as the pinned one, and the PINNED digest itself
    # is proven separately through RepoDigests, which is store-independent.
    ident = dk.docker("image", "inspect", "--format", "{{.Id}}", PYTHON.image).stdout.strip()
    assert r.image_id == ident
    have = dk.docker("image", "inspect", "--format", "{{json .RepoDigests}}", PYTHON.image).stdout.strip()
    assert PY.digest in images.repo_digests(have)


# --- verify_images ---

def test_verify_images_statuses(monkeypatch):
    fake_docker(monkeypatch, digests=json.dumps([f"python@{PY.digest}"]))
    c = verify.check_image(PY)
    assert c.ok and c.status == "verified" and c.detail == ""

    fake_docker(monkeypatch, digests=json.dumps(["python@" + OTHER]))
    c = verify.check_image(PY)
    assert not c.ok and c.status == "mismatch" and OTHER in c.detail

    fake_docker(monkeypatch, digests="[]")
    assert verify.check_image(PY).status == "mismatch"

    fake_docker(monkeypatch, digests="", rc=1, err="Error response from daemon: No such image: x")
    c = verify.check_image(PY)
    assert c.status == "missing" and f"docker pull {PY.pull_reference}" in c.detail

    fake_docker(monkeypatch, digests="", rc=1, err="permission denied")
    assert verify.check_image(PY).status == "error"

    fake_docker(monkeypatch, digests="<<<not json")
    assert verify.check_image(PY).status == "error"


def test_verify_images_never_pulls_or_runs(monkeypatch):
    calls = fake_docker(monkeypatch, digests=json.dumps([f"python@{img.digest}" for img in images.PINNED_IMAGES]))
    verify.verify_images()
    assert calls and all(a[:2] == ("image", "inspect") for a in calls)


def test_verify_images_propagates_unusable_docker(monkeypatch):
    def refuse():
        raise SandboxError("refusing non-local docker endpoint")
    monkeypatch.setattr(dk, "check_local_daemon", refuse)
    with pytest.raises(SandboxError):
        verify.verify_images()


# --- CLI ---

def checks(*statuses):
    return [verify.ImageCheck(i.name, i.reference, i.digest, s, "" if s == "verified" else "detail") for i, s in
            zip(images.PINNED_IMAGES, statuses)]


def test_cli_verify_images_exit_codes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "verify_images", lambda **kw: checks("verified", "verified"))
    assert cli.main(["verify-images"]) == 0
    assert "all pinned images verified" in capsys.readouterr().out
    for bad in ("missing", "mismatch", "error"):
        monkeypatch.setattr(cli, "verify_images", lambda bad=bad, **kw: checks("verified", bad))
        assert cli.main(["verify-images"]) == 1
        assert "NOT VERIFIED" in capsys.readouterr().out
    monkeypatch.setattr(cli, "verify_images", lambda **kw: (_ for _ in ()).throw(SandboxError("daemon down")))
    assert cli.main(["verify-images"]) == 70
    assert "daemon down" in capsys.readouterr().err


def test_cli_verify_images_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "verify_images", lambda **kw: checks("verified", "mismatch"))
    assert cli.main(["verify-images", "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == 1 and data["ok"] is False
    assert [i["status"] for i in data["images"]] == ["verified", "mismatch"]
    assert set(data["images"][0]) == {"name", "reference", "pinned_digest", "status", "detail"}


def test_cli_existing_behaviour_unchanged(capsys):
    assert cli.main([]) == 64                                  # no command: usage, as before
    assert cli.main(["scan", "/definitely/not/here"]) == 64   # scan still validates its path first
    capsys.readouterr()


@pytest.mark.docker
def test_cli_verify_images_real_docker(capsys):
    assert cli.main(["verify-images", "--base-only"]) == 0
    out = capsys.readouterr().out
    assert out.count("VERIFIED") == len(images.PINNED_IMAGES) and "analyzer" not in out


# --- build recipe: pins agree everywhere ---

def test_dockerfile_pins_match_images_module():
    text = (ANALYZER / "Dockerfile").read_text()
    froms = re.findall(r"^FROM (\S+)", text, re.M)
    assert froms == [images.PYTHON_IMAGE.reference]
    arg = lambda n: re.search(rf"^ARG {n}=(\S+)$", text, re.M).group(1)  # noqa: E731
    assert arg("SEMGREP_VERSION") == images.SEMGREP_VERSION
    assert arg("OSV_SCANNER_VERSION") == images.OSV_SCANNER_VERSION
    assert arg("OSV_SCANNER_SHA256") == images.OSV_SCANNER_LINUX_AMD64_SHA256
    assert "--require-hashes" in text and "fetch_verified.py" in text


def test_semgrep_lock_is_fully_hash_pinned():
    lines = [l for l in (ANALYZER / "semgrep-requirements.txt").read_text().splitlines() if l and not l.startswith("#")]
    assert len(lines) > 10
    names = []
    for l in lines:
        m = re.fullmatch(r"([a-z0-9-]+)==([0-9][^ ]*) --hash=sha256:[0-9a-f]{64}", l)
        assert m, l
        names.append(m.group(1))
    assert len(names) == len(set(names))
    assert f"semgrep=={images.SEMGREP_VERSION} " in "\n".join(l + " " for l in lines)


def test_build_script_verifies_images_first_and_never_pulls():
    py = (ANALYZER / "build.py").read_text()   # the recipe (build.sh only runs it)
    assert py.index('"verify-images"') < py.index('"build"') and '"--pull=false"' in py
    assert 'build.py' in (ANALYZER / "build.sh").read_text()


# --- fetch_verified (checksum verification used by the image build) ---

@pytest.fixture
def fv():
    spec = importlib.util.spec_from_file_location("fetch_verified", ANALYZER / "fetch_verified.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_fetch_verified_installs_only_on_match(fv, tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"tool-binary")
    good = hashlib.sha256(b"tool-binary").hexdigest()
    dest = tmp_path / "out" / "tool"
    dest.parent.mkdir()
    fv.fetch_verified(src.as_uri(), good, str(dest), allowed_schemes=("file",))
    assert dest.read_bytes() == b"tool-binary"
    if os.name == "posix":   # permission bits do not exist on Windows
        assert dest.stat().st_mode & 0o777 == 0o755


def test_fetch_verified_mismatch_leaves_nothing_and_keeps_old_file(fv, tmp_path):
    src = tmp_path / "src.bin"
    src.write_bytes(b"tampered")
    d = tmp_path / "out"
    d.mkdir()
    with pytest.raises(ValueError, match="checksum mismatch"):
        fv.fetch_verified(src.as_uri(), hashlib.sha256(b"original").hexdigest(), str(d / "tool"), allowed_schemes=("file",))
    assert list(d.iterdir()) == []
    (d / "tool").write_bytes(b"previous")
    with pytest.raises(ValueError):
        fv.fetch_verified(src.as_uri(), "0" * 64, str(d / "tool"), allowed_schemes=("file",))
    assert [p.name for p in d.iterdir()] == ["tool"] and (d / "tool").read_bytes() == b"previous"


def test_fetch_verified_rejects_bad_inputs(fv, tmp_path):
    src = tmp_path / "s"
    src.write_bytes(b"x")
    ok = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(ValueError, match="scheme"):
        fv.fetch_verified(src.as_uri(), ok, str(tmp_path / "d"))                    # file:// is not allowed by default
    with pytest.raises(ValueError, match="scheme"):
        fv.fetch_verified("http://example.invalid/x", ok, str(tmp_path / "d"))      # plain http is not allowed
    for bad in ("", "abc", ok.upper(), ok + "0"):
        with pytest.raises(ValueError, match="64"):
            fv.fetch_verified("https://example.invalid/x", bad, str(tmp_path / "d"))
    assert not (tmp_path / "d").exists()


def test_fetch_verified_size_cap(fv, tmp_path, monkeypatch):
    src = tmp_path / "s"
    src.write_bytes(b"x" * 100)
    monkeypatch.setattr(fv, "MAX_BYTES", 10)
    with pytest.raises(ValueError, match="exceeds"):
        fv.fetch_verified(src.as_uri(), hashlib.sha256(b"x" * 100).hexdigest(), str(tmp_path / "d"), allowed_schemes=("file",))
    assert not (tmp_path / "d").exists() and [p.name for p in tmp_path.iterdir()] == ["s"]


def test_fetch_verified_cli_exit_codes(tmp_path):
    script = str(ANALYZER / "fetch_verified.py")
    r = subprocess.run(["python3", "-I", script, "https://x"], capture_output=True, text=True)
    assert r.returncode == 64
    r = subprocess.run(["python3", "-I", script, "file:///etc/hostname", "0" * 64, str(tmp_path / "d")],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "FAILED" in r.stderr and not (tmp_path / "d").exists()


def test_mutation_guard_each_pin_is_actually_checked(monkeypatch):
    """If the digest comparison were removed, a mismatching image would be accepted; prove the test would notice."""
    fake_docker(monkeypatch, digests=json.dumps(["python@" + OTHER]))
    with pytest.raises(SandboxError):
        dk.resolve_image(PY.reference)
    monkeypatch.setattr(dk, "verify_pinned_digest", lambda image, digest: None)  # simulate the check being deleted
    assert dk.resolve_image(PY.reference) == PY.digest                            # ...and the mismatch would slip through
