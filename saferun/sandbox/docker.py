"""Thin, defensive wrappers over the docker CLI. Never uses a shell; args are lists.

Everything Docker returns is treated as untrusted input: unexpected output becomes a
SandboxError, never a raw exception and never a silent "success".
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .. import hostos
from .config import CONTAINER_LABEL, ControlStatus, SandboxError
from .controls import REQUIRED_DAEMON, daemon_controls
from .images import digest_of, repo_digests

DEFAULT_TIMEOUT = 30  # seconds per docker CLI call (module attribute so tests can shorten it)
# Plain image reference only: must not start with "-" (would be parsed as a docker option).
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def docker_bin() -> str:
    """Absolute path of the docker executable (PATH is trusted; see PROJECT.md)."""
    path = shutil.which("docker")
    if not path:
        raise SandboxError("docker executable not found on PATH")
    return os.path.abspath(path)


def docker(*args: str, timeout: float | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [docker_bin(), *args], capture_output=True, text=True, errors="replace",
            timeout=DEFAULT_TIMEOUT if timeout is None else timeout, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SandboxError(f"docker {args[0] if args else ''} failed: {e}") from e


def validate_image(image: str) -> str:
    if not isinstance(image, str) or not _IMAGE_RE.match(image):
        raise SandboxError(f"invalid image reference: {image!r}")
    return image


def check_local_daemon() -> None:
    """Refuse a remote daemon: the workspace is bind-mounted by host path, so a remote
    DOCKER_HOST / context would resolve that path on another machine."""
    host = os.environ.get("DOCKER_HOST")
    if host is None:
        r = docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
        if r.returncode != 0:
            raise SandboxError(f"cannot determine the docker endpoint: {r.stderr.strip()}")
        host = r.stdout.strip()
    if not hostos.docker_endpoint_is_local(host):
        only = "local named pipes (npipe:////./pipe/...)" if hostos.IS_WINDOWS else "unix:// sockets"
        raise SandboxError(f"refusing non-local docker endpoint {host!r} (only {only} are supported)")


def daemon_info() -> dict:
    r = docker("info", "--format", "{{json .}}")
    if r.returncode != 0:
        raise SandboxError(f"docker daemon unavailable: {r.stderr.strip()}")
    try:
        info = json.loads(r.stdout)
    except ValueError as e:
        raise SandboxError(f"unexpected `docker info` output: {e}") from e
    if not isinstance(info, dict):
        raise SandboxError("unexpected `docker info` output: not an object")
    return info


def resolve_image(image: str) -> str:
    """Image ID (sha256:...) of a *local* image. SafeRun never pulls implicitly."""
    r = docker("image", "inspect", "--format", "{{.Id}}", validate_image(image))
    if r.returncode != 0:
        raise SandboxError(f"image {image!r} not present locally (SafeRun never pulls implicitly)")
    image_id = r.stdout.strip()
    if not _IMAGE_ID_RE.match(image_id):
        raise SandboxError(f"unexpected image id from docker: {image_id!r}")
    pinned = digest_of(image)
    if pinned is not None:
        verify_pinned_digest(image, pinned)
    return image_id


def verify_pinned_digest(image: str, digest: str) -> None:
    """Fail closed unless the local image behind `image` really carries the pinned `digest`.

    Docker resolves `repo:tag@sha256:...` by digest, so a retagged image should not match at all; this second,
    independent check on what Docker reports (RepoDigests) guards against a daemon that resolves differently.
    """
    r = docker("image", "inspect", "--format", "{{json .RepoDigests}}", validate_image(image))
    if r.returncode != 0:
        raise SandboxError(f"image {image!r} not present locally (SafeRun never pulls implicitly)")
    try:
        have = repo_digests(r.stdout.strip())
    except ValueError as e:
        raise SandboxError(f"cannot verify the digest of image {image!r}: {e}") from e
    if digest not in have:
        raise SandboxError(f"image digest mismatch for {image!r}: pinned {digest}, local image has {have or 'no digest'}")


def preflight(image: str, allow_degraded: frozenset[str] = frozenset()) -> tuple[str, list[ControlStatus]]:
    """Fail closed before anything is created. Returns (image_id, daemon control statuses).

    A required daemon control that is missing raises, unless the caller explicitly lists it in
    `allow_degraded`; allowed degradations stay visible in the returned statuses.
    """
    validate_image(image)
    check_local_daemon()
    info = daemon_info()
    # The sandbox images are Linux images: a daemon in Windows-containers mode (or any other OS type) cannot run them as specified.
    if info.get("OSType") != "linux":
        raise SandboxError(f"the docker daemon runs {info.get('OSType')!r} containers; SafeRun needs Linux containers"
                           + (" (Docker Desktop: right-click the tray icon and choose 'Switch to Linux containers')" if hostos.IS_WINDOWS else ""))
    statuses = daemon_controls(info)
    for s in statuses:
        if s.name in REQUIRED_DAEMON and s.state != "verified" and s.name not in allow_degraded:
            raise SandboxError(f"required control {s.name} is {s.state}: {s.detail}")
    return resolve_image(image), statuses


def check_available(image: str) -> None:
    """Raise SandboxError unless Docker is usable for SafeRun with `image` (used by the test setup)."""
    preflight(image)


def container_exists(name: str) -> bool:
    """True/False for a definite answer; SandboxError if Docker could not tell us."""
    r = docker("inspect", "--type", "container", name)
    if r.returncode == 0:
        return True
    if "no such" in r.stderr.lower():
        return False
    raise SandboxError(f"cannot determine whether container {name} exists: {r.stderr.strip()}")


def inspect(name: str) -> dict:
    """`docker inspect` of a container; {} if it does not exist; SandboxError on odd output."""
    r = docker("inspect", "--type", "container", name)
    if r.returncode != 0:
        if "no such" in r.stderr.lower():
            return {}
        raise SandboxError(f"docker inspect {name} failed: {r.stderr.strip()}")
    try:
        data = json.loads(r.stdout)
        info = data[0]
    except (ValueError, IndexError, KeyError, TypeError) as e:
        raise SandboxError(f"unexpected `docker inspect` output for {name}: {e}") from e
    if not isinstance(info, dict):
        raise SandboxError(f"unexpected `docker inspect` output for {name}: not an object")
    return info


def force_remove(name: str) -> bool:
    """Kill and remove a container; True only if Docker confirms it is gone."""
    docker("rm", "-f", "-v", name, timeout=60)
    return not container_exists(name)


def leftover_containers() -> list[str]:
    r = docker("ps", "-a", "-q", "--filter", f"label={CONTAINER_LABEL}")
    return r.stdout.split()
