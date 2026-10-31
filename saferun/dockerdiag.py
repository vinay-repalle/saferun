"""Classify why Docker is (not) usable and say what to do about it, per platform. Read-only: it only runs `docker version/info`."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from . import hostos
from .sandbox import SandboxError
from .sandbox import docker as dk

OK, NOT_INSTALLED, DAEMON_DOWN, PERMISSION, REMOTE, UNKNOWN = "ok", "not-installed", "daemon-not-running", "permission-denied", "remote", "unknown"

INSTALL_URLS = {
    "linux": "https://docs.docker.com/engine/install/ (then: sudo usermod -aG docker $USER, and log in again)",
    "macos": "https://docs.docker.com/desktop/setup/install/mac-install/ (Docker Desktop, or Colima/OrbStack; start it once)",
    "windows": "https://docs.docker.com/desktop/setup/install/windows-install/ (Docker Desktop with the WSL 2 backend, Linux containers)",
}


@dataclass(frozen=True)
class DockerDiagnosis:
    state: str
    detail: str
    guidance: str = ""

    @property
    def ok(self) -> bool:
        return self.state == OK

    def message(self) -> str:
        return self.detail + (f". {self.guidance}" if self.guidance else "")


def platform_name() -> str:
    return "windows" if hostos.IS_WINDOWS else "macos" if hostos.IS_MACOS else "linux"


def diagnose(*, which=shutil.which, run=subprocess.run, check_local=dk.check_local_daemon, platform: str | None = None) -> DockerDiagnosis:
    """Never raises."""
    plat = platform or platform_name()
    if not which("docker"):
        return DockerDiagnosis(NOT_INSTALLED, "Docker is not installed (no `docker` on PATH)", f"Install it: {INSTALL_URLS[plat]}")
    try:
        r = run([which("docker"), "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, errors="replace",
                timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return DockerDiagnosis(UNKNOWN, f"`docker info` did not complete: {e}", "Check that Docker is running")
    if r.returncode != 0:
        err = " ".join((r.stderr or "").split())
        low = err.lower()
        if "permission denied" in low:
            fix = ("Add your user to the docker group (sudo usermod -aG docker $USER) and log in again" if plat == "linux"
                   else "Make sure your user may use Docker (Docker Desktop is running under your account)")
            return DockerDiagnosis(PERMISSION, "Docker is installed but your user may not use it (permission denied)", fix)
        start = {"linux": "Start it: sudo systemctl start docker", "macos": "Start Docker Desktop (or Colima/OrbStack)",
                 "windows": "Start Docker Desktop and wait until it reports it is running"}[plat]
        if any(w in low for w in ("cannot connect", "is the docker daemon running", "error during connect", "pipe", "no such file")):
            return DockerDiagnosis(DAEMON_DOWN, "Docker is installed but its daemon is not running", start)
        return DockerDiagnosis(UNKNOWN, f"`docker info` failed: {err[:200] or 'no message'}", start)
    try:
        check_local()
    except SandboxError as e:
        return DockerDiagnosis(REMOTE, str(e), "SafeRun needs a local Docker daemon (unset DOCKER_HOST / use the default context)")
    return DockerDiagnosis(OK, f"Docker {r.stdout.strip() or '?'} is running and local")
