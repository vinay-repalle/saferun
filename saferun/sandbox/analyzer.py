"""The analyzer image (Phase 5B): where Semgrep and OSV-Scanner run, instead of on the host.

The image is built locally by docker/analyzer/build.sh, which records its image ID in a lock file. Before every use
`verify_analyzer_image` checks that
  * the lock file exists and the local image `saferun-analyzer:local` has exactly that ID (a retagged or rebuilt image is refused),
  * the labels baked in at build time equal the pins in images.py (tool versions) and the SHA-256 of the rules file in this checkout.
The lock file is only trusted if it and its directory are owned by the current user and owner-only (0600 / 0700), and it is opened
without following symlinks. It returns the image ID, and callers run the sandbox *by that ID*, so the image cannot change between check and use.
Limits: the lock is a local file, not a registry digest or a signature. Whoever can write it AND re-tag or replace the image (the same user,
root, or any member of the `docker` group, which is root-equivalent) can substitute an image; the labels checked below are set by whoever
builds the image and prove nothing on their own.
There is no fallback: any problem raises, and the engine reports the check as unavailable/error, never as clean.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

from . import docker as dk
from .config import SandboxError
from .images import OSV_SCANNER_VERSION, SEMGREP_VERSION

ANALYZER_REPO_TAG = "saferun-analyzer:local"
SEMGREP_EXE = "/usr/local/bin/semgrep"
OSV_EXE = "/usr/local/bin/osv-scanner"
RULES_PATH = "/opt/saferun/rules/python.yml"
_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class AnalyzerUnavailable(SandboxError):
    """The analyzer image is not built or not usable (no host fallback exists)."""


class AnalyzerIntegrityError(SandboxError):
    """The image present locally is not the one that was built and locked (digest, tool or rules mismatch)."""


def lock_path() -> Path:
    env = os.environ.get("SAFERUN_ANALYZER_LOCK")
    if env:
        return Path(env)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "saferun" / "analyzer-image-id"


def rules_sha256() -> str:
    from ..engine.semgrep import RULES_FILE   # local import: the engine imports this module
    return hashlib.sha256(RULES_FILE.read_bytes()).hexdigest()


def _lock_problem(p: Path) -> str | None:
    """Why the lock file's directory or the file itself cannot be trusted, or None. Both must belong to the current user and be
    owner-only (directory 0700, file 0600), and neither may be a symlink (only the immediate parent directory is examined)."""
    me = os.geteuid()
    try:
        dst = os.lstat(p.parent)
    except OSError as e:
        return f"cannot examine the lock directory {p.parent}: {e}"
    if not stat.S_ISDIR(dst.st_mode):
        return f"the lock directory {p.parent} is not a real directory (a symlink?)"
    if dst.st_uid != me:
        return f"the lock directory {p.parent} is owned by uid {dst.st_uid}, not by the current user ({me})"
    if dst.st_mode & 0o077:
        return f"the lock directory {p.parent} is accessible to others (mode {stat.S_IMODE(dst.st_mode):04o}); run: chmod 700 {p.parent}"
    return None


def _read_lock() -> str:
    p = lock_path()
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise AnalyzerUnavailable(f"the analyzer image has not been installed (no lock file at {p}); run `saferun init --only analyzer`") from None
    except OSError as e:
        raise AnalyzerIntegrityError(f"cannot open the analyzer lock file {p} (a symlink?): {e}") from None
    try:
        st = os.fstat(fd)
        problem = None
        if not stat.S_ISREG(st.st_mode):
            problem = "is not a regular file"
        elif st.st_uid != os.geteuid():
            problem = f"is owned by uid {st.st_uid}, not by the current user"
        elif st.st_mode & 0o077:
            problem = f"is accessible to others (mode {stat.S_IMODE(st.st_mode):04o}); run: chmod 600 {p}"
        if problem is None:
            dir_problem = _lock_problem(p)
            if dir_problem:
                raise AnalyzerIntegrityError(f"analyzer lock not trusted: {dir_problem}")
        else:
            raise AnalyzerIntegrityError(f"analyzer lock file {p} {problem}; it is not trusted")
        text = os.read(fd, 4096).decode("ascii", "replace").strip()
    finally:
        os.close(fd)
    if not _ID_RE.match(text):
        raise AnalyzerIntegrityError(f"analyzer lock file {p} is malformed")
    return text


def write_lock(image_id: str) -> Path:
    """Record `image_id` as the trusted analyzer image (used by docker/analyzer/build.sh). Creates the lock directory (0700) if it
    does not exist; an EXISTING directory is never chmod'ed, it must already be owner-only. The file is written 0600, atomically."""
    if not isinstance(image_id, str) or not _ID_RE.match(image_id):
        raise SandboxError(f"not an image ID: {image_id!r}")
    p = lock_path()
    if p.parent.is_symlink():
        raise SandboxError(f"refusing to write the lock through a symlinked directory: {p.parent}")
    if not p.parent.exists():
        p.parent.parent.mkdir(parents=True, exist_ok=True)
        p.parent.mkdir(mode=0o700)
        os.chmod(p.parent, 0o700)
    problem = _lock_problem(p)
    if problem:
        raise SandboxError(f"not writing the analyzer lock: {problem}")
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".lock-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(image_id + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return p


def inspect_analyzer_tag() -> tuple[str, dict]:
    """(image ID, labels) of the local `saferun-analyzer:local` image. Raises AnalyzerUnavailable / AnalyzerIntegrityError."""
    r = dk.docker("image", "inspect", "--format", "{{json .}}", ANALYZER_REPO_TAG)
    if r.returncode != 0:
        if "no such image" in r.stderr.lower():
            raise AnalyzerUnavailable(f"image {ANALYZER_REPO_TAG} is not present locally; run `saferun init --only analyzer`")
        raise AnalyzerUnavailable(f"cannot inspect {ANALYZER_REPO_TAG}: {r.stderr.strip()[:200]}")
    try:
        info = json.loads(r.stdout)
        image_id = info["Id"]
        labels = (info.get("Config") or {}).get("Labels") or {}
        if not isinstance(image_id, str) or not isinstance(labels, dict):
            raise TypeError("unexpected shape")
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise AnalyzerIntegrityError(f"unexpected `docker image inspect` output for {ANALYZER_REPO_TAG}: {e}") from None
    return image_id, labels


def check_labels(labels: dict) -> None:
    """The labels baked in at build time must equal this checkout's pins (tool versions) and rules hash."""
    expected = {"saferun.analyzer": "1", "saferun.semgrep.version": SEMGREP_VERSION,
                "saferun.osv-scanner.version": OSV_SCANNER_VERSION, "saferun.rules.sha256": rules_sha256()}
    wrong = [k for k, v in expected.items() if labels.get(k) != v]
    if wrong:
        raise AnalyzerIntegrityError(f"analyzer image labels do not match the pinned tools/rules: {', '.join(wrong)}; rebuild it")


def verify_analyzer_image() -> str:
    """Return the verified image ID or raise AnalyzerUnavailable / AnalyzerIntegrityError."""
    locked = _read_lock()
    image_id, labels = inspect_analyzer_tag()
    if image_id != locked:
        raise AnalyzerIntegrityError(
            f"analyzer image ID mismatch: {ANALYZER_REPO_TAG} is {image_id}, the build lock says {locked}; rebuild or investigate")
    check_labels(labels)
    return image_id
