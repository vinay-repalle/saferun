"""Removal of OLD SafeRun analyzer images: by `saferun init` right after it installed and locked a new one, and by `saferun cleanup`.

Every guard is checked again right before each delete, and all of them must hold:
  * the ID is a full image ID (sha256:<64 hex>);
  * it is not protected: not the image in the trusted analyzer lock, not the image the `saferun-analyzer:local` tag points to, not the
    pinned python sandbox image, not an ID the caller asks to keep. If any of these cannot be determined (Docker error, a lock file that
    exists but is not trusted), nothing is deleted;
  * the image carries the label saferun.analyzer=1 (other images, including the python image, never have it);
  * no container, running or stopped, uses it (`docker ps -a --filter ancestor=<id>`);
  * the delete is `docker rmi <id>` WITHOUT -f, so Docker itself also refuses an image that is in use or still has more than one name.
The python sandbox image is never deleted automatically. A refused or failed delete is returned as text; `remove_old_image` never raises.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from . import docker as dk
from .analyzer import ANALYZER_LABEL, ANALYZER_REPO_TAG, AnalyzerUnavailable, _read_lock
from .config import SandboxError
from .images import PYTHON_IMAGE

_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GONE = "it is no longer present"


@dataclass(frozen=True)
class OldImage:
    image_id: str
    size: int | None     # bytes as Docker reports them; None if unknown
    problem: str = ""    # non-empty: it would be kept, and why

    @property
    def short(self) -> str:
        return short_id(self.image_id)


def short_id(image_id: str) -> str:
    return image_id[:19] + "…"


def _id_of(ref: str) -> str | None:
    """Image ID behind `ref`; None if no such image. Raises SandboxError when Docker cannot tell."""
    r = dk.docker("image", "inspect", "--format", "{{.Id}}", dk.validate_image(ref))
    if r.returncode != 0:
        if "no such image" in r.stderr.lower():
            return None
        raise SandboxError(f"cannot inspect {ref}: {r.stderr.strip()[:200]}")
    image_id = r.stdout.strip()
    if not _ID_RE.match(image_id):
        raise SandboxError(f"unexpected image ID for {ref}: {image_id[:80]!r}")
    return image_id


def protected_ids(keep=()) -> set[str]:
    """IDs that are never deleted. Raises SandboxError if one of them cannot be determined."""
    ids = {i for i in keep if i}
    try:
        ids.add(_read_lock())
    except AnalyzerUnavailable:
        pass                                      # no lock file at all: nothing is locked
    except SandboxError as e:
        raise SandboxError(f"the analyzer lock cannot be trusted, so the current image is unknown and nothing is deleted: {e}") from None
    for ref in (ANALYZER_REPO_TAG, PYTHON_IMAGE.reference):
        found = _id_of(ref)
        if found:
            ids.add(found)
    return ids


def _facts(image_id: str) -> tuple[dict, int | None] | None:
    """(labels, size in bytes) of a local image; None if it does not exist. Raises SandboxError on a Docker error or odd output."""
    r = dk.docker("image", "inspect", "--format", "{{json .Config.Labels}}\t{{.Size}}", image_id)
    if r.returncode != 0:
        if "no such image" in r.stderr.lower():
            return None
        raise SandboxError(f"cannot inspect image {short_id(image_id)}: {r.stderr.strip()[:200]}")
    raw_labels, _, raw_size = r.stdout.strip().partition("\t")
    try:
        labels = json.loads(raw_labels) or {}
    except ValueError:
        raise SandboxError(f"unexpected `docker image inspect` output for {short_id(image_id)}") from None
    if not isinstance(labels, dict):
        raise SandboxError(f"unexpected labels for {short_id(image_id)}")
    try:
        size = int(raw_size)
    except ValueError:
        size = None
    return labels, size


def _containers_using(image_id: str) -> list[str]:
    r = dk.docker("ps", "-a", "-q", "--no-trunc", "--filter", f"ancestor={image_id}")
    if r.returncode != 0:
        raise SandboxError(f"cannot list the containers that use {short_id(image_id)}: {r.stderr.strip()[:200]}")
    return r.stdout.split()


def removal_problem(image_id: str, protected: set[str]) -> tuple[str, int | None]:
    """("", size) when every guard holds, otherwise (why it must be kept, size). Raises SandboxError when Docker cannot answer."""
    if not isinstance(image_id, str) or not _ID_RE.match(image_id):
        return "not a full image ID", None
    if image_id in protected:
        return "it is the current analyzer image or the python sandbox image", None
    facts = _facts(image_id)
    if facts is None:
        return GONE, None
    labels, size = facts
    if labels.get(ANALYZER_LABEL) != "1":
        return f"it has no {ANALYZER_LABEL} label (not a SafeRun analyzer image)", size
    users = _containers_using(image_id)
    if users:
        return f"it is used by {len(users)} container(s)", size
    return "", size


def remove_old_image(image_id: str, keep=()) -> tuple[bool, str]:
    """Delete one old analyzer image if every guard holds. Returns (removed, reason it was kept or ""). Never raises."""
    try:
        problem, _ = removal_problem(image_id, protected_ids(keep))
        if problem:
            return False, problem
        r = dk.docker("rmi", image_id, timeout=120)
    except SandboxError as e:
        return False, str(e)
    if r.returncode != 0:
        return False, "docker rmi refused: " + (r.stderr.strip().splitlines() or ["no reason given"])[-1][:200]
    return True, ""


def find_old_images(keep=()) -> list[OldImage]:
    """Local SafeRun analyzer images other than the protected ones, each with the reason it would be kept (empty if removable).
    Raises SandboxError when Docker cannot be asked."""
    r = dk.docker("image", "ls", "-q", "--no-trunc", "--filter", f"label={ANALYZER_LABEL}=1")
    if r.returncode != 0:
        raise SandboxError(f"cannot list images: {r.stderr.strip()[:200]}")
    ids: list[str] = []
    for line in r.stdout.split():
        if not _ID_RE.match(line):
            raise SandboxError(f"unexpected `docker image ls` output: {line[:80]!r}")
        if line not in ids:
            ids.append(line)
    protected = protected_ids(keep)
    out = []
    for image_id in ids:
        if image_id in protected:
            continue
        problem, size = removal_problem(image_id, protected)
        if problem != GONE:
            out.append(OldImage(image_id, size, problem))
    return out
