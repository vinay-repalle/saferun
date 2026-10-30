"""`saferun verify-images`: check that the local Docker images carry the pinned digests (Phase 5A).

Read-only: it inspects local images through the Docker CLI. It never pulls, never creates containers, and
never changes images. A missing image or a digest mismatch is a failure (fail closed), not a warning.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from . import docker as dk
from .analyzer import ANALYZER_REPO_TAG, AnalyzerIntegrityError, AnalyzerUnavailable, verify_analyzer_image
from .config import SandboxError
from .images import PINNED_IMAGES, PinnedImage, repo_digests

VERIFIED, MISSING, MISMATCH, ERROR = "verified", "missing", "mismatch", "error"


@dataclass(frozen=True)
class ImageCheck:
    name: str
    reference: str
    pinned_digest: str
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == VERIFIED

    def to_dict(self) -> dict:
        return asdict(self)


def check_image(img: PinnedImage) -> ImageCheck:
    base = dict(name=img.name, reference=img.reference, pinned_digest=img.digest)
    try:
        r = dk.docker("image", "inspect", "--format", "{{json .RepoDigests}}", dk.validate_image(img.reference))
    except SandboxError as e:
        return ImageCheck(**base, status=ERROR, detail=str(e))
    if r.returncode != 0:
        if "no such image" in r.stderr.lower():
            return ImageCheck(**base, status=MISSING,
                              detail=f"not present locally; fetch it explicitly with: docker pull {img.pull_reference}")
        return ImageCheck(**base, status=ERROR, detail=f"docker image inspect failed: {r.stderr.strip()[:200]}")
    try:
        have = repo_digests(r.stdout.strip())
    except ValueError as e:
        return ImageCheck(**base, status=ERROR, detail=f"unexpected docker output: {e}")
    if img.digest in have:
        return ImageCheck(**base, status=VERIFIED)
    return ImageCheck(**base, status=MISMATCH,
                      detail=f"local image has {', '.join(have) if have else 'no registry digest'}, pinned is {img.digest}")


def check_analyzer() -> ImageCheck:
    """The locally built analyzer image against its build lock and pinned tool/rules labels."""
    base = dict(name="analyzer", reference=ANALYZER_REPO_TAG, pinned_digest="")
    try:
        image_id = verify_analyzer_image()
    except AnalyzerUnavailable as e:
        return ImageCheck(**base, status=MISSING, detail=str(e))
    except AnalyzerIntegrityError as e:
        return ImageCheck(**base, status=MISMATCH, detail=str(e))
    except SandboxError as e:
        return ImageCheck(**base, status=ERROR, detail=str(e))
    return ImageCheck(**{**base, "pinned_digest": image_id}, status=VERIFIED)


def verify_images(images: tuple[PinnedImage, ...] = PINNED_IMAGES, *, analyzer: bool = True) -> list[ImageCheck]:
    """Raises SandboxError when Docker itself is unusable (remote endpoint, daemon down)."""
    dk.check_local_daemon()
    checks = [check_image(i) for i in images]
    if analyzer:
        checks.append(check_analyzer())
    return checks
