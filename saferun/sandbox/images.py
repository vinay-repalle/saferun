"""Pinned container images (Phase 5A): data and pure helpers only (no Docker calls, no imports from the rest of the package).

Every image SafeRun runs is referenced as `repository:tag@sha256:<digest>`. The digest is the manifest (index)
digest, which is content-addressed: Docker resolves the reference by digest and the tag is only a label for humans.
`saferun verify-images` and `docker.resolve_image` refuse to continue when the local image does not carry the pinned digest.

How a digest becomes a pin: (1) read it from the local image (`docker image inspect`) that the test suite ran against,
(2) confirm the registry serves that exact digest for the repository (`docker buildx imagetools inspect <repo>@<digest>`),
(3) record it here together with the date. To update a pin, repeat these steps deliberately; nothing updates itself.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^(?P<name>[^@]+)@(?P<digest>sha256:[0-9a-f]{64})$")


@dataclass(frozen=True)
class PinnedImage:
    name: str          # profile name
    repository: str    # as Docker lists it in RepoDigests, e.g. "python"
    tag: str           # human-readable label; NOT trusted, the digest decides
    digest: str        # sha256:<64 hex>, manifest-index digest
    pinned_on: str     # ISO date the digest was verified against the registry

    @property
    def reference(self) -> str:
        return f"{self.repository}:{self.tag}@{self.digest}"

    @property
    def pull_reference(self) -> str:
        return f"{self.repository}@{self.digest}"


PYTHON_IMAGE = PinnedImage("python", "python", "3.12-slim",
                           "sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea", "2026-10-29")
NODE_IMAGE = PinnedImage("node", "node", "22-slim",
                         "sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da", "2026-10-29")
PINNED_IMAGES: tuple[PinnedImage, ...] = (PYTHON_IMAGE, NODE_IMAGE)

# Where the prebuilt analyzer image is published, and WHO may have signed it (Phase 5E).
# The image is built and pushed by .github/workflows/release-analyzer.yml and signed with cosign "keyless": the signature is bound to
# the workflow's GitHub OIDC identity, not to a key anyone holds. SafeRun accepts a signature only if the certificate identity matches
# this expression: that exact repository, that exact workflow file, and a TAG ref `analyzer-v<number>(.<number>)*` (never a branch or
# a pull request). tests/test_release_signature.py checks the expression against the workflow file.
ANALYZER_REGISTRY_REPOSITORY = "ghcr.io/vinay-repalle/saferun-analyzer"
ANALYZER_SIGNER_IDENTITY_REGEXP = (r"^https://github\.com/vinay-repalle/saferun/\.github/workflows/release-analyzer\.yml"
                                   r"@refs/tags/analyzer-v[0-9]+(\.[0-9]+)*$")
GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


@dataclass(frozen=True)
class AnalyzerRelease:
    """An officially PUBLISHED prebuilt analyzer image: where it lives, the manifest digest it must have, and who must have signed it.
    `saferun init` first verifies the cosign signature of `<repository>@<digest>` (identity + issuer below), then pulls that reference
    (content-addressed: Docker rejects anything else), then applies the same label/tool/rules verification as for a locally built
    image, and only then locks it. A release without a signer identity is refused: there is no unsigned install."""
    repository: str      # e.g. ANALYZER_REGISTRY_REPOSITORY
    digest: str          # sha256:<64 hex> of the published manifest
    published_on: str
    signer_identity_regexp: str = ANALYZER_SIGNER_IDENTITY_REGEXP
    oidc_issuer: str = GITHUB_OIDC_ISSUER

    @property
    def reference(self) -> str:
        return f"{self.repository}@{self.digest}"


# The current release: tag analyzer-v1.0.1 (commit a275dce, rules unchanged since), signed by this repository's release workflow. The digest was read from
# the registry and its cosign signature was verified with ANALYZER_SIGNER_IDENTITY_REGEXP before it was recorded (docs/release-images.md). A new analyzer
# (new tool pins or rules) is a new tag, a new digest and a new commit here. Set to None to make `saferun init` build locally with docker/analyzer/build.sh.
ANALYZER_RELEASE: AnalyzerRelease | None = AnalyzerRelease(
    ANALYZER_REGISTRY_REPOSITORY,
    "sha256:6f26c3e3fed1a8b2a981bdcb920c4da3b2829bce2679709ba8880789ce6f6fa4",
    "2026-10-30",
)

# Tools baked into the analyzer image build recipe (docker/analyzer/). Not used at run time yet (Phase 5B).
# The Dockerfile ARG defaults must equal these values; tests enforce it.
SEMGREP_VERSION = "1.182.1"
OSV_SCANNER_VERSION = "2.7.0"
OSV_SCANNER_LINUX_AMD64_SHA256 = "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"


def digest_of(reference: str) -> str | None:
    """The sha256 digest named by an image reference, or None for a tag-only reference."""
    m = _REF_RE.match(reference)
    return m.group("digest") if m else None


def repo_digests(raw: str) -> list[str]:
    """Digests (`sha256:...`) from the JSON of `docker image inspect --format {{json .RepoDigests}}`.

    Raises ValueError for anything but a JSON list of `name@sha256:<64 hex>` strings (or null/empty).
    """
    data = json.loads(raw)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("RepoDigests is not a list")
    out = []
    for item in data:
        m = _REF_RE.match(item) if isinstance(item, str) else None
        if not m:
            raise ValueError(f"unexpected RepoDigests entry: {item!r}")
        out.append(m.group("digest"))
    return out
