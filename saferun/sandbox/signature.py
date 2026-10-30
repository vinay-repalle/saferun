"""Cosign signature check for the published analyzer image (Phase 5E). Fails closed: every problem raises `SignatureError`.

What is verified: that `<repository>@<digest>` carries a Sigstore "keyless" signature whose certificate was issued to the expected
GitHub Actions identity (`AnalyzerRelease.signer_identity_regexp`, issuer `oidc_issuer`) and that the signed payload names exactly
that repository and digest. The check is made by the `cosign` command line tool (not bundled: install it from
https://docs.sigstore.dev/cosign/system_config/installation/, version 2.2 or newer), which also checks the transparency log (Rekor).

How it is run: argv list (no shell), absolute path of the executable, minimal environment (no tokens or credentials), a private
HOME (so nothing is read from or written to the user's home), a hard timeout and an output cap. This runs on the HOST: cosign parses
signature data from the registry, which is why the image itself is only pulled AFTER this check succeeds and why the digest, tags and
labels are verified again afterwards. Needs internet (registry, Sigstore TUF root, Rekor); there is no offline or "skip" mode.

What it does not prove: that the signed workflow itself is free of bugs, that the repository or its GitHub account was not compromised,
or anything about cosign's own correctness. See docs/release-images.md.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import docker as dk
from .config import SandboxError
from .images import DIGEST_RE, AnalyzerRelease

COSIGN_TIMEOUT_S = 120
MAX_OUTPUT = 1024 * 1024
INSTALL_HINT = "install cosign 2.2 or newer (https://docs.sigstore.dev/cosign/system_config/installation/)"
_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "TZ", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
             "SSL_CERT_FILE", "SSL_CERT_DIR")


class SignatureError(SandboxError):
    """The release signature is missing, wrong, or could not be checked. The image must not be pulled or trusted."""


class CosignMissing(SignatureError):
    """The `cosign` executable is not installed, so nothing could be verified."""


def find_cosign() -> str | None:
    path = shutil.which("cosign")
    return os.path.abspath(path) if path else None


def build_command(cosign: str, rel: AnalyzerRelease) -> list[str]:
    """argv for `cosign verify`. Refuses anything that is not a plain image reference and a sha256 digest."""
    if not DIGEST_RE.match(rel.digest or ""):
        raise SignatureError(f"release digest is not a sha256 digest: {rel.digest!r}")
    if not rel.signer_identity_regexp or not rel.oidc_issuer:
        raise SignatureError("the release names no signer identity or issuer, so its signature cannot be checked")
    try:
        dk.validate_image(rel.reference)
    except SandboxError as e:
        raise SignatureError(str(e)) from None
    return [cosign, "verify",
            "--certificate-identity-regexp", rel.signer_identity_regexp,
            "--certificate-oidc-issuer", rel.oidc_issuer,
            "--output", "json", rel.reference]


def parse_output(stdout: str, rel: AnalyzerRelease) -> int:
    """Number of signature payloads in cosign's JSON that name exactly `rel`'s repository and digest; raises if there is none.
    cosign has already verified the signatures; this makes sure what it reports is about the image we asked for."""
    try:
        data = json.loads(stdout)
    except (ValueError, RecursionError):
        raise SignatureError("cosign printed no valid JSON; the signature was NOT confirmed") from None
    if not isinstance(data, list):
        raise SignatureError("cosign output has an unexpected shape; the signature was NOT confirmed")
    good = 0
    for item in data:
        try:
            crit = item["critical"]
            digest = crit["image"]["docker-manifest-digest"]
            ref = crit["identity"]["docker-reference"]
        except (KeyError, TypeError):
            continue
        if digest == rel.digest and ref == rel.repository:
            good += 1
    if not good:
        raise SignatureError("cosign reported no signature for exactly this repository and digest; it was NOT confirmed")
    return good


def verify_release_signature(rel: AnalyzerRelease, *, which=find_cosign, run=subprocess.run, timeout_s: float = COSIGN_TIMEOUT_S) -> int:
    """Raise SignatureError / CosignMissing unless `rel` is validly signed by the expected identity. Returns the number of signatures."""
    cosign = which()
    if not cosign:
        raise CosignMissing(f"cosign is not installed, so the signature of {rel.reference} cannot be checked: {INSTALL_HINT}")
    argv = build_command(cosign, rel)
    env = {k: os.environ[k] for k in _ENV_KEEP if k in os.environ and "\0" not in os.environ[k]}
    with tempfile.TemporaryDirectory(prefix="saferun-cosign-") as home:
        env.update(HOME=home, TMPDIR=home, XDG_CACHE_HOME=str(Path(home) / "cache"), XDG_CONFIG_HOME=str(Path(home) / "config"))
        try:
            r = run(argv, capture_output=True, text=True, errors="replace", timeout=timeout_s, stdin=subprocess.DEVNULL,
                    env=env, cwd=home)
        except subprocess.TimeoutExpired:
            raise SignatureError(f"cosign did not finish within {int(timeout_s)} s; the signature was NOT confirmed") from None
        except OSError as e:
            raise SignatureError(f"cosign could not be started: {e}") from None
    if r.returncode != 0:
        tail = " ".join((r.stderr or "").split())[-300:]
        raise SignatureError(f"cosign could not verify the signature of {rel.reference} (exit {r.returncode}): {tail or 'no message'}")
    if len(r.stdout or "") > MAX_OUTPUT:
        raise SignatureError("cosign printed an unexpectedly large output; the signature was NOT confirmed")
    return parse_output(r.stdout or "", rel)
