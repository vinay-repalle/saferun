"""A pinned, hash-verified copy of cosign that SafeRun fetches itself, so users do not have to install it.

Trust model: the expected SHA-256 of every supported cosign binary is written in THIS file (taken from the upstream release's
`cosign_checksums.txt`, v2.4.3, the version the release workflow uses). A download is written to a temporary file in the private
tool directory, hashed, and only a file whose SHA-256 equals the pin is made executable and moved into place. The file is hashed
again every time it is looked up, so a binary that was modified later is ignored (and re-fetched by `saferun init`). Nothing else is
trusted: not the redirect target, not the file name, not the HTTP headers. HTTPS only, size-capped.
What this does NOT give you: it trusts the hashes in this reviewed source file, and the GitHub release that they were copied from.
The cosign binary then verifies the analyzer image's signature exactly as before (signature.py); the identity check is unchanged.
"""
from __future__ import annotations

import hashlib
import os
import platform
import sys
import tempfile
import urllib.request
from pathlib import Path

from .. import hostos
from .config import SandboxError

COSIGN_VERSION = "2.4.3"
BASE_URL = f"https://github.com/sigstore/cosign/releases/download/v{COSIGN_VERSION}"
MAX_BYTES = 200 * 1024 * 1024
# (system, machine) -> (release asset, sha256). Source: cosign_checksums.txt of release v2.4.3.
ASSETS = {
    ("linux", "x86_64"): ("cosign-linux-amd64", "caaad125acef1cb81d58dcdc454a1e429d09a750d1e9e2b3ed1aed8964454708"),
    ("linux", "aarch64"): ("cosign-linux-arm64", "bd0f9763bca54de88699c3656ade2f39c9a1c7a2916ff35601caf23a79be0629"),
    ("darwin", "x86_64"): ("cosign-darwin-amd64", "98a3bfd691f42c6a5b721880116f89210d8fdff61cc0224cd3ef2f8e55a466fb"),
    ("darwin", "arm64"): ("cosign-darwin-arm64", "edfc761b27ced77f0f9ca288ff4fac7caa898e1e9db38f4dfdf72160cdf8e638"),
    ("windows", "x86_64"): ("cosign-windows-amd64.exe", "a2ac24e197111c9430cb2a98f10a641164381afb83df036504868e4ea5720800"),
}
_MACHINE_ALIASES = {"amd64": "x86_64", "x64": "x86_64", "arm64": "aarch64"}


class CosignFetchError(SandboxError):
    """The pinned cosign could not be obtained or did not match its pinned hash. Nothing was installed."""


def platform_key(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    s = (system or platform.system()).lower()
    m = (machine or platform.machine()).lower()
    if s == "darwin":
        m = {"amd64": "x86_64", "x64": "x86_64"}.get(m, m)           # Apple silicon reports arm64
    else:
        m = _MACHINE_ALIASES.get(m, m)
    return s, m


def asset_for(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    key = platform_key(system, machine)
    if key not in ASSETS:
        raise CosignFetchError(f"no pinned cosign build for {key[0]}/{key[1]}; install cosign {COSIGN_VERSION}+ yourself "
                               "(https://docs.sigstore.dev/cosign/system_config/installation/) and put it on PATH")
    return ASSETS[key]


def tool_dir() -> Path:
    return hostos.user_data_base() / "saferun" / "bin"


def managed_path(system: str | None = None) -> Path:
    exe = ".exe" if (system or sys.platform).lower().startswith(("win", "windows")) else ""
    return tool_dir() / f"cosign-{COSIGN_VERSION}{exe}"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def managed_cosign() -> str | None:
    """Absolute path of the managed cosign if it exists, is a regular file (no symlink) and still has its pinned hash; else None. Never raises."""
    try:
        want = asset_for()[1]
        p = managed_path()
        if p.is_symlink() or not p.is_file() or _sha256(p) != want:
            return None
        return str(p.resolve())
    except (OSError, SandboxError):
        return None


def ensure_cosign(*, opener=None, progress=None) -> str:
    """Return the managed cosign, downloading and verifying it first if needed. Raises CosignFetchError (nothing is left behind)."""
    have = managed_cosign()
    if have:
        return have
    name, want = asset_for()
    url = f"{BASE_URL}/{name}"
    if not url.startswith("https://"):
        raise CosignFetchError("cosign must be downloaded over https")
    opener = opener or urllib.request.urlopen
    d = tool_dir()
    if d.is_symlink():
        raise CosignFetchError(f"refusing to use a symlink as the tool directory: {d}")
    try:
        hostos.ensure_private_dir(d.parent)      # <data>/saferun also holds the analyzer lock, which requires it to be owner-only
        hostos.ensure_private_dir(d)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".cosign-")
    except OSError as e:
        raise CosignFetchError(f"cannot prepare {d}: {e}") from None
    try:
        h, size = hashlib.sha256(), 0
        with os.fdopen(fd, "wb") as out, opener(url, timeout=120) as resp:  # noqa: S310 - https enforced above
            while chunk := resp.read(1 << 20):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise CosignFetchError(f"download exceeds {MAX_BYTES} bytes; refused")
                h.update(chunk)
                out.write(chunk)
                if progress:
                    progress("cosign", size, None)
        if h.hexdigest() != want:
            raise CosignFetchError("the downloaded cosign does not match its pinned SHA-256; it was discarded and NOT installed")
        if not hostos.IS_WINDOWS:
            os.chmod(tmp, 0o700)
        os.replace(tmp, managed_path())
    except CosignFetchError:
        raise
    except OSError as e:                      # URLError, timeouts and disk errors are all OSError subclasses
        raise CosignFetchError(f"could not download cosign from {url}: {e}") from None
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    got = managed_cosign()
    if not got:
        raise CosignFetchError("cosign was installed but could not be verified afterwards")
    return got
