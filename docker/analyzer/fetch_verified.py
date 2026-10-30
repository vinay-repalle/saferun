#!/usr/bin/env python3
"""Download a file and install it only if its SHA-256 matches the expected value (stdlib only; used during image builds).

    fetch_verified.py URL SHA256 DEST

Exit 0 and DEST written (mode 0755) only on a match. On any mismatch, oversize download or error nothing is left at DEST and the exit
code is non-zero, so a `RUN` step in the Dockerfile fails the build.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import sys
import tempfile
import urllib.request

MAX_BYTES = 256 * 1024 * 1024
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def fetch_verified(url: str, expected_sha256: str, dest: str, *, allowed_schemes: tuple[str, ...] = ("https",)) -> None:
    if not _SHA_RE.match(expected_sha256):
        raise ValueError("expected checksum must be 64 lowercase hex characters")
    if url.split(":", 1)[0] not in allowed_schemes:
        raise ValueError(f"URL scheme not allowed: {url.split(':', 1)[0]!r}")
    directory = os.path.dirname(os.path.abspath(dest))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fetch-")
    try:
        h = hashlib.sha256()
        size = 0
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - scheme checked above
            while chunk := resp.read(1 << 20):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError(f"download exceeds {MAX_BYTES} bytes")
                h.update(chunk)
                out.write(chunk)
        if not hmac.compare_digest(h.hexdigest(), expected_sha256):
            raise ValueError(f"checksum mismatch: expected {expected_sha256}, got {h.hexdigest()}")
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 64
    try:
        fetch_verified(argv[1], argv[2], argv[3])
    except Exception as e:  # noqa: BLE001 - any failure must fail the build
        print(f"fetch_verified: FAILED: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"fetch_verified: ok {argv[3]} sha256={argv[2]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
