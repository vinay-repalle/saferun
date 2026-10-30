# Analyzer image build recipe

This recipe builds the analyzer image that SafeRun uses to run Semgrep and OSV-Scanner in isolation (Phase 5B). `docker/analyzer/build.sh` builds it locally (what `saferun init` does today); `.github/workflows/release-analyzer.yml` builds the same recipe for a signed release (`docs/release-images.md`). The image ends with `USER 65534:65534`; SafeRun additionally runs it with no network, a read-only root, no capabilities and resource limits.

| Item | Pin | Verification |
|---|---|---|
| Base image | `python:3.12-slim@sha256:78387bc3…` | `FROM` by digest; `build.sh` runs `saferun verify-images` first |
| Semgrep | `1.182.1`, 66 wheels | `pip --require-hashes --only-binary=:all:` against `semgrep-requirements.txt` |
| OSV-Scanner | `2.7.0` linux/amd64 | `fetch_verified.py` compares the SHA-256 of the download and aborts the build on mismatch |

Limits: the lock covers linux/amd64 and CPython 3.12 only. The OSV-Scanner checksum was taken from the upstream release
`osv-scanner_SHA256SUMS` (same GitHub trust root as the binary; it protects against corruption and later tampering of the
download, not against a compromised upstream release) and matches the binary used by the host-side checks.

Regenerate the Semgrep lock when bumping the version (`images.py`, `Dockerfile` and this lock must agree):

    python -m pip download semgrep==<version> -d wheels/
    # one line per wheel: name==version --hash=sha256:$(sha256sum wheel)

`tests/test_image_pins.py` fails if the pins in `saferun/sandbox/images.py`, the Dockerfile and the lock drift apart.
