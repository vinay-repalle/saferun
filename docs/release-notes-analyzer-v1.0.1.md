<!-- GitHub Release text for tag analyzer-v1.0.1. Fill in the two <…> placeholders from the workflow run summary AFTER the run; do not guess them. -->
# SafeRun analyzer image analyzer-v1.0.1

The signed analyzer image used by `saferun init` (Semgrep, OSV-Scanner and SafeRun's rules, run with no network, a read-only root and no capabilities).

**This release supersedes `analyzer-v1.0.0`.** The image content is the same tools and rules; what changed is that the image now carries the license texts and notices for the software it redistributes.

## What is in the image
| Component | Version |
|---|---|
| Semgrep | 1.182.1 (hash-locked wheels) |
| OSV-Scanner | 2.7.0 (linux/amd64, SHA-256 `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`) |
| SafeRun rules | `python.yml`, SHA-256 `4a42c022baf2f1b9deb32be30fa50e5fee1cd1738ad5846b29a287f24596fdbc` |
| Base image | `python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea` |

## Changes since analyzer-v1.0.0
* Adds `/usr/share/doc/saferun-analyzer/`: SafeRun's MIT `LICENSE`, `THIRD_PARTY_NOTICES.md`, the Semgrep (LGPL-2.1) and OSV-Scanner (Apache-2.0) license texts, and an inventory and full license texts for the 191 Go modules linked into OSV-Scanner (`licenses/osv-scanner-v2.7.0-go-modules.md`, `licenses/osv-scanner-v2.7.0-go-module-licenses.txt`).
* The release workflow's smoke test now fails if any of those files is missing from the image.
* No change to Semgrep, OSV-Scanner, the rules or the sandbox restrictions.

## Verify it (cosign 2.2 or newer)
```sh
cosign verify \
  --certificate-identity-regexp '^https://github\.com/vinay-repalle/saferun/\.github/workflows/release-analyzer\.yml@refs/tags/analyzer-v[0-9]+(\.[0-9]+)*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/vinay-repalle/saferun-analyzer@<DIGEST FROM THE WORKFLOW RUN SUMMARY>
```
Image: `ghcr.io/vinay-repalle/saferun-analyzer@<DIGEST FROM THE WORKFLOW RUN SUMMARY>` (tag `analyzer-v1.0.1`). Always use the digest, not the tag.

SafeRun does this check for you: once this digest is recorded in `ANALYZER_RELEASE`, `saferun verify-images --signature` and `saferun init --only analyzer` verify the signature before pulling anything.

## Notes
* Signed keylessly by this repository's `release-analyzer` workflow from the tag `analyzer-v1.0.1` (Sigstore transparency log). A signature from any other repository, workflow, branch or tag pattern is refused by SafeRun.
* The build is pinned but not bit-for-bit reproducible; the digest identifies the one image that was tested, pushed and signed.
* Licenses: Semgrep is LGPL-2.1-or-later and unmodified; OSV-Scanner is Apache-2.0; one linked Go module (`filepath-securejoin`) is BSD-3-Clause AND MPL-2.0. See `THIRD_PARTY_NOTICES.md` in the image. Not legal advice.
* Known limits: the Semgrep LICENSE text was taken from upstream's default branch (the 1.182.1 tag could not be located); Go module licenses were identified from license texts, not file by file.
* `analyzer-v1.0.0` remains as a git tag but its image has no license notices: do not use it.
