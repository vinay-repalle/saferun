# Prebuilt images: what exists, and how the analyzer image is released

`saferun init` installs three kinds of image/data.

| Component | How `saferun init` gets it | Trust anchor |
|---|---|---|
| Python / Node.js sandbox images | `docker pull python@sha256:… / node@sha256:…` (digest from `saferun/sandbox/images.py`) | The pinned manifest digest, verified again afterwards against the image's `RepoDigests` (`saferun verify-images`). Docker rejects content that does not hash to the digest. |
| Analyzer image (Semgrep, OSV-Scanner, rules) | **Built locally** with `docker/analyzer/build.sh` (the default today). A cosign-signed prebuilt release is supported by the code but **no personal release has been published yet**: `ANALYZER_RELEASE` is `None`. Once one is published and recorded, `saferun init` installs it, and `--build-local` still builds locally | Local build: hash-locked wheels, checksum-verified OSV-Scanner, digest-pinned base, owner-only lock file. Published release (once it exists): the cosign signature (GitHub Actions identity of this repository's release workflow) **and** the pinned digest, then labels/tool versions/rules hash, then an owner-only lock file. |
| OSV vulnerability data | `saferun osv-db update` (HTTPS, public data) | Server MD5 + a locally recorded SHA-256 manifest. Detects corruption and later changes, **not** a malicious server (see `docs/cli.md`). |

**Status:** **no signed analyzer release has been published from `vinay-repalle/saferun` yet.** `ANALYZER_RELEASE` in `saferun/sandbox/images.py` is `None`, so `saferun init` builds the analyzer locally (`docker/analyzer/build.sh`) and `saferun verify-images --signature` reports that there is nothing to verify. Earlier project history mentioned a release `analyzer-v1.0.0` under a previous owner's registry and signer identity; it is **not** trusted here: SafeRun accepts only signatures from this repository's workflow, so it would be refused. The release workflow, the cosign verification and the install path below are implemented and tested with fakes, but have never run against a real image from this repository. The sections below describe how it will work once you publish one. Nothing is published or recorded automatically.

## How an install of the published image will work (inactive until a release is recorded)
1. **Verify the signature first.** `cosign verify --certificate-identity-regexp <identity> --certificate-oidc-issuer https://token.actions.githubusercontent.com --output json <repo>@<digest>`.
   The identity must be this repository's `release-analyzer.yml` workflow run for a **tag** `analyzer-v<number>[.<number>…]` (a branch, a pull request, another workflow or another
   repository is refused). SafeRun also checks that the signed payload names exactly this repository and digest. Nothing has been pulled at this point.
2. `docker pull <repo>@<digest>`; confirm the local image carries exactly that digest in `RepoDigests`.
3. Tag it `saferun-analyzer:local`; check the labels (Semgrep and OSV-Scanner versions, rules hash equal to this checkout's `python.yml`).
4. Write the owner-only lock file. Every scan afterwards verifies lock, image ID and labels as before.

Any failure leaves the image **untrusted and unlocked**. There is no unsigned install and no automatic fallback: if `cosign` is not installed or the signature does not verify, `init` says so and
stops; building locally is an explicit choice (`saferun init --only analyzer --build-local`). `saferun verify-images --signature` repeats step 1 on demand (online).

Requirements on the user's machine: Docker, internet access to `ghcr.io`, `tuf-repo-cdn.sigstore.dev` and `rekor.sigstore.dev` during `init`, and
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.2 or newer on `PATH` (without sudo: download the `cosign-linux-amd64` release binary and `install -m 0755 cosign ~/.local/bin/cosign`; SafeRun never installs it). cosign runs on the host (argv only, minimal environment, private HOME, 120 s timeout) and parses
registry/Sigstore data there; that is why the image is not pulled until the signature has verified. Scans never use the network.

## Publishing a release (maintainer)
Only an intentional tag push publishes anything. Ordinary CI (`ci.yml`) never logs in to a registry and has no write permissions.

### Manual GitHub configuration (once)
1. **Default branch is `main`.** The release workflow refuses a tag whose commit is not on `main`.
2. **Actions enabled** for the repository (Settings → Actions → General). No secrets are needed: the workflow uses only the automatic `GITHUB_TOKEN`, with `packages: write` and `id-token: write` granted to the release job alone (the top-level permission is `contents: read`).
3. **Workflow permissions** (Settings → Actions → General → Workflow permissions): "Read repository contents" is enough; the release job requests what it needs itself. Leave "Allow GitHub Actions to create and approve pull requests" off.
4. **Protect `main` and tags** (recommended): a branch rule that requires the `python`, `web` and `package` CI jobs; a tag ruleset for `analyzer-v*` so only you can create or move such tags. A moved tag changes the signed identity's meaning, never re-use or move a release tag.
5. **Account hygiene:** 2FA on the GitHub account. A takeover of the account or repository would let an attacker sign with the expected identity (see below).
6. **After the first release:** the package `saferun-analyzer` appears under your profile → Packages. ghcr.io creates it **private**; make it public (Package settings → Change visibility → Public) because `saferun init` pulls anonymously. Check that the package is linked to this repository (the image's `org.opencontainers.image.source` label does that) and that the repository has write access to the package (Package settings → Manage Actions access).

### Cutting a release
1. Commit and push the repository to `main` and wait for CI to pass.
2. Push a tag on a `main` commit. `analyzer-v1.0.0` below is only an **example**: the name of the first release from this repository, which has **not** been published (an `analyzer-v1.0.0` existed in the previous owner's repository and is unrelated): `git tag analyzer-v1.0.0 && git push origin analyzer-v1.0.0`.
   The workflow refuses other tag names and commits not on `main`, then, in this order:
   1. builds the image from `docker/analyzer/` (`linux/amd64`, single manifest) **locally on the runner without pushing it**;
   2. smoke-tests that exact image: labels equal SafeRun's pins, Semgrep and OSV-Scanner versions, the baked rules equal this commit's rules, **no network** from inside the container, and a real scan with the baked rules, all under the same restrictions SafeRun applies (no network, read-only root, no capabilities, non-root);
   3. only if that passed: logs in to `ghcr.io`, pushes **that same image** as `ghcr.io/vinay-repalle/saferun-analyzer:analyzer-v1.0.0` and reads back its digest;
   4. signs the **digest** (keyless, GitHub OIDC), verifies the signature with the same identity expression SafeRun uses, and checks that a *wrong* identity is refused (the job fails if cosign accepts it);
   5. prints the digest and a manual `cosign verify` command in the run summary.
   Any failing step stops the job; nothing is signed that was not pushed, and nothing is pushed that failed the smoke test. A failure after the push leaves an unsigned image in the registry: SafeRun refuses it (no signature, no install) and you should delete that package version.
3. In a reviewed commit, record it in `saferun/sandbox/images.py`: `ANALYZER_RELEASE = AnalyzerRelease(ANALYZER_REGISTRY_REPOSITORY, "sha256:<digest from the run>", "<date>")`. The rules
   (`saferun/engine/rules/python.yml`) in that commit must be the ones the tag was built from, otherwise the label check fails for every user (a test and `saferun status` show it).
4. Check it from a clean machine: `saferun verify-images --signature`, then `saferun init --only analyzer`.
5. Update policy: a new analyzer version (new Semgrep/OSV-Scanner pin or new rules) is a new tag, a new digest and a new commit; users re-run `saferun init` (status shows the analyzer as invalid/outdated until they do).

### Trusting only this repository
The accepted signer is the regular expression `ANALYZER_SIGNER_IDENTITY_REGEXP` in `saferun/sandbox/images.py`: exactly `https://github.com/vinay-repalle/saferun/.github/workflows/release-analyzer.yml@refs/tags/analyzer-v<number>[.<number>…]`, issued by `https://token.actions.githubusercontent.com`. A signature from any other repository, workflow, branch, pull request or tag pattern, **including the repository this project was copied from**, does not match (unit tests list those identities and assert they are rejected). Verification failure, a missing `cosign`, a payload naming another digest or repository, or a missing signature all stop `init` before anything is pulled.

### Installing and verifying a released image (users)
Requirements: `cosign` 2.2+ on `PATH`, Docker, internet access to `ghcr.io`, `tuf-repo-cdn.sigstore.dev` and `rekor.sigstore.dev`.
```bash
saferun verify-images --signature      # checks the recorded release's signature, exit 1 on any failure
saferun init --only analyzer           # verifies, pulls by digest, re-checks the digest and the labels, locks
```
Without SafeRun (replace `<digest>`; the digest is the one recorded in `ANALYZER_RELEASE`):
```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/vinay-repalle/saferun/\.github/workflows/release-analyzer\.yml@refs/tags/analyzer-v[0-9]+(\.[0-9]+)*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/vinay-repalle/saferun-analyzer@sha256:<digest>
```
Build reproducibility: the inputs are pinned (base image digest, hash-locked Semgrep wheels, checksum-verified OSV-Scanner, rules hash), but the image is **not bit-for-bit reproducible** (layer and config timestamps differ between builds). The digest you record identifies the one image that was tested, pushed and signed.

### Third-party software in the analyzer image
Publishing the image **redistributes** other people's software. The inventory, the license texts that must travel with it, and the verification behind them are in
`docker/analyzer/THIRD_PARTY_NOTICES.md` and `docker/analyzer/licenses/`; the Dockerfile copies them into the image under `/usr/share/doc/saferun-analyzer/`, and the release workflow's smoke test fails if they are missing.
* Semgrep (LGPL-2.1-or-later) and OSV-Scanner (Apache-2.0) license texts are included. Their upstream sources are the corresponding-source references. See the notices file for exactly which upstream files were used and how they were checked.
* The Python packages installed with Semgrep keep their own license files in their `dist-info` directories.
* **Open items:** (1) the Go modules statically linked into the OSV-Scanner binary are not enumerated; (2) the Semgrep LICENSE text came from upstream's default branch because the 1.182.1 tag could not be located. This is not legal advice.

### Version and tag strategy
* The tag sequence `analyzer-v<n>` versions the **analyzer image only**. It is independent of the SafeRun package version in `pyproject.toml` (`0.0.1`).
* `analyzer-v1.0.0` was built before the license texts were added to the image, so its image does **not** contain them. Tags are never moved or re-created: keep that package private, and publish the image that contains the notices as a **new tag** (next free number, for example `analyzer-v1.0.1`), record that digest in `ANALYZER_RELEASE`, and only then make the package public.
* Recording the digest and releasing are separate commits: the tag is created first from `main`, the digest is recorded afterwards in a reviewed commit.

## What this does and does not give
* The digest pins the exact bytes; the signature says those bytes were produced by this repository's release workflow from a tag, recorded in the public Sigstore transparency log. Someone who edits
  `ANALYZER_RELEASE` to point at another image cannot also produce a signature with the expected identity.
* It does **not** prove the workflow or repository was free of compromise at release time, that the pinned tools are free of vulnerabilities, or that cosign itself is correct. If the GitHub account
  or the repository is taken over, new tags could be signed with the expected identity: protect the account (2FA) and review tags.
* Verification needs cosign and internet at install time. After installation the trust anchor is the local lock file, with the limits stated in `PROJECT.md` (*Phase 5 security status*): the same user, root or
  a member of the `docker` group can still replace the local image and lock.
* The signature check has not yet been run against a real cosign binary and a real image from this repository, and no clean-machine `saferun init` from a published image has been recorded. Both are open until you publish a release.

## Offline machines
Prepare on a connected machine and copy: the OSV directory (`saferun osv-db update --dir DIR`, relocatable, then `SAFERUN_OSV_DB=DIR` or place it at the default location) and the
images (`docker save` / `docker load`). SafeRun trusts a loaded image only if Docker reports the pinned registry digest for it; if your Docker drops repository digests on `docker load`,
`saferun status` reports the image as invalid. That behaviour has not been tested against every Docker version.
**The analyzer still cannot be installed on a machine that never has internet access**: its lock file is written only by a local build or by a verified published-image install (which needs the
registry and Sigstore), and no supported "import a loaded analyzer image" step exists. Build it once while online (`saferun init --only analyzer`, or `--build-local`) or build elsewhere and
rebuild/verify on the target. This is a known gap, not something the setup command works around.
