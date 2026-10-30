# Release checklist: analyzer-v1.0.1

Prepared 2026-10-30. **Nothing below the "Prepared and verified" section has been run.** Commands marked **[needs approval]** publish, push, or change something outside your working copy; commands marked **[credentials]** need your GitHub account (SSH push access to `vinay-repalle/saferun`, and the GitHub web UI). The `gh` CLI is not installed on this machine, so the web UI is used for the Actions run and the Release page.

## 0. Prepared and verified (done, locally)
- [x] Non-Docker Python tests: 983 passed (`pytest -m "not docker"`).
- [x] Docker tests with `SAFERUN_REQUIRE_DOCKER=1` (`pytest -m docker`): 106 passed.
- [x] Dashboard: `npm test` 50 passed; `npm run build` succeeded.
- [x] `python -m build` produced wheel and sdist; the wheel has the rules and `LICENSE`; the sdist has the Dockerfile, `THIRD_PARTY_NOTICES.md` and `licenses/`.
- [x] The analyzer image built locally from the exact staged context (as in the workflow) and the workflow's smoke test was reproduced by hand: labels, Semgrep 1.182.1, OSV-Scanner 2.7.0, rules hash, user 65534, all six notice files present, no network, real Semgrep scan. (Throwaway tag, since removed. Not the pushed/signed image.)
- [x] OSV-Scanner Go inventory completed: 191 modules read from the pinned binary, licenses read per module (`docker/analyzer/licenses/osv-scanner-v2.7.0-go-modules.md`, `…-go-module-licenses.txt`), referenced by the notices, the smoke test and a test.
- [x] Real `cosign verify` of the existing `analyzer-v1.0.0` (digest `sha256:e4c60845…c6b29`) with this project's identity expression succeeded. That is v1.0.0 only: **nothing about v1.0.1 has been signed or verified.**

## 1. Review and commit the changes **[needs approval]**
```bash
cd /home/vinayrepalle/Documents/SafeRun-personal
git status && git diff                       # review: workflow, notices, docs, tests, new docker/analyzer/licenses/*, docs/release-*.md
git add -A && git commit -m "Complete OSV-Scanner Go license inventory and prepare analyzer-v1.0.1"
git push origin main
```
Wait for the `ci` workflow on that commit to be green (GitHub → Actions → ci). The release workflow refuses a tag whose commit is not on `main`.

## 2. Confirm the tag is free, then tag **[needs approval]**
`analyzer-v1.0.0` exists and must not be moved or deleted.
```bash
git ls-remote --tags origin 'analyzer-v1.0.1'          # must print nothing
git tag analyzer-v1.0.1 "$(git rev-parse HEAD)"        # HEAD = the commit pushed in step 1
git show --stat analyzer-v1.0.1 | head
```

## 3. Publish: push the tag **[needs approval] [credentials]**
This is the one command that builds, pushes and signs the image (in GitHub Actions; there is no local `docker push`).
```bash
git push origin analyzer-v1.0.1
```
Watch GitHub → Actions → `release-analyzer`. It builds locally on the runner, smoke-tests that exact image, logs in to ghcr.io, pushes it, signs the digest keylessly, verifies with SafeRun's identity expression and checks that a wrong identity is refused.
* Success: the run summary shows "Analyzer image published and signed" with the digest.
* If a step **after the push** fails, the summary says "pushed but NOT signed and verified": do **not** record it. Delete that package version in GitHub (Packages → saferun-analyzer → versions) **[credentials]**, fix the cause, and use a **new** tag (`analyzer-v1.0.2`). Never move or re-create `analyzer-v1.0.1`.

## 4. Read the digest from two sources and compare
```bash
# (a) copy it from the run summary: sha256:<64 hex>
# (b) read it from the registry (anonymous; the package is already public):
D=$(docker buildx imagetools inspect ghcr.io/vinay-repalle/saferun-analyzer:analyzer-v1.0.1 --format '{{.Manifest.Digest}}'); echo "$D"
```
They must be identical. Do not type a digest from memory.

## 5. Verify the real signature (cosign 2.2+, already installed at ~/.local/bin/cosign)
```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/vinay-repalle/saferun/\.github/workflows/release-analyzer\.yml@refs/tags/analyzer-v[0-9]+(\.[0-9]+)*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/vinay-repalle/saferun-analyzer@$D"
```
Check the output: exit 0, `docker-manifest-digest` equals `$D`, and the certificate extension for the ref is `refs/tags/analyzer-v1.0.1`.
Also confirm the notices are in the pulled image:
```bash
docker pull "ghcr.io/vinay-repalle/saferun-analyzer@$D"
docker run --rm --network none --entrypoint ls "ghcr.io/vinay-repalle/saferun-analyzer@$D" /usr/share/doc/saferun-analyzer /usr/share/doc/saferun-analyzer/licenses
```

## 6. Record the digest in `ANALYZER_RELEASE` (a separate, reviewed commit) **[needs approval]**
Edit `saferun/sandbox/images.py` (currently `ANALYZER_RELEASE: AnalyzerRelease | None = None`):
```python
ANALYZER_RELEASE: AnalyzerRelease | None = AnalyzerRelease(ANALYZER_REGISTRY_REPOSITORY, "sha256:<digest verified in step 5>", "2026-MM-DD")
```
The rules and `docker/analyzer/` must be unchanged since the tag, otherwise every user's label check fails:
```bash
git diff analyzer-v1.0.1 -- saferun/engine/rules docker/analyzer     # must print nothing
python -m pytest -q -m "not docker"                                    # use your venv's python; see docs/install-and-test.md
```
Tests that describe the local-build path set `ANALYZER_RELEASE = None` themselves. Update docs that say "`ANALYZER_RELEASE` is `None`" (README, PROJECT.md, docs/release-images.md, docs/cli.md) in the same commit. Then commit and push **[needs approval]**.

## 7. Check it end to end
```bash
saferun verify-images --signature          # exit 0; real cosign check of the recorded release
```
`saferun init --only analyzer` **skips** an analyzer that is already installed and valid, and `status` does not compare the installed image with the recorded release. This machine currently holds a locally locked image that came from the previous owner's registry (`ghcr.io/vinay-ampera/…@sha256:3b7adfc9…`). To really exercise the published-image install, start from "analyzer missing":
```bash
mv ~/.local/share/saferun/analyzer-image-id ~/.local/share/saferun/analyzer-image-id.bak   # your lock; restore it if you want the old image back
docker rmi saferun-analyzer:local                                                           # removes only the tag
saferun status                              # analyzer should now be MISSING
saferun init --only analyzer                # verifies the signature, pulls by digest, re-checks digest and labels, writes the lock
saferun status                              # exit 0, analyzer READY
```
Success looks like: "signature verified", the pulled image carries the recorded digest, labels and rules hash verified, `status` exit 0. Then run one scan (`saferun scan ./some-project`) to confirm the analyzer checks run. Ideally repeat on a machine that has never had the old image.

## 8. GitHub Release **[needs approval] [credentials]**
GitHub → Releases → Draft a new release → choose the existing tag `analyzer-v1.0.1` (do not create a new tag from the UI) → title `analyzer-v1.0.1` → paste `docs/release-notes-analyzer-v1.0.1.md` after replacing both `<DIGEST FROM THE WORKFLOW RUN SUMMARY>` placeholders with the digest verified in step 5 (and deleting the leading HTML comment) → publish only after steps 5 to 7 passed. Do not attach binaries.

## 9. Decisions that are yours
- **`analyzer-v1.0.0` image:** it is public and has no license notices. Options: leave it (git tag stays either way), or delete that package version in GitHub Packages after v1.0.1 is verified **[credentials, destructive]**. Not done.
- **Package visibility:** `saferun-analyzer` is already readable anonymously; no change needed or made.
- **Branch/tag protection** for `main` and `analyzer-v*` (recommended in `docs/release-images.md`): not configured from here.
- **The `docker` CI job** is advisory and has never been seen to pass on GitHub; the same tests pass locally.

## What needs what
| Step | Needs |
|---|---|
| 1 commit/push, 2 tag, 3 tag push | your approval + SSH push access |
| 3 workflow run, 8 release page, deleting a package version | GitHub web UI (your account) |
| 4 to 5 digest read and `cosign verify` | a real published image; network to ghcr.io, Sigstore |
| 6 record digest | the verified digest from step 5 + your approval |
| 7 init check | Docker; changes your local analyzer state (backup shown) |
