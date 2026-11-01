# Releasing `saferun-cli` to PyPI (maintainer procedure)

**Status:** `0.0.1` was uploaded to TestPyPI (2026-11-01) and installed and tested from there in a clean environment (`--version`, `init`, `doctor`, `scan`, `run`). Nothing has been uploaded to production PyPI yet. Every upload below is a deliberate, manual step by the maintainer. A version can be uploaded to an index only once, so the TestPyPI `0.0.1` cannot be re-uploaded; the first production release is `0.0.2`. CI never publishes (`tests/test_ci_workflow.py` enforces it), and the analyzer image has its own release path ([release-images.md](release-images.md)).

Facts checked: on 2026-10-31 the name `saferun-cli` did not exist on pypi.org or test.pypi.org; since then it exists on test.pypi.org (version `0.0.1`), and on 2026-11-01 it was still absent from pypi.org (`saferun` belongs to an unrelated project and must not be used). Check again immediately before the first upload, names are first come, first served.

## 0. One-time setup
1. Create accounts on <https://test.pypi.org> and <https://pypi.org> with 2FA.
2. Create an **API token per index**. For the very first upload a token has to be account-wide; after the project exists, replace it with a token scoped to `saferun-cli`. Better still, after the first upload configure a *trusted publisher* (GitHub OIDC, no stored token) for a future publish workflow.
3. Never put a token in the repository, a shell history or a command line. Use environment variables for the session only:
   ```bash
   export TWINE_USERNAME=__token__
   read -rs TWINE_PASSWORD && export TWINE_PASSWORD     # paste the token, it is not echoed
   ```

## 1. Prepare a clean release candidate
```bash
git status --short                      # must be empty; build from a committed state
python -m pip install -U build twine
rm -rf dist build *.egg-info
python -m build
python -m twine check dist/*            # both files must say PASSED
python -m zipfile -l dist/*.whl         # expect saferun/…, engine/rules/python.yml; NO docker/ tests/ web/
sha256sum dist/*                        # record the hashes with the release notes
```
The version comes from `saferun/__init__.py` (`__version__`). **A version can be uploaded to an index exactly once**, even if it is deleted afterwards; if a test upload goes wrong, bump the version (for example `0.0.2.dev1`, `0.0.2rc1`) instead of retrying.

## 2. TestPyPI upload (only with the maintainer's explicit go-ahead)
```bash
python -m twine upload --repository testpypi dist/*
```
`--repository testpypi` uploads to <https://test.pypi.org/legacy/>. Without it twine targets the real PyPI, so never omit it for a test.

## 3. Install from TestPyPI in a clean environment and test
`saferun-cli` has no Python dependencies, so one index is enough (this also avoids pulling look-alike packages from TestPyPI):
```bash
python3 -m venv /tmp/tp && /tmp/tp/bin/pip install --index-url https://test.pypi.org/simple/ saferun-cli==<version>
cd /tmp && /tmp/tp/bin/saferun --version
/tmp/tp/bin/python -c "import saferun, sys; print(saferun.__file__)"          # must be in site-packages
XDG_DATA_HOME=/tmp/tp-data /tmp/tp/bin/saferun doctor                          # empty data dir: expect FAIL lines with fixes
XDG_DATA_HOME=/tmp/tp-data /tmp/tp/bin/saferun init --only analyzer --yes      # fetches a verified cosign, verifies the signature, pulls by digest
XDG_DATA_HOME=/tmp/tp-data /tmp/tp/bin/saferun init --only osv-db --yes        # ~260 MB
XDG_DATA_HOME=/tmp/tp-data /tmp/tp/bin/saferun doctor                          # expect all PASS
XDG_DATA_HOME=/tmp/tp-data /tmp/tp/bin/saferun run my_script.py
```
Repeat with `pipx install --index-url https://test.pypi.org/simple/ saferun-cli`, `uv tool install --index https://test.pypi.org/simple/ saferun-cli` and Poetry 2.0+ (`poetry source add --priority=explicit testpypi https://test.pypi.org/simple/` then `poetry add --source testpypi saferun-cli`). Check the project page renders (README, links, classifiers).

## 4. PyPI (only after TestPyPI looked right and the maintainer approves)
```bash
python -m twine upload dist/*           # the same files that were tested; do not rebuild
```
Then, on a clean machine, repeat step 3 against the real index (`pip install saferun-cli`). A PyPI release cannot be removed and re-used; a bad release can only be *yanked* (the file stays downloadable by exact pin) and replaced by a new version.

## What publishing does and does not change
* Users run `pip install saferun-cli`; the analyzer image they get is still the signed `analyzer-v1.0.1` recorded in `ANALYZER_RELEASE` (a new analyzer is a separate tag, workflow run and reviewed commit).
* The package contains no secrets and no analyzer recipe; `saferun init --build-local` needs a source checkout or the sdist.
* The sdist includes `tests/`, `docs/`, `web/` sources and `.github/` on purpose; the wheel contains only the `saferun` package.
