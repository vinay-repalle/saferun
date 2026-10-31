# Clean-environment install, validation and CI

Everything below is a *procedure*. None of it has been recorded as run for this repository yet (see `IMPLEMENTATION.md`): run it, then note the real results.

## Install

SafeRun is published as the PyPI package **`saferun-cli`** (the name `saferun` belongs to an unrelated project); it installs the command **`saferun`**. Python 3.12+; no Python dependencies.

```bash
pip install saferun-cli          # or: pipx install saferun-cli · uv tool install saferun-cli · poetry add saferun-cli
                                 # Poetry must be 2.0 or newer (see below)
saferun init                     # Docker check, verified cosign, signed analyzer image, OSV data (~260 MB)
saferun doctor                   # PASS / WARNING / FAIL
saferun run my_script.py         # scan, then run only inside the sandbox
```
**Poetry 2.0 or newer is required.** The package declares its license as an SPDX expression, which needs wheel metadata version 2.4 (setuptools 77+). Poetry 1.x, including 1.8.2 packaged by Ubuntu 24.04, fails with "Unable to create package with no name" (verified); pip, pipx and uv are not affected, and Poetry 2.5.1 was verified. Install a current Poetry with `pipx install poetry`.

A wheel is a supported install: everything `saferun init` needs from the package (CLI, engine, Semgrep rules) is inside it, and the analyzer comes from the signed registry image. Only `saferun init --build-local` needs the build recipe (`docker/`), which is in the sdist and the repository but not in the wheel; without it `init` says so. You do not install cosign or the OSV data yourself. Docker is the only prerequisite (Windows and macOS: see [platforms.md](platforms.md)). Setup needs internet access to the Docker registries, `ghcr.io`, `github.com` (only to fetch cosign when you have none), the Sigstore TUF root and transparency log, and `osv-vulnerabilities.storage.googleapis.com`; scans never use the network.

Prerequisites per platform: Linux: Docker Engine and membership of the `docker` group · macOS: Docker Desktop (or Colima/OrbStack) running · Windows: Docker Desktop, Linux containers, WSL 2 backend. `saferun doctor` diagnoses each of these.

## Install from a fresh clone (development)

```bash
git clone https://github.com/vinay-repalle/saferun.git && cd saferun
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/saferun init --all          # pulls the pinned python/node images, installs the signed analyzer (cosign fetched and verified, by digest), downloads the OSV data (~260 MB)
.venv/bin/saferun doctor              # exit 0 if nothing FAILED
.venv/bin/saferun scan ./some-project
```
The analyzer release `analyzer-v1.0.1` is recorded in `ANALYZER_RELEASE`, so `init` installs it after verifying its cosign signature (see `docs/release-images.md`). Add `--build-local` to build the analyzer from `docker/` instead (no cosign needed).

## Validate (run these yourself; nothing here has been run for you)

```bash
# 1. tests that do not need Docker
.venv/bin/python -m pytest -q -ra -m "not docker"

# 2. everything, including the Docker sandbox and the real analyzer (after `saferun init --all`); fails instead of skipping
SAFERUN_REQUIRE_DOCKER=1 .venv/bin/python -m pytest -q -ra

# 3. website (optional)
(cd web && npm ci --ignore-scripts && npm test && npm run build)

# 4. packaging: build, check metadata, inspect, install into a clean environment
.venv/bin/python -m build && .venv/bin/python -m twine check dist/*
python3 -m zipfile -l dist/*.whl | grep -E 'rules/python.yml|saferun/cli.py'
tar tzf dist/*.tar.gz | grep docker/analyzer/Dockerfile
python3 -m venv /tmp/clean-wheel && /tmp/clean-wheel/bin/pip install dist/*.whl && (cd /tmp && /tmp/clean-wheel/bin/saferun --version && /tmp/clean-wheel/bin/saferun doctor)
```

## Continuous integration (`.github/workflows/ci.yml`)

Runs on every pull request and every push to `main`. Read-only token, no secrets, no registry login, nothing published; all actions pinned to commit SHAs.

| Job | Blocking | What it does |
|---|---|---|
| `python` | yes | `pip install -e '.[dev]'`, `compileall`, `sh -n` on the build script, `pytest -m "not docker"` |
| `web` | yes | `npm ci --ignore-scripts`, `npm test`, `npm run build` |
| `package` | yes | `python -m build`, checks wheel and sdist contents, installs the wheel into a clean venv and starts the CLI (a built wheel is the supported install, see above) |
| `audit` | no (advisory) | `npm audit` (website production dependencies) |
| `docker` | no (advisory) | `saferun init --only python,node,analyzer --build-local`, then `pytest -m docker` on the runner's Docker daemon |

The `docker` job is advisory because it depends on the runner's Docker/cgroup configuration and has never been run; promote it to blocking only after you have seen it pass. There is no lint step: the repository has no linter configuration, and adding one unconfigured would only produce noise.

## Publishing the package

The PyPI and TestPyPI procedure (nothing has been uploaded yet) is in [release-pypi.md](release-pypi.md).

## Manual GitHub settings

See "Manual GitHub configuration" in [release-images.md](release-images.md).
