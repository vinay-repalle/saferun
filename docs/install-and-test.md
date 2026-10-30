# Clean-environment install, validation and CI

Everything below is a *procedure*. None of it has been recorded as run for this repository yet (see `IMPLEMENTATION.md`): run it, then note the real results.

## Supported installation: a source checkout

Decision (pre-validation review): SafeRun is supported **only when installed from a source checkout** (`pip install -e .`). The wheel is *not* a supported way to run it, because two things SafeRun needs live outside the Python package:

| Needed by | Location | In the wheel? |
|---|---|---|
| `saferun init` (local analyzer build) | `docker/analyzer/` (found relative to the checkout by `saferun/setup.py`) | no |
| Dashboard UI (`saferun-web`) | `web/dist`, produced by `npm run build` (found by `saferun/api/app.py`) | no |
| Semgrep rules, CLI, engine | `saferun/` | yes |

What happens on a wheel install: the CLI starts; `saferun init` explains that the build recipe is missing; `saferun-web` serves only the API (no UI). Nothing breaks silently, but the product is not usable end to end, so we do not claim wheel support. CI still builds the wheel and sdist and installs the wheel into a clean venv, as a **packaging sanity check** (metadata, bundled rules, entry point), not as a statement of support.

The sdist additionally contains `docker/`, the `web/` sources (no `node_modules`/`dist`), `docs/`, `tests/` and `.github/`, so an unpacked sdist behaves like a checkout.

**Decision for the owner:** wheel support would need either (a) moving the analyzer recipe into the package (for example `saferun/analyzer_recipe/`) and building `web/dist` into it before `python -m build` (touches `saferun/setup.py`, `saferun/api/app.py`, `docker/analyzer/build.sh`, the release workflow's staging step and several tests), or (b) nothing, if you are happy with source installs. Note that once a signed analyzer release exists, `init` no longer needs `docker/`, so a wheel could then run the CLI scans (still without the dashboard UI).

## Install from a fresh clone

Requirements: Linux, Python 3.12+ with `venv`, a local Docker Engine reachable by your user (cgroup limits and seccomp enabled), internet for the one-time setup.

```bash
git clone https://github.com/vinay-repalle/saferun.git && cd saferun
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/saferun init --all          # pulls the pinned python/node images, installs the signed analyzer (cosign-verified, by digest), downloads the OSV data (~260 MB)
.venv/bin/saferun status              # exit 0 only if everything is ready
.venv/bin/saferun scan ./some-project
```

The analyzer release `analyzer-v1.0.1` is recorded in `ANALYZER_RELEASE`, so `init` installs it after verifying its cosign signature: **cosign 2.2+ must be on your PATH** (see `docs/release-images.md`). Add `--build-local` to build the analyzer locally instead (no cosign needed).

## Validate (run these yourself; nothing here has been run for you)

```bash
# 1. tests that do not need Docker
.venv/bin/python -m pytest -q -ra -m "not docker"

# 2. everything, including the Docker sandbox and the real analyzer (after `saferun init --all`); fails instead of skipping
SAFERUN_REQUIRE_DOCKER=1 .venv/bin/python -m pytest -q -ra

# 3. dashboard (optional)
(cd web && npm ci --ignore-scripts && npm test && npm run build)

# 4. packaging sanity check (wheels are not a supported install): build, inspect, install into a clean environment
.venv/bin/python -m build
python3 -m zipfile -l dist/*.whl | grep -E 'rules/python.yml|saferun/cli.py'
tar tzf dist/*.tar.gz | grep docker/analyzer/Dockerfile
python3 -m venv /tmp/clean-wheel && /tmp/clean-wheel/bin/pip install dist/*.whl && (cd /tmp && /tmp/clean-wheel/bin/saferun --help)
```

## Continuous integration (`.github/workflows/ci.yml`)

Runs on every pull request and every push to `main`. Read-only token, no secrets, no registry login, nothing published; all actions pinned to commit SHAs.

| Job | Blocking | What it does |
|---|---|---|
| `python` | yes | `pip install -e '.[dev,web]'`, `compileall`, `sh -n` on the build script, `pytest -m "not docker"` |
| `web` | yes | `npm ci --ignore-scripts`, `npm test`, `npm run build` |
| `package` | yes | `python -m build`, checks wheel and sdist contents, installs the wheel into a clean venv and starts the CLI (packaging sanity check only; wheels are not a supported install, see above) |
| `audit` | no (advisory) | `npm audit` (production dependencies) and `pip-audit` (web extra) |
| `docker` | no (advisory) | `saferun init --only python,node,analyzer --build-local`, then `pytest -m docker` on the runner's Docker daemon |

The `docker` job is advisory because it depends on the runner's Docker/cgroup configuration and has never been run; promote it to blocking only after you have seen it pass. There is no lint step: the repository has no linter configuration, and adding one unconfigured would only produce noise.

## Manual GitHub settings

See "Manual GitHub configuration" in [release-images.md](release-images.md).
