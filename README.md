# SafeRun

Checks AI-generated code before you run or trust it. Executing untrusted code in a sandbox **limits the impact** of that
code; it does **not** prove the code is safe, and a passing scan does not guarantee security.
Status: Phases 1-4 and 5A-5E are implemented and committed (not independently certified). The signed analyzer image `analyzer-v1.0.1` is published from this repository and recorded in `ANALYZER_RELEASE`, so `saferun init` installs it after verifying its cosign signature (`analyzer-v1.0.0` predates the license notices and is not used); see [docs/release-images.md](docs/release-images.md). Not yet done: a clean-machine install test, CI, a built-wheel install test, a detection-quality benchmark and broader JavaScript rules (see *Remaining work* in [PROJECT.md](PROJECT.md)). **The CLI is the product**; `web/` is a static informational website.

## License
SafeRun is released under the [MIT License](LICENSE) (Copyright (c) 2026 Vinay Repalle). The analyzer image also redistributes third-party software under its own licenses (Semgrep, OSV-Scanner and others); their notices are in [docker/analyzer/THIRD_PARTY_NOTICES.md](docker/analyzer/THIRD_PARTY_NOTICES.md) and inside the image.

## Key features
- **Restricted Docker sandbox** (Phase 1): read-only sanitized project copy, no network, non-root, no capabilities, resource limits, verified at run time.
- **Validation engine** (Phase 2): Python syntax check and `node --check` in the sandbox; Semgrep (Python) and an **offline** OSV-Scanner dependency scan, both run **only inside a verified, locked-down analyzer container** (Phase 5B, no host-side fallback); one normalized report and a PASS / WARNING / FAIL verdict.
- **CLI** (Phase 3): `saferun scan PATH`, text or JSON output, deterministic exit codes. Incomplete scans never report PASS.

## Prerequisites
Python 3.12+ and a **local** Docker that runs Linux containers, reachable by your user (remote endpoints are refused), with cgroup limits (memory, swap, pids, CPU) and seccomp enabled in the daemon. Linux is the fully tested platform; native Windows and macOS support is new and only partly verified, see [docs/platforms.md](docs/platforms.md) for what is tested and the limitations.
`saferun init` installs the rest (the images are pulled by pinned digest; SafeRun never pulls on its own during a scan). Manual equivalent:
```bash
docker pull python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea   # Python profile
docker pull node@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da       # Node.js profile
saferun verify-images --base-only
```
Images must provide `timeout` and `sh`, and must not declare `VOLUME`.

## Install and set up
**Supported: install from a source checkout** (below). A built wheel contains only the `saferun` package (CLI, engine, bundled rules); it does **not** contain the analyzer build recipe (`docker/`), so `saferun init --build-local` cannot work from a wheel. Wheels are built in CI as a packaging check only. Details: [docs/install-and-test.md](docs/install-and-test.md).

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'   # needs python3-venv/pip; Semgrep and OSV-Scanner are NOT needed on the host
saferun init                      # first run: logo (on a colour terminal), short intro, pick components, installs only what is missing or invalid
saferun status                    # what is installed and verified (exit 0 only if everything is ready)
```
`saferun init` detects what is already installed (images by pinned digest, the analyzer by lock/labels/rules hash, OSV data by integrity manifest and age), skips what is valid, and offers to install,
repair or update the rest. For scripts/CI: `saferun init --all`, `--only python,node`, `--skip osv-db`, `--yes`, `--repair` (see [docs/cli.md](docs/cli.md)). The sandbox images are pulled **by
pinned digest**; the analyzer image is **the cosign-signed release recorded in `ANALYZER_RELEASE`** (`analyzer-v1.0.1`, pinned by digest), installed after its signature is verified (needs `cosign` 2.2+ on your PATH; SafeRun does not install it); `--build-local` builds it locally with `docker/analyzer/build.sh` instead; see [docs/release-images.md](docs/release-images.md); the OSV data is downloaded once
(about 260 MB) and every scan then runs offline. Developers can still use `docker/analyzer/build.sh` and `saferun osv-db update` directly.
```bash
.venv/bin/pytest -q                        # Docker tests skip (loudly) if Docker is missing
SAFERUN_REQUIRE_DOCKER=1 .venv/bin/pytest  # ...or fail instead of skipping (use this to prove a full run)
```

**Clean-environment install and validation, and what the CI runs:** [docs/install-and-test.md](docs/install-and-test.md).

## Quick start
```bash
saferun scan ./my-project                 # human-readable report
saferun scan ./my-project --format json   # machine-readable report (schema_version 1)
saferun scan ./my-project --osv-offline   # accepted for compatibility: scans are ALWAYS offline
```
Exit codes: **0** PASS · **1** FAIL · **2** WARNING (including any incomplete scan) · **64** invalid usage/path · **70** fatal · **130** interrupted.

> **Privacy / network:** scans never use the network. Semgrep and OSV-Scanner run in a container without network access, and OSV-Scanner reads a local copy of the OSV data (`saferun osv-db update`, an explicit download of public data that contains nothing about your project). Without that data the dependency check reports `error` (verdict at best WARNING). Per-scan *online* OSV queries were removed in Phase 5B, see [PROJECT.md](PROJECT.md).
>
> **Limits of the OSV data checks:** the download is checked against the server's MD5 header (refused if absent) and a SHA-256 is recorded locally and re-checked before every scan. That detects corruption and later modification of the files. It does **not** authenticate the download (the hash comes from the same server, or from your own disk), and someone who can write the data directory can rewrite the manifest too. Data older than 30 days makes the dependency check `incomplete`.

## Website (static)
`web/` is a static informational site (what SafeRun is, features, security, CLI usage, GitHub link). It has no backend and does not scan anything.
```bash
cd web && npm ci --ignore-scripts && npm test && npm run build   # output: web/dist
```
**Hosting:** Netlify. **Live site:** https://safe-run.netlify.app · **Repository:** https://github.com/vinay-repalle/saferun

| Netlify setting | Value |
|---|---|
| Deployment branch | `main` |
| Base directory | `web` |
| Build command | `npm ci --ignore-scripts && npm run build` |
| Publish directory | `dist` |
| Node.js | 22 |

Pages are switched by the URL hash, so no redirect rules are needed.

> **Scope:** the website is a static informational site only. SafeRun's CLI, sandbox and security analysis stay in this repository (`saferun/`, `docker/`) and run on your own machine; none of that is hosted by Netlify, and the site scans nothing.

## Supported runtimes
| Runtime | Image | Status |
|---|---|---|
| Python | `python:3.12-slim` | sandbox, syntax check and Semgrep implemented |
| JavaScript / Node.js | `node:22-slim` | sandbox, `node --check` and npm lockfile scan implemented; **dependency installation, test runners and JS Semgrep rules are not implemented** |

## Documentation
- [docs/cli.md](docs/cli.md) — CLI options, exit codes, output examples
- [docs/engine.md](docs/engine.md) — validation engine: checks, dependency coverage, statuses, verdict rules
- [docs/sandbox.md](docs/sandbox.md) — sandbox library usage and guarantees
- [PROJECT.md](PROJECT.md) — goals, architecture, threat model, known exposures (**read before relying on the sandbox**), phases
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — status, test evidence, limitations, technical notes
