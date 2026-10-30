# SafeRun

Checks AI-generated code before you run or trust it. Executing untrusted code in a sandbox **limits the impact** of that
code; it does **not** prove the code is safe, and a passing scan does not guarantee security.
Status: Phases 1-4 and 5A-5E are implemented and committed (not independently certified). No signed analyzer release has been published from this repository yet (`ANALYZER_RELEASE` is `None`), so `saferun init` builds the analyzer image locally; see [docs/release-images.md](docs/release-images.md). Not yet done: a clean-machine install test, CI, a built-wheel install test, a detection-quality benchmark and broader JavaScript rules (see *Remaining work* in [PROJECT.md](PROJECT.md)). **The CLI is the primary product**; the dashboard is a secondary, loopback-only demonstration interface.

## License
SafeRun is released under the [MIT License](LICENSE) (Copyright (c) 2026 Vinay Repalle). The analyzer image also redistributes third-party software under its own licenses (Semgrep, OSV-Scanner and others); their notices are in [docker/analyzer/THIRD_PARTY_NOTICES.md](docker/analyzer/THIRD_PARTY_NOTICES.md) and inside the image.

## Key features
- **Restricted Docker sandbox** (Phase 1): read-only sanitized project copy, no network, non-root, no capabilities, resource limits, verified at run time.
- **Validation engine** (Phase 2): Python syntax check and `node --check` in the sandbox; Semgrep (Python) and an **offline** OSV-Scanner dependency scan, both run **only inside a verified, locked-down analyzer container** (Phase 5B, no host-side fallback); one normalized report and a PASS / WARNING / FAIL verdict.
- **CLI** (Phase 3): `saferun scan PATH`, text or JSON output, deterministic exit codes. Incomplete scans never report PASS.
- **Local web dashboard** (Phase 4, optional `web` extra): upload a ZIP, see verdict, check coverage and findings. Runs the same CLI as a subprocess (no separate validation code), refuses non-loopback access in code, treats archives as hostile. **Not for exposure beyond your own machine** — see [docs/api.md](docs/api.md).

## Prerequisites
Linux, Python 3.12+, a **local** Docker Engine reachable by your user (remote endpoints are refused), cgroup limits (memory, swap, pids, CPU) and seccomp enabled in the daemon.
`saferun init` installs the rest (the images are pulled by pinned digest; SafeRun never pulls on its own during a scan). Manual equivalent:
```bash
docker pull python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea   # Python profile
docker pull node@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da       # Node.js profile
saferun verify-images --base-only
```
Images must provide `timeout` and `sh`, and must not declare `VOLUME`.

## Install and set up
**Supported: install from a source checkout** (below). A built wheel contains only the `saferun` package (CLI, engine, bundled rules); it does **not** contain the analyzer build recipe (`docker/`) or the built dashboard (`web/dist`), so `saferun init` cannot build the analyzer from a wheel and `saferun-web` shows no UI. Wheels are built in CI as a packaging check only. Details: [docs/install-and-test.md](docs/install-and-test.md).

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'   # needs python3-venv/pip; Semgrep and OSV-Scanner are NOT needed on the host
saferun init                      # first run: logo (on a colour terminal), short intro, pick components, installs only what is missing or invalid
saferun status                    # what is installed and verified (exit 0 only if everything is ready)
```
`saferun init` detects what is already installed (images by pinned digest, the analyzer by lock/labels/rules hash, OSV data by integrity manifest and age), skips what is valid, and offers to install,
repair or update the rest. For scripts/CI: `saferun init --all`, `--only python,node`, `--skip osv-db`, `--yes`, `--repair` (see [docs/cli.md](docs/cli.md)). The sandbox images are pulled **by
pinned digest**; the analyzer image is **built locally** with `docker/analyzer/build.sh` (no signed prebuilt release has been published from this repository yet, so cosign is not needed today). Once we publish our own cosign-signed release and record it in `ANALYZER_RELEASE`, `init` will install it after verifying the signature (needs `cosign` 2.2+ on your PATH; SafeRun does not install it) and `--build-local` will still force the local build; see [docs/release-images.md](docs/release-images.md); the OSV data is downloaded once
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

## Web dashboard (optional, local only)
```bash
.venv/bin/pip install -e '.[dev,web]' && (cd web && npm ci --ignore-scripts && npm run build)
.venv/bin/saferun-web            # http://127.0.0.1:8765/  — loopback only, refuses any other bind address
```
Semgrep and OSV-Scanner now parse uploaded files inside the isolated analyzer container (Phase 5B), not on the host. The dashboard stays loopback-only and has no authentication until the isolation has been reviewed; read [docs/api.md](docs/api.md) and the Phase 5 security status in [PROJECT.md](PROJECT.md).

## Supported runtimes
| Runtime | Image | Status |
|---|---|---|
| Python | `python:3.12-slim` | sandbox, syntax check and Semgrep implemented |
| JavaScript / Node.js | `node:22-slim` | sandbox, `node --check` and npm lockfile scan implemented; **dependency installation, test runners and JS Semgrep rules are not implemented** |

## Documentation
- [docs/cli.md](docs/cli.md) — CLI options, exit codes, output examples
- [docs/engine.md](docs/engine.md) — validation engine: checks, dependency coverage, statuses, verdict rules
- [docs/sandbox.md](docs/sandbox.md) — sandbox library usage and guarantees
- [docs/api.md](docs/api.md) — local web dashboard: API, ZIP handling, limits, worker environment, security notes
- [PROJECT.md](PROJECT.md) — goals, architecture, threat model, known exposures (**read before relying on the sandbox**), phases
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — status, test evidence, limitations, technical notes
