
## Plain-English findings (Stage 12)
**What changed.** A finding can carry `explanation`: one or two short sentences (what it is, why it matters, how to fix it) next to the unchanged `message`. The text report prints it as `In plain words: ...` directly under the message (default on, no flag); the JSON has the `explanation` key only when one exists. Texts are in `saferun/engine/explain.py` (tested table keyed by rule id, plus a template for dependency findings filled from existing finding data). Covered: the 11 Semgrep rules, withheld-file rules, syntax findings, one generic text for `secrets.*`, dependency findings. Unknown ids have none.
**Decisions (owner-confirmed).** One line per finding, no separate table; wording uses "can"/"could" and never claims an attack will happen or that a fix guarantees safety; texts are not in the Semgrep rules file or the image, so no analyzer release is needed.
**Unchanged.** `message`, the Upgrade plan, `schema_version` (1), the website fixture. The engine fills `explanation` after the checks run, so findings built by hand (like the fixture's) have none.
**Limits.** Texts are short general guidance, not advice for a specific code base; the dependency text does not describe the particular vulnerability. Follow-ups not done here: grouping dependency findings by package, and not showing git commit hashes under "fixed in".
# SafeRun — Project

Developer tool that checks AI-generated code *before* it is run or trusted. CLI + static website
share one backend, one validation engine, one sandbox. SafeRun is **Python-only**: JavaScript/Node.js is not
supported (the JavaScript syntax check and npm-lockfile scan that existed from Phase 2 were removed; npm files get a plain "not supported, not scanned" note — see *Runtime profiles*).

**Non-goals:** generating/repairing code, multi-agent systems, LLM API calls, CI/CD integration (v1),
any claim that a passing scan means the code is secure.

## Architecture (target)

```
saferun/
  sandbox/     Phase 1  workspace copy + locked-down docker run   (implemented)
  engine/      Phase 2  checks -> normalized findings -> verdict (implemented; see *Validation engine*)
  cli.py       Phase 3  `saferun scan <dir>` (implemented; see docs/cli.md)
web/           React + Vite static website (informational only; no scanning, no server)
```

Sandbox (`saferun/sandbox/`): `workspace.py` (sanitized temp copy) · `docker.py` (defensive CLI wrappers, daemon
preflight) · `copy.py` (fd-relative, identity-verified, limited copy) · `secrets.py` (credential signatures, output
redaction) · `reaper.py` (orphan recovery) · `controls.py` (what is really in force: daemon capabilities and the applied
container config, pure functions) · `runner.py` (`build_create_args` holds every security flag; `run_sandboxed` does
preflight → create → **verify applied config, fail closed** → start → timeout → inspect → cleanup) ·
`attestation.py` (kernel-view probe inside a sandbox) · `profiles.py` (python image) · `config.py`
(limits/result types). Uses the docker CLI via argument lists (no shell, no Docker SDK, no socket handed to anything
untrusted). A future backend interface is **not** introduced in Phase 1 (see *OpenSandbox reuse assessment*).

## Validation engine (Phase 2, `saferun/engine/`)
`model.py` (Finding, CheckResult, CheckStatus, Severity, ValidationReport) · `verdict.py` (rules) · `tools.py` (controlled subprocess runner) ·
`semgrep.py`, `osv.py`, `secretscan.py`, `pysyntax.py` (one module per check, each `run_check(ctx) -> CheckResult`) · `engine.py` (`validate_project`) ·
`context.py` (injectable runners for tests) · `paths.py` (untrusted-path normalisation) · `rules/python.yml` (bundled Semgrep rules) · `rules/gitleaks.toml` (bundled gitleaks configuration).

Flow: `create_workspace` (Phase 1 sanitized copy) → list files → run enabled checks (each guarded: an exception becomes an `error` result) →
`compute_verdict` → delete the copy. The sandbox API is unchanged; the engine only *uses* `create_workspace`, `run_sandboxed` and the docker helpers.

**Where each tool runs, and why (since Phase 5B).** Everything that parses untrusted files runs **inside a container**: the Python syntax check (`compile()`) in the
`python` image, and Semgrep, OSV-Scanner and gitleaks (secrets) in the **analyzer image** (`saferun-analyzer:local`, built by `docker/analyzer/build.sh`). All of them go through the same
`run_sandboxed` path with the same verified restrictions (no network, read-only root and project, non-root, all capabilities dropped, seccomp/no-new-privileges, memory/swap/CPU/pids/fd/file-size
limits, container-side kill deadline). Only OSV-Scanner gets one extra mount: the offline OSV data directory, read-only (the applied mount set is verified exactly, so an unexpected or writable
mount stops the run). Semgrep runs with the rule file baked into the image (a scanned project cannot supply rules) and `--disable-nosem`. The host never executes Semgrep or OSV-Scanner and the
host environment is not passed to the container. There is **no fallback**: see *Phase 5 security status*. Neither tool executes project code; they only read it.

**Dependency handling.** SafeRun never installs, fetches or builds dependencies and never runs install scripts. OSV-Scanner reads dependency files only
(`--no-resolve`): **lockfiles** (`poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`) and the **manifest** `requirements.txt` (not a lockfile). Scans use no network at all: OSV-Scanner runs offline against local OSV data (`saferun osv-db update` is the only download, of public data; nothing about any project is sent). Without the data the check reports `error`. A manifest without a scannable file beside it (`Pipfile`, `pyproject.toml`) and requirements variants (`requirements-dev.txt`, …) are *coverage gaps*:
status `incomplete`/`skipped`, never clean. `requirements.txt` entries not pinned with `==` are noted as not reliably matched.

**Findings vs operational errors.** A finding is a signal in the project. `error`/`timeout`/`unavailable`/`skipped`/`incomplete` describe the analysis, carry no
findings (except `incomplete`, which keeps partial results) and force at least `WARNING`. Severity mapping: Semgrep → rule's `saferun_severity` else
ERROR/WARNING/INFO → high/medium/low; OSV → CVSS score of the vulnerability group (≥9 critical, ≥7 high, ≥4 medium, >0 low) else the database's label,
else `unknown` (treated as medium); a Python syntax error → medium (a broken file is a validation problem, not a demonstrated vulnerability); a gitleaks secret finding → high (always; the value is never kept); a withheld
private key/token → high, a withheld private-mode file → low. Verdict rules: [docs/engine.md](docs/engine.md) / `verdict.py`. All tool-derived strings are stripped of control and
bidi characters and length-bounded; tool-reported paths are accepted only if they are relative paths inside the copy.

**Limitations.** The bundled Semgrep rules are a small starting set (11 rules, Python only) and do no taint or cross-file analysis; no JavaScript support (npm files are not scanned and only get a plain note); Python syntax is checked with the sandbox image's Python 3.12 only (Semgrep itself tolerates and does not report syntax errors — observed with 1.182.1); OSV matches known vulnerabilities only (no malware detection, no reachability; look-alike package names are a separate, offline hint: `saferun check-names`, not part of `scan`);
`requirements.txt` is a manifest: unpinned entries are evaluated at their lower bound and transitive dependencies are not resolved; unsupported file formats are not scanned; Semgrep skips files > 1 MB and these are reported `incomplete`; at most 50 lockfiles, 1000 findings per check.

## Threat model

**Assets:** host files/credentials, Docker daemon, host CPU/RAM/disk, network position, other scans' data.
**Attacker:** author of the scanned project (or an LLM that wrote it): malicious code, tests, archives,
filenames, dependency manifests; also hostile output (size, terminal escapes).

| Threat | Control (Phase 1) |
|---|---|
| Read/modify host files; credential exposure | Only a sanitized *copy* of the project is mounted, read-only; symlinks/special files not copied; concurrent modification of the source is *detected* (not prevented, no atomic snapshot — see below); size/count/depth limits; no other mounts |
| Docker socket / credentials | Never mounted; env passed explicitly (none inherited from host) |
| Docker applying something weaker than asked (daemon policy, option precedence, a changed `create`) | After `docker create` and before `docker start`, 28 properties of the created container are checked from `docker inspect`; any deviation raises and the code never runs |
| Daemon unable to enforce a control (no seccomp, seccomp unconfined, no swap/pids/memory/CPU cgroup support) | Preflight refuses the run unless the caller lists the control in `allow_degraded`; every control's state is returned in `SandboxResult.controls` |
| Wrong or swapped image; implicit pull; option injection via image/command | `--pull never`; container created from the resolved image ID (recorded as `image_id`); image reference validated; `--entrypoint ""`; command is an argv list, validated, never shell-interpreted; images declaring `VOLUME` refused |
| Remote/odd Docker endpoint | Only `unix://` endpoints accepted (checked from `DOCKER_HOST` or the current context) |
| Privilege escalation | Non-root uid 65534, `--cap-drop ALL`, `no-new-privileges`, not privileged, daemon-default seccomp + AppArmor (checked, see below) |
| Persistence / tampering in container | `--read-only` rootfs; `/tmp` tmpfs `noexec,nosuid,nodev`, size-capped; `/dev/shm` size-capped |
| Network exfiltration / SSRF | `--network none` |
| CPU / memory / fork bomb / disk | `--cpus`, `--memory`=`--memory-swap`, `--pids-limit`, `ulimit nofile/fsize/core`, tmpfs and shm size |
| Hang | Host-side timeout → `docker kill`; container-side `timeout -s KILL`; container always `rm -f`'d |
| Output flooding | Output capped (256 KiB default), excess drained and discarded; log driver `none` |
| Leftovers | Container removal verified and workspace deleted independently in `finally`; `reap_orphans()` for crashes |

Controls marked † are verified by automated tests *on this host* (see IMPLEMENTATION.md); the
seccomp filter and AppArmor profile come from the Docker daemon's defaults and are checked, not pinned.

| Additional controls | Evidence |
|---|---|
| † seccomp filter active (`Seccomp: 2` in `/proc/self/status`) | test_seccomp_filter_is_active_in_container |
| † AppArmor `docker-default (enforce)` — only checked when the daemon reports AppArmor, otherwise the test skips visibly | test_apparmor_profile_is_applied_when_host_has_apparmor |
| † `memory.swap.max == 0`, `memory.max`, `pids.max` in the container's cgroup | test_swap_is_disabled_and_memory_limit_in_cgroup |
| † Copy limits (bytes/files/depth, defaults 400 MiB / 20 000 / 32) checked by a pre-scan *before* any file is copied, and again while copying | test_workspace.py |
| † Identity-verified copy with a final validation pass: pre-scan records a signature of every entry/listing; copy pass requires lstat and the opened fd to match, listings to match, files unchanged after reading; a final pass re-checks every directory (identity, metadata, listing) and entry. Detected changes abort the copy (`WorkspaceChangedError`); `O_NOFOLLOW` throughout. Detection only — see *Concurrent modification* below | test_races.py (43 tests; those added for each race fail against the respective pre-fix code) |
| † Container-side `timeout -s KILL` (timeout + grace) kills a run whose SafeRun parent was SIGKILLed | test_orphan_is_killed_by_container_timeout_then_reaped |
| † `reap_orphans()` removes only SafeRun-labelled containers past their deadline and flock-free `saferun-ws-*` dirs; never live runs or foreign objects | test_cleanup.py |
| † Non-world-readable files withheld, never read; signature-bearing files withheld by content; hard links to inodes with outside names skipped; output redacted | test_sensitive.py, test_hardlinks.py (each fails when its control is disabled) |
| † Applied container config verified before start (28 checks, each shown to flip on the opposite value); fail closed (container never started) | test_hardening.py (golden-config mutations, `never_started` tests) |
| † Daemon preflight: seccomp present and not unconfined, memory/swap/pids/CPU cgroup support; AppArmor reported (not required); unverifiable controls reported as `unavailable`/`unverified`, never `verified` | test_hardening.py (preflight, daemon_controls) |
| † Kernel-view attestation (`attest(image)`): reads `/proc` and `/sys` inside a sandbox with the real flags (seccomp mode 2, NoNewPrivs, empty capabilities, uid, loopback-only, cgroup limits, swap 0, read-only filesystems, AppArmor profile) — on the Python image | test_hardening.py |
| † Robustness to unexpected Docker behaviour: malformed JSON, missing state, daemon down (a failed `inspect` no longer counts as "container removed"), hung CLI, non-UTF-8 output, kill that does not stop the container, reaper with daemon down | test_hardening.py |
| † Concurrent runs (6 in parallel) are isolated and fully cleaned up | test_concurrent_runs_are_isolated_and_all_cleaned_up |
| † Both cleanup steps always run; original exception preserved (cleanup errors added as notes) | test_cleanup.py |

## Removed: web dashboard and API
The Phase 4 local dashboard (`saferun/api`, `saferun-web`, hostile-ZIP upload, loopback guard) was removed; it was a demonstration interface only. SafeRun has no network-facing component: the CLI is the only way to scan, and `web/` is a static informational site.

## Operational assumptions and known exposures (read before relying on SafeRun)

- **`docker` binary, `PATH` and the local daemon are trusted.** The `docker` CLI is resolved from `PATH` to an
  absolute path and honours `DOCKER_CONFIG`/`DOCKER_CONTEXT`; whoever controls those controls the sandbox. A *remote*
  endpoint is **refused** (only `unix://`), because the workspace is bind-mounted by host path. Checked with the default
  context only; rootless Docker and Podman are untested.
- **Docker group = root.** The user running SafeRun is trusted; the daemon runs as root, no userns remap
  (container uid 65534 is host uid 65534).
- **Shared kernel.** Container escapes via kernel/runc bugs are not mitigated; not proven secure.
- **`/proc` and `/sys` expose host information** to scanned code: kernel version, CPU model, memory size,
  and `/proc/self/mountinfo` reveals the host workspace path and overlay layer paths.
- **File permissions are rewritten** in the workspace copy: files 0644, dirs 0755, executable bits dropped
  (so `./script.sh` will not run directly). Files that are *not world-readable in the source* are withheld
  rather than widened (see below); `SensitivePolicy(honor_private_modes=False)` opts out.
- **Sensitive files.** Withheld (not copied, listed in `SandboxResult.withheld`): non-world-readable files and
  directories, and files whose *content* carries a credential signature (PEM private key with body; AWS, GitHub,
  Slack, Google, Stripe-live, PyPI, Anthropic token formats) — by content/mode, never by filename;
  `SensitivePolicy.allow_paths` opts single paths back in. A world-readable file with a secret in an unrecognised
  format **is** visible to the sandboxed code. `stdout`/`stderr` are redacted (values of secret-looking assignments in
  readable files + the signatures) and cut-off tails dropped on truncation — best effort: code can encode a secret first.
  Withheld files are *not analysed*; any non-empty `withheld`/`skipped` means a partial scan and must be reported as such.
- **Concurrent modification of the source tree.** SafeRun copies a *live* directory and takes no atomic snapshot (that needs
  filesystem snapshots: LVM/btrfs/ZFS/overlay). Changes between the pre-scan and the end of a final validation pass —
  added, removed, replaced, retyped, chmod'ed or modified entries and directories — are detected and abort the copy
  (`WorkspaceChangedError`; retry). Not detected: changes after the final validation (they cannot alter already-copied files),
  changes that leave every recorded field (mode, dev, ino, size, mtime, ctime, directory names) identical (possible within one
  timestamp tick on kernels < 6.13 or coarse-timestamp filesystems; untested there), content already present at scan time, and
  cross-file inconsistency that existed before the scan. A concurrent writer can force repeated aborts. Archive uploads (Phase 4)
  should be extracted into a private directory so the race does not arise. Details: IMPLEMENTATION.md.
- **Hard links.** A multi-link file is copied only if every name of its inode was seen inside the scanned tree;
  otherwise it is skipped as `hardlink-external` (prevents a link to e.g. `~/.ssh/id_rsa` from importing its content).
  Relies on `st_nlink` (verified on ext4 only); snapshot trees (`cp -al`) are skipped.
- **Symlinks, FIFOs, devices are not copied** and are listed in `SandboxResult.skipped` (untrusted names;
  sanitize before display). Bind mounts/submounts inside the project directory are not detected.
- **`/dev/shm`** is now size-capped (`shm_mb`, default 16) and verified; it is charged to the memory cgroup.
- **Infrastructure errors vs program errors.** Failures before the code starts (preflight, validation, `create`,
  config verification) and an unreadable final state raise `SandboxError`. Once started, Docker/`timeout` failures
  surface as a normal result: exit code 125/126/127 (also used by programs) and Docker's own text in `stderr`, which a
  program can imitate. Exit 137 = SIGKILL (OOM or timeout; use `oom_killed` / `timed_out`). Callers must not treat
  stderr as trusted. Images must provide `timeout` (coreutils/busybox) and `sh`; verified for the two profiles only.
- **Timeouts:** host-side limit is wall-clock from `docker start` (create time excluded); the container-side
  limit is `timeout_s + container_grace_s`. Both are best-effort against a hung Docker daemon.
- **Orphan recovery is explicit**: the CLI does not call `reap_orphans()`; the Phase 4 server does at startup and after a killed job.
  Containers use `saferun-` names and a `saferun.deadline` label; workspaces live in the system temp dir.
- Images are referenced by tag but each run uses the *resolved image ID* (recorded); images are now referenced by pinned digest (Phase 5A; see *Image pinning*). Sandbox output is not terminal-escape sanitized by the sandbox; the Phase 3 CLI strips control/escape characters from everything it prints.
- Out of scope for Phase 1: side channels; archive attacks (Phase 4/5); running scanners on hostile input
  (Phase 2 originally ran Semgrep/OSV-Scanner on the host; since Phase 5B they run only inside the analyzer container, see *Validation engine*); dependency installation (deferred, separate network-enabled step).

## Runtime profiles
A *profile* (`profiles.py`) is just a name for an image plus its interpreter; every profile gets exactly the same
restrictions, verified the same way. There is one: **python** → `python:3.12-slim@sha256:78387bc3…` (pinned by digest, pulled by `saferun init`).

**JavaScript was removed.** Phase 2 added a `node:22-slim` profile, a `node --check` syntax check and an npm-lockfile scan. SafeRun is now Python-only, so the Node image, the `javascript-syntax` check, the `--no-javascript-check` behaviour (the flag is still accepted, hidden, and does nothing) and the npm OSV data are gone. A project with `package.json`, `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml` gets the dependency-check note "JavaScript/npm dependencies are not supported and were not scanned." (no effect on status or verdict; with only npm files the check is `not_applicable`, never a pass). The secrets scan still reads files of any type. The website in `web/` is built with Node but is not part of the scanner.

## OpenSandbox reuse assessment
Source of this assessment: official docs and selected raw files read read-only over the web (no clone, install or
execution); the broader audit is in the project history. Files read: `SECURITY.md`, `ROADMAP.md`,
`server/configuration.md`, `server/pyproject.toml`, `server/opensandbox_server/{config.py,startup_guard.py}`,
`services/{validators.py,docker/docker_service.py,docker/container_ops.py}`, `specs/{sandbox-lifecycle.yml,execd-api.yaml}`
(first 100 000 characters each), `docs/architecture/**`, `docs/guides/{network-isolation,secure-container,isolation-sessions}.md`,
`sandbox-images` README. **Not read:** `services/docker/{volumes,networking,runtime}.py`, execd Go sources, any
image/resource-quantity validation (not found in `validators.py`). Decisions are therefore limited to what was read.
All reviewed code is **Apache-2.0** ("Copyright 2025/2026 The OpenSandbox Authors"); **no OpenSandbox source was copied**,
so no Apache-2.0 §4 obligations are triggered. If code is ever copied: include the license text, mark changed files,
keep copyright notices, and carry any NOTICE file (none was seen). SafeRun adds **no new runtime dependency**.

| Component / source | Contributes | Dependencies · license | Security limitations | Decision |
|---|---|---|---|---|
| Server `server/opensandbox_server/` | HTTP lifecycle API over Docker/K8s | FastAPI, docker, kubernetes, grpcio, psycopg, redis… · Apache-2.0 | network-exposed control plane (`0.0.0.0`), API key unset by default | **Avoid** (extra infrastructure) |
| execd `components/execd` | in-sandbox command/file daemon | Go · Apache-2.0 | runs *inside* the untrusted container; token default and user unknown | **Avoid** |
| Egress sidecar `components/egress` | FQDN/DNS/nft egress policy | Go · Apache-2.0 | default `dns` mode does not enforce IP rules; needs `NET_ADMIN`; incompatible with gVisor | **Avoid for now**; candidate for Phase 2's dependency-acquisition step after verification |
| Docker runtime `services/docker/*` | container creation | docker SDK · Apache-2.0 | defaults weaker than SafeRun's: host network, no read-only root/user/swap/ulimit/tmpfs settings found | **Avoid**; own implementation already stricter and verified |
| `startup_guard.py` | fail fast unless insecure start is explicitly acknowledged | stdlib · Apache-2.0 | tied to API-key startup | **Adapt idea** → `preflight()` + explicit `allow_degraded` (own code) |
| `services/validators.py` | input hygiene: non-empty entrypoint, option-like values (`-…`) rejected, normalised traversal-free paths | FastAPI `HTTPException` coupling · Apache-2.0 | no image/resource validation in the file | **Adapt ideas** → `validate_command`, `validate_image`, mount-path check (own code) |
| Command semantics (`specs/execd-api.yaml`) | argv vs shell; argv[0] non-empty; NUL invalid | spec only · Apache-2.0 | shell mode exists | **Adapt idea**: SafeRun accepts argv only |
| Container labels (`created-at`, `expires-at`) | orphan bookkeeping | — | — | **Build own** (done: `saferun.deadline`, reaper) |
| `resourceLimits` (`cpu`, `memory`, `gpu` strings) | resource request | — | no disk/pids/swap/fd/fsize | **Avoid**; explicit integer limits kept |
| Code interpreter image / kernels (`sandbox-images`) | Python/Node/Java/Go via Jupyter kernels | Ubuntu 24.04, many OSS · Apache-2.0 (+ bundled licenses) | persistent kernels, root kernels inside Jupyter owner's trust boundary; version via env vars | **Avoid** |
| SDKs (`SupportedLanguages`, 5 languages) | host-side clients | Apache-2.0 | they control sandboxes; they do not run code themselves | **Avoid** |
| Isolation sessions (bubblewrap) | per-run namespaces in one sandbox | bwrap · Apache-2.0 | needs `CAP_SYS_ADMIN` + unconfined AppArmor/seccomp; "hard trust boundaries out of scope" | **Avoid** |
| gVisor / Kata / Firecracker runtime options | stronger isolation | runsc / kata · Apache-2.0 | gVisor ↔ egress sidecar conflict; Firecracker K8s-only | **Defer**: a future backend could pass `--runtime`; not implemented |
| Release practice (cosign signing, digest pinning) | supply-chain hygiene | — | — | Digest pinning **done** (Phase 5A); cosign signing: workflow + client verification implemented (Phase 5E); `analyzer-v1.0.0` was published from this repository (commit `5e78fb0`) and a real `cosign verify` with this project's identity expression succeeded on 2026-10-30, but it lacks the license notices, so it is **not recorded**; `analyzer-v1.0.1` (commit `a275dce`) is published and recorded in `ANALYZER_RELEASE` as `sha256:6f26c3e3fed1a8b2a981bdcb920c4da3b2829bce2679709ba8880789ce6f6fa4`; its signature was verified with real cosign (`saferun verify-images --signature` passes). A clean-machine `saferun init` from it has not been recorded as passing. (An earlier `analyzer-v1.0.0` under the previous owner's registry is unrelated and untrusted) |

A broad backend-interface refactor was **not** done in Phase 1: it is not needed to complete the phase, would touch
verified code, and the only second backend considered (OpenSandbox) failed the risk review above. The seams exist
(`build_create_args`, `controls.py`, `SandboxResult`); an interface can be extracted when a second backend is real.

## Phases

1. Environment + sandbox PoC — **approved as the Phase 2 baseline** (a milestone approval, not a security certification)
2. Validation engine (syntax, Semgrep, dependency vulns, normalized report, tests) — **committed (`088b279`)**
3. CLI — **committed (`a9ea5dc`)**; the primary product
4. Web dashboard — committed (`e4bceef`), later **removed** (see *Removed: web dashboard and API*)
5. Integration, security testing, release docs — 5A image pinning, 5B analyzer isolation, 5C adversarial tests, 5D cleanup/exhaustion hardening and 5E signed analyzer release (workflow + cosign verification) are **implemented and committed**; `analyzer-v1.0.0` is published and signed but not recorded (no license notices in the image); `analyzer-v1.0.1` is published, signed and recorded in `ANALYZER_RELEASE` (a release under a previous owner's identity is not trusted here)

6. Post-Phase-5 product work (not numbered when done): `saferun init` / `status` / `doctor` / `run`, self-provisioned cosign, terminal presentation, CI, packaging, PyPI releases 0.0.1 and 0.0.2, static website — **done and committed**
7. Onward: see [STAGES.md](STAGES.md) (planned work, one line per stage)

A phase starts only after the previous one's acceptance criteria are met and approved.

### Remaining work (audit 2026-10-30; status updated in Phase 7), in priority order
*Items 2-5 were done after the audit; planned new work is tracked in [STAGES.md](STAGES.md).*
1. **Clean-machine end-to-end test** (fresh clone, `pip install`, `saferun init --all`, `status`, `verify-images --signature`, `scan`) — no passing run is recorded.
2. **CI** — done: `.github/workflows/ci.yml` runs the non-Docker tests on Linux, Windows and macOS, the website tests and build, and a wheel/sdist build with a clean-venv install; Docker tests and `npm audit` are advisory jobs. There is no lint job.
3. **Packaging** — done: `[build-system]` exists, the version is 0.0.2 and it is published on PyPI as `saferun-cli`; CI installs the built wheel into a clean venv. The wheel still excludes `docker/` (so `init --build-local` needs a source checkout).
4. **Project files**: LICENSE (MIT) and SECURITY.md exist; there is no CHANGELOG.
5. **Docker-less tests** — done: the non-Docker subset (`-m "not docker"`) is a blocking CI job on all three platforms.
6. **Detection quality**: rules are measured only by a small advisory benchmark of simulated samples (docs/benchmark.md; no independent evaluation); SafeRun is Python-only (JavaScript support was removed). Planned: STAGES.md.
Future enhancements (not release blockers unless a later audit says so): gVisor/Kata backend, ARM64 analyzer.

## Image pinning (Phase 5A)
- Profiles and `DEFAULT_IMAGE` use `repo:tag@sha256:<index digest>` references from `saferun/sandbox/images.py`. Docker resolves by digest; the tag is only a label.
- `dk.resolve_image` (called by every `preflight`) additionally checks that the local image's `RepoDigests` contain the pinned digest and raises
  `SandboxError` otherwise, so a mismatch stops the run before any container exists. Tag-only references (used by some tests) behave as before.
- Pins were taken from the local images the Phase 1-4 tests ran on and confirmed against Docker Hub on 2026-10-29 (`docker buildx imagetools inspect
  python@sha256:78387bc3…` returned that digest). **The `python:3.12-slim` tag has since moved** to `sha256:aa943ce4…`; the pin intentionally stays on the
  tested digest. Updating a pin is a deliberate, reviewed change (re-run the suite and `verify-images`).
- Report compatibility: the `tool` string of `python-syntax` is unchanged (`compile() (python:3.12-slim, sandboxed)`), via `RuntimeProfile.label`; the pinned image is still what runs. Only error text that quotes the image reference (`image ... not present locally`, `digest mismatch`) now shows the full `repo:tag@sha256:` reference.
- `docker/analyzer/` holds an unwired, unbuilt build recipe for the Phase 5B analyzer image (base by digest, Semgrep wheels hash-locked, OSV-Scanner SHA-256 verified).

## Phase 5 security status (5B isolation, 5C adversarial testing)

**What is protected, by design.** Hostile source files and dependency files are parsed by Semgrep / OSV-Scanner only inside a container with: no network (`--network none`, verified from
`docker inspect` before start), read-only root filesystem, the project mounted read-only (a sanitized copy: no symlinks/devices/credential files), a read-only OSV data mount, uid 65534,
`--cap-drop ALL`, `no-new-privileges`, the daemon's seccomp profile, memory = swap limit, CPU and pids limits, fd and file-size ulimits, a private noexec tmpfs, no published ports/devices,
log driver off, `--init`, and a container-side `timeout -s KILL` deadline plus a host-side kill. The image is built from a digest-pinned base, hash-locked Semgrep wheels and a
checksum-verified OSV-Scanner binary; before **every** use SafeRun checks the image ID against the build lock and the tool-version and rules-hash labels against its own pins, then runs the
container *by that ID*. Image missing / ID or label mismatch / Docker unusable / container policy violated -> the check is `unavailable` or `error` (never clean, verdict at best WARNING).
There is no host-side execution path: asserted statically (AST test of the check modules: no `run_tool`/`find_tool`/`subprocess`/`which` names or imports), dynamically (`subprocess.Popen` and `subprocess.run` patched to raise during a scan with the analyzer unavailable; `os.system` and the `exec*` family are NOT covered by that test) and end to end (host
`semgrep`/`osv-scanner` shims on PATH are never started, also through the dashboard API, which has since been removed).

**Network.** Scans are always offline. `saferun osv-db update` is the only code that downloads anything in normal use (the opt-in `saferun check-names --online` also contacts pypi.org, sending package names only; see *Package-name check* below) (public OSV data over HTTPS; size cap; the server's MD5 header is REQUIRED (earlier versions silently skipped the check: the real server sends `x-goog-hash` as two headers and only the first was read, so the MD5 was never actually compared); a readable zip with at least a floor of advisories; SHA-256/size/entry count/time recorded in `manifest.json`; atomic replace; existing directories are never chmod'ed). The host reads only the zip's central directory to count advisories (stdlib `zipfile`, nothing is extracted); it does not parse the advisories. **Per-scan online OSV queries were removed**, a deliberate behaviour change: allowing network in the analyzer container would expose the host's
bridge gateway and LAN to a process that parses hostile input, and Docker alone cannot restrict egress to api.osv.dev (that needs a host firewall or an egress proxy, both outside this phase and
rejected earlier in the OpenSandbox review). Consequence: a project with lockfiles but no local OSV data now yields WARNING (error) where it used to yield findings; the dashboard no longer offers
"online" (`osv=online` -> 422). Data freshness is the operator's responsibility.

**Tested controls vs proven guarantees.** The 5C suite tried specific hostile inputs and probes on this host (Docker 29.8.0, one kernel, the daemon's builtin seccomp profile, AppArmor `docker-default`) and each ended
safely: deeply nested / oversized / NUL / non-UTF-8 sources; malformed, deeply nested and huge lockfiles; requirements directives pointing at host files and metadata endpoints; symlinks,
FIFOs, sockets and external hardlinks; fork bomb, OOM, CPU spin, tmpfs/output flood, fd exhaustion; mount/unshare/chroot/proc-write/cgroup-write attempts; DNS and TCP connection attempts;
tampered lock, crashing analyzer, missing data; CLI exit codes and report schema; loopback-only dashboard (removed later). **A passing test is evidence for that input on that host, not a proof.** Not
established: absence of Semgrep/OSV-Scanner/Go/Python parser vulnerabilities, kernel or runc escapes (the container shares the host kernel; gVisor/Kata are deferred), behaviour under other
kernels/Docker versions/rootless Docker/user-namespace remapping, other CPU architectures (the analyzer lock is linux/amd64), SELinux (not used on this host), or side channels. AppArmor IS active here: `docker info` lists `name=apparmor,profile=default`, and the Phase 1 attestation run against the analyzer image reads `docker-default (enforce)` from inside the container (`tests/test_analyzer_isolation.py::TestRealAnalyzerContainer::test_kernel_view_attestation_of_the_analyzer_image`); that is a property of this host, and the profile's contents are not audited.

**Remaining limitations (stated, not hidden).**
- **Analyzer image trust.** The image is pinned by a local lock file (the image ID, written by `build.sh`), not by a registry digest or a signature. The lock is trusted only if it and its directory are owned by the current user and owner-only (file 0600, directory 0700), it is opened without following symlinks, and anything else fails closed *before* Docker is consulted. This stops accidental or group/other tampering; it does **not** stop the same user, root, or any member of the `docker` group (root-equivalent) from replacing the image and rewriting the lock. The labels checked afterwards (tool versions, rules hash) are set by whoever builds an image and prove nothing on their own; the ID in the lock is the control. `build.sh` locks whatever it just built without human review. Only the immediate lock directory is examined, not its ancestors. Phase 5E adds support for a published, cosign-signed image whose digest is pinned in `ANALYZER_RELEASE` (`analyzer-v1.0.1`; the older `analyzer-v1.0.0` is not recorded, see `docs/release-images.md`); `init` installs it by default and `--build-local` builds locally. In either case the local lock remains the anchor after installation.
- **OSV data trust.** Before every scan the data is re-validated against `manifest.json` (SHA-256, size, advisory floor, symlinks/readability, timestamps); invalid -> `error`, older than 30 days -> `incomplete`, neither is ever clean. What this does and does not give: the download's MD5 comes from the same server over the same TLS connection, so it detects corruption, not a malicious or compromised server; the SHA-256 is computed locally after download, so it detects later modification but does not authenticate the original download; the manifest sits next to the data, so anyone who can write the directory can rewrite both; OSV publishes no signature that SafeRun checks; the advisory floors (PyPI 5 000) are sanity checks, not proof of completeness; a file swapped between validation and the container's read is not detected (the window is the scan itself). Freshness is reported in every dependency check's notes and by `saferun osv-db status`.
- The OSV-Scanner checksum comes from the same upstream release as the binary (integrity, not authenticity); Semgrep wheel hashes were generated from PyPI at lock time (Linux x86_64, CPython 3.12 only).
- Coverage cross-check quirk (pre-existing): files whose names contain control characters are reported with sanitized paths, so Semgrep's scanned-file list cannot be matched and the check ends `incomplete` (safe direction, misleading text "e.g. too large").
- Fixed in 5C: text output could be given extra, forged finding lines by a file name containing a newline / U+2028 (every printed field is now one line; JSON output was never affected).
- (Dashboard, removed later: it had no authentication.) One scan at a time; resource limits for the analyzer (1.5 GiB, 2 CPUs, 256 pids) are fixed defaults. A second sandbox backend is deferred (the container boundary is Docker-only).
- Phase 5D (implemented; see IMPLEMENTATION.md *Phase 5D*): cancel on server stop, instance lock + orphan-worker kill + full sweep after a SIGKILLed server, `507` for disk-full uploads, bounded health probe, reaper/sandbox client behaviour with a hung daemon. Still untested for real: a truly hung `dockerd`, a real full filesystem, a real second OS user (simulated by changing the uid SafeRun sees).

## Secrets scan (`hardcoded-secrets`, Stage 11)
**What it is.** A separate check, `saferun/engine/secretscan.py`, running **gitleaks 8.30.1** (`gitleaks dir`, MIT; chosen over detect-secrets, trufflehog and custom Semgrep rules: single checksummed binary like OSV-Scanner, vendor-specific rules, no online verification, built-in redaction; trufflehog was rejected because it verifies secrets online by default and is AGPL-3.0) in the verified analyzer container (no network, read-only project, same limits as the other analyzer checks, no host fallback). The binary is pinned by the SHA-256 of its release archive; the baked configuration `saferun/engine/rules/gitleaks.toml` and the tool version are image labels compared with this checkout before every use, so an analyzer image built before this change fails verification (one `saferun init` brings the user to a current image).
**Handling untrusted input.** The project cannot influence the tool: `--config` points only at the baked file, `--ignore-gitleaks-allow` is set, `.gitleaksignore` files are deleted from the private copy, the environment is not forwarded. Output is parsed strictly (a JSON list of objects with a rule id; anything else is `error`), capped (100 000 entries read, 1 000 findings kept), de-duplicated, and every string passes `clean_text`; paths must be relative paths inside the copy.
**Secrets never leave the container as values.** gitleaks runs with `--redact`, and the parser takes only `RuleID`, `File`, `StartLine`, `EndLine`; `Secret`, `Match`, `Fingerprint` and all other fields are discarded, the message is a fixed text, and stderr of a failed run is not echoed. Tests feed a tool output that contains a sentinel value in `Secret`/`Match`/stderr and assert it appears nowhere (finding, JSON report, text report, CLI output).
**Verdict.** Every finding is HIGH (so FAIL); no verdict-rule change was needed. `--no-secrets-check` gives `skipped` (at best WARNING); a missing image is `unavailable`; mismatching labels are `error`; files over 1 MB are `incomplete`.
**Honest limits.** Known vendor token formats only; the generic entropy rule is disabled (high false-positive rate), so plain passwords and unrecognised tokens are missed; example keys in docs or tests can be flagged; nothing is verified as live; binary files and git history are not scanned; vendored folders are skipped like in the Semgrep check. Files matching SafeRun's own credential signatures are withheld at copy time (`workspace-sensitive-files`) and never reach gitleaks. For existing users the check reports `error` until they install an analyzer image that contains gitleaks, which keeps their scans at WARNING; `saferun run` is affected the same way.

## Package-name check (`saferun check-names`)
A separate command (`saferun/pkgnames.py`); `scan` and `run` do not call it. It reads declared Python dependency names (`requirements*.txt`, `pyproject.toml` directly in the given directory, plus names on the command line), normalises them (PEP 503) and compares them with `saferun/data/top_pypi.txt`, a snapshot of the 10 000 most downloaded PyPI names (source: hugovk's top-pypi-packages dataset, date in the file header; regenerated with `tools/update_top_pypi.py`). A name outside the snapshot but within 1 edit (2 when both have 8+ characters) of a snapshot name is "similar". Offline by default. `--online` (explicit opt-in) asks `https://pypi.org/simple/<name>/` whether a name outside the snapshot exists and when it was first uploaded; only the name is sent. Failures are "could not check", exit 2, never a pass.
**Limitations.** A heuristic: measured on the dataset itself, ~98% of single-edit typos of popular names are caught and ~7% of real packages just below the cutoff are falsely flagged; look-alikes of packages outside the snapshot, prefix/suffix tricks and non-PyPI ecosystems are not covered; the snapshot ages between refreshes; download counts are not looked up (PyPI's own API does not provide them). Details: [docs/cli.md](docs/cli.md).

## Setup workflow (`saferun init`, `saferun status`)
Implemented in `saferun/setup.py`; it only orchestrates existing verification (pinned-digest image check, analyzer lock/labels/rules hash, OSV manifest validation) and adds no trust of its own.
A component is *ready* only if that verification passes at that moment. Installation actions: `docker pull <repo>@<pinned digest>` for the Python image; `docker/analyzer/build.sh` for the analyzer (needs a repository
checkout and internet once); `osvdb.update` for the OSV data (atomic, keeps old data on any failure). Every installed component is re-verified; failure is reported, never assumed. Rebuilding an analyzer that failed verification needs
`--repair` or an explicit interactive confirmation, because it replaces the image and re-locks it. **Prebuilt analyzer image: `analyzer-v1.0.1`** (recorded in `ANALYZER_RELEASE`; `init` installs it by digest after a cosign check, `--build-local` builds locally; `analyzer-v1.0.0` is superseded; see `docs/release-images.md`);
the dormant download path pulls by digest, re-verifies and only then locks. Offline: nothing is downloaded, valid components are still used, missing ones are listed with preload instructions; an analyzer cannot yet be installed without
internet. Trust limits are those of the underlying checks (documented under *Phase 5 security status*); `init` pulling the two pinned base images makes SafeRun fetch images only on explicit user request, never during a scan.

## Dependency findings: fix label and accepted risks (Stage 10)
**What changed.** (1) A dependency finding carries `fix_kind` (`patch` / `minor` / `major`), computed in `saferun/engine/osv.py` (`fix_kind`, `version_key`) from the installed version and the nearest fixed release above it, using only data OSV already supplies; the text report shows it next to "fixed in" and in the Upgrade plan. (2) New `saferun/engine/accept.py` and `saferun scan --accept-file FILE`: `[[accept]]` entries (`id` or alias, optional `package`, required `reason` and `expires`) move matching dependency findings out of the verdict into a visible **Accepted risks** list; expired entries stop applying.
**Decisions (owner-confirmed).** The accept file is read **only** from `--accept-file`, never from the scanned project (an untrusted project could otherwise hide its own vulnerabilities; a `.saferun-accept.toml` found in the project is ignored with a stderr note). Accepted findings stay visible but no longer count toward FAIL/WARNING.
**Unchanged.** Existing finding fields and the JSON `schema_version` (1): new keys are additive and appear only when present (`fix_kind` when known; `accepted`/`accept_notes` only with an accept file), so a consumer that ignores unknown keys is unaffected. Dependency findings with a known fixed version do gain `fix_kind` in the JSON (an additive change to existing output). `run` and `check-names` are unchanged.
**Limits.** The label is by version numbers only (no semver breaking-change knowledge; `0.x` minors are often breaking; non-numeric versions get no label). Only dependency findings can be accepted. Date comparison uses the local calendar date of the machine running the scan.
